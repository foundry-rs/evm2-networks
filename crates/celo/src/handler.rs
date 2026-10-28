//! Celo transaction handlers.
//!
//! Port of celo-revm's `CeloHandler`. Native-fee transactions follow the OP rules, except that the
//! base fee goes to the `FeeHandler`. CIP-64 transactions with a fee currency debit the fees from
//! the fee-currency token before execution and credit refund, tip and base fee after it.

use crate::{
    CELO_FEE_HANDLER_ADDRESS, CELO_MAINNET_CHAIN_ID, CELO_SEPOLIA_CHAIN_ID, CIP64_TX_TYPE, CeloEvm,
    CeloEvmTypes, CeloTxEnvelope,
    deposit::{execute_deposit, prepare_deposit},
    fee_currency::{balance_of, credit_gas_fees, debit_gas_fees, ensure_fee_currency_context},
};
use alloy_consensus::{Transaction, TxEip1559, TxEip2930, TxLegacy};
use alloy_primitives::{Address, B256, U256, b256, keccak256};
use evm2::{
    EvmFeatures, SpecId, TxResult,
    env::TxEnvExt,
    ethereum::{
        LazyTxEip7702, PreparedTx, access_list_counts, effective_gas_price, eip1559, eip2930,
        eip7702, execute_initial_frame, finalize_gas, initial_gas_and_reservoir,
        intrinsic_and_floor_gas, legacy, prepare_initial_frame, validate_block_gas_limit,
        validate_chain_id, validate_create_initcode, validate_execution_gas_limit_cap,
        validate_floor_gas, validate_gas_price, validate_intrinsic_gas,
        validate_nonce_not_overflow, validate_priority_fee, validate_sender_and_bump_nonce,
        validate_tx_gas_limit_cap, warm_access_list, warm_base_accounts,
    },
    handler::{GasSettlement, TxHandlerHooks},
    interpreter::{GasTracker, MessageResult},
    registry::{HandlerError, HandlerResult, TxRegistry, TxRequest, handler},
};
use op_evm2::{
    L1BlockInfo, OpSpecId,
    constants::{DEPOSIT_TRANSACTION_TYPE, L1_FEE_RECIPIENT, OPERATOR_FEE_RECIPIENT},
};

/// Historical EIP-2930 transactions with a wrong chain ID, accepted by op-geth's sender recovery
/// bug and kept valid by celo-revm, as `(chain_id, block_number, tx_hash)`.
const CHAIN_ID_EXCEPTIONS: [(u64, u64, B256); 2] = [
    (
        CELO_SEPOLIA_CHAIN_ID,
        12531083,
        b256!("0x4564b9903cfe18814ffc2696e1ad141d9cc3a549dc4f5726e15f7be2e0ccaa25"),
    ),
    (
        CELO_MAINNET_CHAIN_ID,
        53619115,
        b256!("0xd6bdf3261df7e7a4db6bbc486bf091eb62dfd2883e335c31219b6a37d3febca1"),
    ),
];

/// Historical CIP-64 transactions included without a fee-currency balance covering
/// `gas_limit * max_fee_per_gas`, as `(chain_id, block_number, tx_hash)`.
const CIP64_MAX_FEE_EXCEPTIONS: [(u64, u64, B256); 1] = [(
    CELO_MAINNET_CHAIN_ID,
    75046581,
    b256!("0xe9e0248cf5b02ce016b195690fbb168f08eeeff7b9b353a52ecf98f4229ba834"),
)];

/// Celo transaction validation errors, surfaced as [`HandlerError::External`].
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum CeloTxError {
    /// Non-deposit transactions must carry their EIP-2718 enveloped bytes.
    #[error("missing enveloped transaction bytes for non-deposit transaction")]
    MissingEnvelopedTx,
    /// Deposit system transactions are not supported after Regolith. This turns the deposit into a
    /// failed deposit.
    #[error("deposit system transactions post regolith hardfork are not supported")]
    DepositSystemTxPostRegolith,
    /// The fee currency is not registered in the `FeeCurrencyDirectory`.
    #[error("fee currency not registered: {0}")]
    FeeCurrencyNotRegistered(Address),
    /// The base fee converted to the fee currency, or the fee-currency gas cost, overflows `u128`.
    #[error("fee-currency fee overflows u128")]
    FeeOverflow,
    /// `balanceOf` of the fee currency failed.
    #[error("failed to read the fee-currency balance")]
    BalanceReadFailed,
    /// `debitGasFees` of the fee currency failed.
    #[error("failed to debit gas fees")]
    DebitFailed,
    /// `creditGasFees` of the fee currency failed.
    #[error("failed to credit gas fees")]
    CreditFailed,
}

/// Handler hooks for native-fee Celo transactions.
///
/// Port of the native-fee paths of celo-revm, which follow op-revm: the L1 data fee and the
/// operator fee are charged on top of the gas, and settlement credits the L1 fee and operator fee
/// vaults. The base fee is credited to the `FeeHandler` instead of OP's base fee vault.
#[derive(Clone, Copy, Debug, Default)]
pub struct CeloHandlerHooks;

/// Reloads the cached L1 block info when it was not loaded for the current block, and clears the
/// per-transaction L1 cost cache.
fn load_l1_block_info(host: &mut CeloEvm<'_>) -> HandlerResult<()> {
    let number = host.block().number;
    if host.ext().l1_block_info.l2_block != Some(number) {
        let spec = host.config_spec_id();
        host.ext_mut().l1_block_info = L1BlockInfo::try_fetch(host.state_mut(), number, spec)?;
    }
    host.ext_mut().l1_block_info.clear_tx_l1_cost();
    Ok(())
}

fn enveloped_tx(envelope: &CeloTxEnvelope) -> HandlerResult<&[u8]> {
    envelope
        .enveloped_tx()
        .map(|bytes| bytes.as_ref())
        .ok_or_else(|| HandlerError::external(CeloTxError::MissingEnvelopedTx))
}

/// Returns whether `envelope` is one of the `(chain_id, block_number, tx_hash)` `exceptions`.
fn is_exception(
    exceptions: &[(u64, u64, B256)],
    host: &CeloEvm<'_>,
    envelope: &CeloTxEnvelope,
) -> bool {
    let chain_id = host.version().chain_id;
    let number = host.block().number;
    exceptions.iter().any(|(chain, block, hash)| {
        *chain == chain_id
            && U256::from(*block) == number
            && envelope.enveloped_tx().is_some_and(|tx| keccak256(tx) == *hash)
    })
}

impl TxHandlerHooks<CeloEvmTypes> for CeloHandlerHooks {
    fn before_execution(
        host: &mut CeloEvm<'_>,
        envelope: &CeloTxEnvelope,
        caller: Address,
        upfront_fee: U256,
    ) -> HandlerResult<()> {
        load_l1_block_info(host)?;
        let spec = host.config_spec_id();
        let enveloped = enveloped_tx(envelope)?;
        let gas_limit = U256::from(envelope.gas_limit());

        let fee_charge = host.feature(EvmFeatures::FEE_CHARGE);
        let additional_cost = if fee_charge {
            host.ext_mut().l1_block_info.tx_cost(enveloped, gas_limit, spec)
        } else {
            U256::ZERO
        };

        // The stock handler validated `gas_limit * max_fee + value`; the L1 data fee and the
        // operator fee must be covered on top of it.
        let required = gas_limit
            .saturating_mul(U256::from(envelope.max_fee_per_gas()))
            .saturating_add(envelope.value())
            .saturating_add(additional_cost);
        let balance_check = host.feature(EvmFeatures::BALANCE_CHECK);
        let balance_top_up = host.feature(EvmFeatures::BALANCE_TOP_UP);
        let mut account = host.state_mut().account(&caller)?;
        let balance = account.balance();
        if balance < required {
            if balance_check {
                return Err(HandlerError::InsufficientFunds);
            }
            if balance_top_up {
                account.add_balance(required - balance);
            }
        }

        if fee_charge {
            let balance =
                account.balance().saturating_sub(upfront_fee.saturating_add(additional_cost));
            account.set_balance(balance);
        }
        Ok(())
    }

    fn settle_transaction(
        host: &mut CeloEvm<'_>,
        envelope: &CeloTxEnvelope,
        gas: GasSettlement<CeloEvmTypes>,
    ) -> HandlerResult<TxResult<CeloEvmTypes>> {
        let caller = gas.caller;
        let gas_price = gas.gas_price;
        let gas_limit = gas.gas_limit;
        let mut result = finalize_gas(host, gas)?;
        let gas_used = result.tx_gas_used();
        let spec = host.config_spec_id();
        let basefee = host.block().basefee;
        let enveloped = enveloped_tx(envelope)?;

        let info = &mut host.ext_mut().l1_block_info;
        let operator_fee_refund = info.operator_fee_refund(gas_limit, gas_used, spec);
        let l1_cost = info.calculate_tx_l1_cost(enveloped, spec);
        let operator_fee_cost = if spec.is_enabled_in(OpSpecId::ISTHMUS) {
            info.operator_fee_charge(enveloped, U256::from(gas_used), spec)
        } else {
            U256::ZERO
        };
        info.clear_tx_l1_cost();

        if host.feature(EvmFeatures::FEE_CHARGE) {
            let caller_refund = U256::from(gas_limit.saturating_sub(gas_used))
                .saturating_mul(gas_price)
                .saturating_add(operator_fee_refund);
            host.state_mut().account(&caller)?.add_balance(caller_refund);
            let beneficiary = host.block().beneficiary;
            let reward = U256::from(gas_used).saturating_mul(gas_price.saturating_sub(basefee));
            host.state_mut().account(&beneficiary)?.add_balance(reward);
        }

        // Like celo-revm, the fee recipients are credited even when fee charging is disabled.
        let base_fee_amount = basefee.saturating_mul(U256::from(gas_used));
        for (recipient, amount) in [
            (L1_FEE_RECIPIENT, l1_cost),
            (CELO_FEE_HANDLER_ADDRESS, base_fee_amount),
            (OPERATOR_FEE_RECIPIENT, operator_fee_cost),
        ] {
            host.state_mut().account(&recipient)?.add_balance(amount);
        }

        result.ext.l1_fee = l1_cost;
        result.ext.operator_fee = operator_fee_cost;
        Ok(result)
    }
}

type Hooks = CeloHandlerHooks;

/// Shared start of every non-deposit transaction: the fee currency context of the block is loaded
/// first, like celo-revm's `validate_env`, and the enveloped bytes are required.
fn begin(host: &mut CeloEvm<'_>, envelope: &CeloTxEnvelope) -> HandlerResult<()> {
    ensure_fee_currency_context(host)?;
    enveloped_tx(envelope)?;
    Ok(())
}

fn prepare_legacy(
    req: &mut TxRequest<'_, '_, CeloEvmTypes, TxLegacy>,
) -> HandlerResult<PreparedTx> {
    begin(req.host, req.envelope)?;
    legacy::prepare_with_hooks::<CeloEvmTypes, Hooks>(req)
}

fn prepare_eip1559(
    req: &mut TxRequest<'_, '_, CeloEvmTypes, TxEip1559>,
) -> HandlerResult<PreparedTx> {
    begin(req.host, req.envelope)?;
    eip1559::prepare_with_hooks::<CeloEvmTypes, Hooks>(req)
}

fn prepare_eip7702(
    req: &mut TxRequest<'_, '_, CeloEvmTypes, LazyTxEip7702>,
) -> HandlerResult<PreparedTx> {
    begin(req.host, req.envelope)?;
    eip7702::prepare_with_hooks::<CeloEvmTypes, Hooks>(req)
}

/// A transaction prepared outside the stock handlers.
#[derive(Debug)]
struct Prepared {
    caller: Address,
    gas_price: U256,
    intrinsic: u64,
    floor_gas: u64,
}

/// Executes the top-level frame of a transaction prepared outside the stock handlers.
fn execute_frame(
    host: &mut CeloEvm<'_>,
    tx: &impl Transaction,
    prepared: &Prepared,
) -> HandlerResult<MessageResult<CeloEvmTypes>> {
    let Prepared { caller, gas_price, intrinsic, .. } = *prepared;
    let (execution_gas_limit, reservoir) =
        initial_gas_and_reservoir(host.version(), tx.gas_limit(), intrinsic, 0);
    let tx_env = TxEnvExt {
        origin: caller,
        gas_price,
        chain_id: U256::from(host.version().chain_id),
        ..TxEnvExt::default()
    };
    let mut tx_gas =
        GasTracker::new_with_execution_gas_and_reservoir(execution_gas_limit, reservoir);
    let frame = prepare_initial_frame(
        host,
        caller,
        tx.nonce(),
        tx.kind(),
        tx.input(),
        tx.value(),
        &mut tx_gas,
    )?;
    Ok(execute_initial_frame(host, &tx_env, frame, &mut tx_gas, execution_gas_limit, reservoir)?)
}

/// A prepared EIP-2930 transaction.
#[derive(Debug)]
enum PreparedEip2930 {
    /// Prepared by the stock handler.
    Stock(PreparedTx),
    /// A historical wrong-chain-ID transaction ([`CHAIN_ID_EXCEPTIONS`]).
    Exception(Prepared),
}

/// Prepares an EIP-2930 transaction with the stock handler, except for the historical
/// wrong-chain-ID transactions, which skip only the chain ID check.
fn prepare_eip2930(
    req: &mut TxRequest<'_, '_, CeloEvmTypes, TxEip2930>,
) -> HandlerResult<PreparedEip2930> {
    begin(req.host, req.envelope)?;
    if !is_exception(&CHAIN_ID_EXCEPTIONS, req.host, req.envelope) {
        return eip2930::prepare_with_hooks::<CeloEvmTypes, Hooks>(req).map(PreparedEip2930::Stock);
    }

    // The stock EIP-2930 preparation without `validate_chain_id`.
    let caller = req.tx.signer();
    let tx = req.tx.inner();
    let host = &mut *req.host;
    let gas_price = U256::from(tx.gas_price);
    validate_gas_price(host.version(), gas_price, host.block().basefee)?;
    validate_tx_gas_limit_cap(host.version(), tx.gas_limit)?;
    validate_block_gas_limit(host.version(), tx.gas_limit, host.block().gas_limit)?;
    validate_create_initcode(host.version(), tx.to, &tx.input)?;
    validate_nonce_not_overflow(tx.nonce)?;
    let (accounts, storage_keys) = access_list_counts(&tx.access_list);
    let (intrinsic, floor_gas) = intrinsic_and_floor_gas(
        host.version(),
        caller,
        tx.to,
        &tx.input,
        accounts,
        storage_keys,
        tx.value,
    );
    validate_intrinsic_gas(tx.gas_limit, intrinsic, 0)?;
    validate_floor_gas(tx.gas_limit, floor_gas)?;
    validate_execution_gas_limit_cap(host.version(), tx.gas_limit, intrinsic, floor_gas)?;

    let max_gas_cost = U256::from(tx.gas_limit) * gas_price;
    validate_sender_and_bump_nonce(host, caller, tx.nonce, max_gas_cost.saturating_add(tx.value))?;
    warm_base_accounts(host, tx.to);
    warm_access_list(host, &tx.access_list);
    Hooks::before_execution(host, req.envelope, caller, max_gas_cost)?;
    Ok(PreparedEip2930::Exception(Prepared { caller, gas_price, intrinsic, floor_gas }))
}

fn execute_eip2930(
    req: TxRequest<'_, '_, CeloEvmTypes, TxEip2930>,
    prepared: PreparedEip2930,
) -> HandlerResult<TxResult<CeloEvmTypes>> {
    let prepared = match prepared {
        PreparedEip2930::Stock(prepared) => {
            return eip2930::execute_prepared::<CeloEvmTypes, Hooks>(req, prepared);
        }
        PreparedEip2930::Exception(prepared) => prepared,
    };
    let tx = req.tx.inner();
    let result = execute_frame(req.host, *tx, &prepared)?;
    Hooks::settle_transaction(
        req.host,
        req.envelope,
        GasSettlement {
            caller: prepared.caller,
            gas_price: prepared.gas_price,
            gas_limit: tx.gas_limit,
            floor_gas: prepared.floor_gas,
            initial_state_gas: 0,
            state_refund: 0,
            result,
        },
    )
}

/// A prepared CIP-64 transaction.
#[derive(Debug)]
enum PreparedCip64 {
    /// Fees paid in native CELO: an EIP-1559 transaction.
    Native(PreparedTx),
    /// Fees paid in an ERC-20 fee currency.
    FeeCurrency {
        prepared: Prepared,
        fee_currency: Address,
        base_fee_in_erc20: u128,
        /// Whether the fees are debited and credited (balance and base fee checks enabled).
        charge: bool,
        /// Gas left for `creditGasFees` after `debitGasFees`.
        credit_gas_limit: u64,
    },
}

/// Returns the EIP-1559 fields of a CIP-64 transaction.
const fn as_cip64(tx: &CeloTxEnvelope) -> Option<&TxEip1559> {
    match tx.as_cip64() {
        Some(tx) => Some(&tx.inner),
        None => None,
    }
}

/// Prepares a CIP-64 transaction.
///
/// Without a fee currency it is an EIP-1559 transaction. With one, the fee fields are in the fee
/// currency: the base fee is converted with the block's exchange rate, the currency's intrinsic
/// gas is added, and, with balance and base fee checks enabled, the sender's fee-currency balance
/// must cover `gas_limit * max_fee_per_gas` before `debitGasFees` charges
/// `gas_limit * effective_gas_price`. The native balance only has to cover the value. Like
/// celo-revm, the sender is validated against the state after the debit.
fn prepare_cip64(
    req: &mut TxRequest<'_, '_, CeloEvmTypes, TxEip1559>,
) -> HandlerResult<PreparedCip64> {
    begin(req.host, req.envelope)?;
    let Some(fee_currency) = req.envelope.as_cip64().and_then(|tx| tx.fee_currency) else {
        return eip1559::prepare_with_hooks::<CeloEvmTypes, Hooks>(req).map(PreparedCip64::Native);
    };
    let caller = req.tx.signer();
    let tx = req.tx.inner();
    let host = &mut *req.host;
    let info = *host
        .ext()
        .fee_currency_context
        .get(&fee_currency)
        .ok_or(HandlerError::external(CeloTxError::FeeCurrencyNotRegistered(fee_currency)))?;
    let (numerator, denominator) = info.exchange_rate;
    let base_fee_in_erc20 =
        u128::try_from(host.block().basefee.saturating_mul(numerator) / denominator)
            .map_err(|_| HandlerError::external(CeloTxError::FeeOverflow))?;

    let max_fee_per_gas = U256::from(tx.max_fee_per_gas);
    let max_priority_fee_per_gas = U256::from(tx.max_priority_fee_per_gas);
    let base_fee = U256::from(base_fee_in_erc20);
    let gas_price = effective_gas_price(max_fee_per_gas, max_priority_fee_per_gas, base_fee);
    validate_priority_fee(host.version(), max_fee_per_gas, max_priority_fee_per_gas)?;
    validate_gas_price(host.version(), gas_price, base_fee)?;
    validate_chain_id(host.version(), Some(tx.chain_id), false)?;
    validate_tx_gas_limit_cap(host.version(), tx.gas_limit)?;
    validate_block_gas_limit(host.version(), tx.gas_limit, host.block().gas_limit)?;
    validate_create_initcode(host.version(), tx.to, &tx.input)?;
    validate_nonce_not_overflow(tx.nonce)?;
    let (accounts, storage_keys) = access_list_counts(&tx.access_list);
    let (intrinsic, floor_gas) = intrinsic_and_floor_gas(
        host.version(),
        caller,
        tx.to,
        &tx.input,
        accounts,
        storage_keys,
        tx.value,
    );
    // The currency's intrinsic gas raises the intrinsic gas, not the calldata floor.
    let intrinsic = intrinsic.saturating_add(info.intrinsic_gas);
    validate_intrinsic_gas(tx.gas_limit, intrinsic, 0)?;
    validate_floor_gas(tx.gas_limit, floor_gas)?;
    validate_execution_gas_limit_cap(host.version(), tx.gas_limit, intrinsic, floor_gas)?;

    let max_fee_gas_limit = info.intrinsic_gas.saturating_mul(3);
    let mut credit_gas_limit = max_fee_gas_limit;
    let charge =
        host.feature(EvmFeatures::BALANCE_CHECK) && host.feature(EvmFeatures::BASE_FEE_CHECK);
    if charge {
        if !is_exception(&CIP64_MAX_FEE_EXCEPTIONS, host, req.envelope) {
            let max_gas_cost = U256::from(tx.gas_limit) * max_fee_per_gas;
            let balance = balance_of(host, fee_currency, caller)?
                .ok_or(HandlerError::external(CeloTxError::BalanceReadFailed))?;
            if balance < max_gas_cost {
                return Err(HandlerError::InsufficientFunds);
            }
        }
        let gas_cost = u128::from(tx.gas_limit)
            .checked_mul(gas_price.to())
            .ok_or(HandlerError::external(CeloTxError::FeeOverflow))?;
        let debit =
            debit_gas_fees(host, fee_currency, caller, U256::from(gas_cost), max_fee_gas_limit)?;
        if !debit.status {
            return Err(HandlerError::external(CeloTxError::DebitFailed));
        }
        credit_gas_limit = credit_gas_limit.saturating_sub(debit.total_gas_spent);
    }

    validate_sender_and_bump_nonce(host, caller, tx.nonce, tx.value)?;
    warm_base_accounts(host, tx.to);
    warm_access_list(host, &tx.access_list);
    Ok(PreparedCip64::FeeCurrency {
        prepared: Prepared { caller, gas_price, intrinsic, floor_gas },
        fee_currency,
        base_fee_in_erc20,
        charge,
        credit_gas_limit,
    })
}

/// Executes a prepared CIP-64 transaction.
///
/// With a fee currency, the transaction runs at the fee-currency gas price (which `GASPRICE`
/// returns), and `creditGasFees` then refunds the unused gas to the sender, pays the tip to the
/// coinbase (or the `FeeHandler` if the coinbase is zero) and the base fee to the `FeeHandler`. A
/// failed credit invalidates the transaction.
fn execute_cip64(
    req: TxRequest<'_, '_, CeloEvmTypes, TxEip1559>,
    prepared: PreparedCip64,
) -> HandlerResult<TxResult<CeloEvmTypes>> {
    let (prepared, fee_currency, base_fee_in_erc20, charge, credit_gas_limit) = match prepared {
        PreparedCip64::Native(prepared) => {
            let basefee = req.host.block().basefee.saturating_to();
            let mut result = eip1559::execute_prepared::<CeloEvmTypes, Hooks>(req, prepared)?;
            result.ext.base_fee_in_erc20 = Some(basefee);
            return Ok(result);
        }
        PreparedCip64::FeeCurrency {
            prepared,
            fee_currency,
            base_fee_in_erc20,
            charge,
            credit_gas_limit,
        } => (prepared, fee_currency, base_fee_in_erc20, charge, credit_gas_limit),
    };
    let tx = req.tx.inner();
    let host = req.host;
    let result = execute_frame(host, *tx, &prepared)?;
    let mut result = finalize_gas(
        host,
        GasSettlement {
            caller: prepared.caller,
            gas_price: prepared.gas_price,
            gas_limit: tx.gas_limit,
            floor_gas: prepared.floor_gas,
            initial_state_gas: 0,
            state_refund: 0,
            result,
        },
    )?;

    if charge {
        // celo-revm computes the credit amounts with saturating `u128` arithmetic.
        let gas_used = u128::from(result.tx_gas_used());
        let gas_price = prepared.gas_price.to::<u128>();
        let refund = gas_price.saturating_mul(u128::from(tx.gas_limit).saturating_sub(gas_used));
        let tip = gas_price.saturating_sub(base_fee_in_erc20).saturating_mul(gas_used);
        let base_fee = base_fee_in_erc20.saturating_mul(gas_used);
        let beneficiary = host.block().beneficiary;
        let fee_recipient =
            if beneficiary.is_zero() { CELO_FEE_HANDLER_ADDRESS } else { beneficiary };
        let credit = credit_gas_fees(
            host,
            fee_currency,
            prepared.caller,
            fee_recipient,
            CELO_FEE_HANDLER_ADDRESS,
            U256::from(refund),
            U256::from(tip),
            U256::from(base_fee),
            credit_gas_limit,
        )?;
        if !credit.status {
            return Err(HandlerError::external(CeloTxError::CreditFailed));
        }
    }
    result.ext.base_fee_in_erc20 = Some(base_fee_in_erc20);
    Ok(result)
}

/// Returns the Celo transaction registry for `spec`.
///
/// Registers deposits (type `0x7e`), CIP-64 (type `0x7b`), and the standard legacy, EIP-2930,
/// EIP-1559 and, from Isthmus (Prague), EIP-7702 handlers wired with [`CeloHandlerHooks`]. There
/// is no EIP-4844 on Celo.
pub fn celo_tx_registry(spec: OpSpecId) -> TxRegistry<CeloEvmTypes, TxResult<CeloEvmTypes>> {
    let mut registry = TxRegistry::new()
        .with_handler(
            DEPOSIT_TRANSACTION_TYPE,
            CeloTxEnvelope::as_deposit,
            handler(prepare_deposit, execute_deposit),
        )
        .with_handler(
            0,
            CeloTxEnvelope::as_legacy,
            handler(prepare_legacy, legacy::execute_prepared::<CeloEvmTypes, Hooks>),
        )
        .with_handler(1, CeloTxEnvelope::as_eip2930, handler(prepare_eip2930, execute_eip2930))
        .with_handler(
            2,
            CeloTxEnvelope::as_eip1559,
            handler(prepare_eip1559, eip1559::execute_prepared::<CeloEvmTypes, Hooks>),
        )
        .with_handler(CIP64_TX_TYPE, as_cip64, handler(prepare_cip64, execute_cip64));
    if spec.into_eth_spec().enables(SpecId::PRAGUE) {
        registry.register(
            4,
            CeloTxEnvelope::as_eip7702,
            handler(prepare_eip7702, eip7702::execute_prepared::<CeloEvmTypes, Hooks>),
        );
    }
    registry
}
