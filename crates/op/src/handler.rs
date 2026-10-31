//! OP transaction handlers.
//!
//! Port of `op-revm/src/handler.rs` onto evm2's typed handler registry. Regular transactions reuse
//! the stock evm2 handlers with [`OpHandlerHooks`] for the L1 data fee, the operator fee and the
//! fee vaults. Deposits have a dedicated handler.

use crate::{
    L1BlockInfo, OpEvmTypes, OpSpecId, OpTxEnvelope, OpTxResultExt, TxDeposit,
    constants::{
        BASE_FEE_RECIPIENT, DEPOSIT_TRANSACTION_TYPE, L1_FEE_RECIPIENT, OPERATOR_FEE_RECIPIENT,
    },
};
use alloy_consensus::{Transaction, TxEip1559, TxEip2930, TxLegacy};
use alloy_primitives::{Address, U256};
use evm2::{
    Evm, EvmFeatures, SpecId, TxResult, TxResultExt,
    env::TxEnvExt,
    ethereum::{
        LazyTxEip7702, PreparedTx, eip1559, eip2930, eip7702, execute_initial_frame, finalize_gas,
        initial_gas_and_reservoir, intrinsic_and_floor_gas, legacy, prepare_initial_frame,
        validate_floor_gas, validate_intrinsic_gas, warm_base_accounts,
    },
    handler::{GasSettlement, TxHandlerHooks},
    interpreter::{GasTracker, InstrStop},
    registry::{HandlerError, HandlerResult, TxRegistry, TxRequest, handler},
};

/// OP-specific transaction validation errors, surfaced as [`HandlerError::External`].
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum OpTxError {
    /// Non-deposit transactions must carry their EIP-2718 enveloped bytes to compute the L1 fee.
    #[error("missing enveloped transaction bytes for non-deposit transaction")]
    MissingEnvelopedTx,
    /// Deposit system transactions are not supported after Regolith.
    ///
    /// Like op-revm, this never surfaces from execution: it turns the deposit into a failed
    /// deposit (see [`OpTxResultExt::failed_deposit`]).
    #[error("deposit system transactions post regolith hardfork are not supported")]
    DepositSystemTxPostRegolith,
}

/// Handler hooks for regular (non-deposit) OP transactions.
#[derive(Clone, Copy, Debug, Default)]
pub struct OpHandlerHooks;

/// Reloads the cached L1 block info when it was not loaded for the current block, and clears the
/// per-transaction L1 cost cache.
fn load_l1_block_info(host: &mut Evm<'_, OpEvmTypes>) -> HandlerResult<()> {
    let number = host.block().number;
    if host.ext().l1_block_info.l2_block != Some(number) {
        let spec = host.config_spec_id();
        host.ext_mut().l1_block_info = L1BlockInfo::try_fetch(host.state_mut(), number, spec)?;
    }
    // op-revm clears the cache after every transaction; clearing it before the next one also
    // covers validation-only runs, which do not reach settlement.
    host.ext_mut().l1_block_info.clear_tx_l1_cost();
    Ok(())
}

fn enveloped_tx(envelope: &OpTxEnvelope) -> HandlerResult<&[u8]> {
    envelope
        .enveloped_tx()
        .map(|bytes| bytes.as_ref())
        .ok_or_else(|| HandlerError::external(OpTxError::MissingEnvelopedTx))
}

impl TxHandlerHooks<OpEvmTypes> for OpHandlerHooks {
    /// Port of the non-deposit branch of op-revm's `validate_against_state_and_deduct_caller`.
    fn before_execution(
        host: &mut Evm<'_, OpEvmTypes>,
        envelope: &OpTxEnvelope,
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
                return Err(HandlerError::InsufficientFunds { fee: required, balance });
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

    /// Port of op-revm's `reimburse_caller` (operator fee refund) and `reward_beneficiary` (fee
    /// vaults).
    fn settle_transaction(
        host: &mut Evm<'_, OpEvmTypes>,
        envelope: &OpTxEnvelope,
        gas: GasSettlement<OpEvmTypes>,
    ) -> HandlerResult<TxResult<OpEvmTypes>> {
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
            // Every OP spec is post-London, so the base fee is always burned from the tip.
            let beneficiary = host.block().beneficiary;
            let reward = U256::from(gas_used).saturating_mul(gas_price.saturating_sub(basefee));
            host.state_mut().account(&beneficiary)?.add_balance(reward);
        }

        // Like op-revm, the vaults are credited even when fee charging is disabled.
        let base_fee_amount = basefee.saturating_mul(U256::from(gas_used));
        for (recipient, amount) in [
            (L1_FEE_RECIPIENT, l1_cost),
            (BASE_FEE_RECIPIENT, base_fee_amount),
            (OPERATOR_FEE_RECIPIENT, operator_fee_cost),
        ] {
            host.state_mut().account(&recipient)?.add_balance(amount);
        }

        result.ext.l1_fee = l1_cost;
        result.ext.operator_fee = operator_fee_cost;
        Ok(result)
    }
}

fn prepare_legacy(req: &mut TxRequest<'_, '_, OpEvmTypes, TxLegacy>) -> HandlerResult<PreparedTx> {
    enveloped_tx(req.envelope)?;
    legacy::prepare_with_hooks::<OpEvmTypes, OpHandlerHooks>(req)
}

fn prepare_eip2930(
    req: &mut TxRequest<'_, '_, OpEvmTypes, TxEip2930>,
) -> HandlerResult<PreparedTx> {
    enveloped_tx(req.envelope)?;
    eip2930::prepare_with_hooks::<OpEvmTypes, OpHandlerHooks>(req)
}

fn prepare_eip1559(
    req: &mut TxRequest<'_, '_, OpEvmTypes, TxEip1559>,
) -> HandlerResult<PreparedTx> {
    enveloped_tx(req.envelope)?;
    eip1559::prepare_with_hooks::<OpEvmTypes, OpHandlerHooks>(req)
}

fn prepare_eip7702(
    req: &mut TxRequest<'_, '_, OpEvmTypes, LazyTxEip7702>,
) -> HandlerResult<PreparedTx> {
    enveloped_tx(req.envelope)?;
    eip7702::prepare_with_hooks::<OpEvmTypes, OpHandlerHooks>(req)
}

/// Deposit state after preparation.
#[derive(Debug)]
enum PreparedDeposit {
    /// The deposit passed validation; mint and nonce bump are applied.
    Ready { intrinsic: u64, floor_gas: u64, nonce: u64 },
    /// The deposit failed validation and will be included as a failed deposit.
    Failed(HandlerError),
}

/// Returns `true` for errors that are not attributable to the transaction (database and fatal
/// errors), which op-revm surfaces instead of turning a deposit into a failed deposit.
const fn is_non_tx_error(error: &HandlerError) -> bool {
    matches!(error, HandlerError::Database(_) | HandlerError::Fatal(_))
}

/// Port of the deposit branches of op-revm's `validate_env`, `validate_initial_tx_gas` and
/// `validate_against_state_and_deduct_caller`.
fn prepare_deposit(
    req: &mut TxRequest<'_, '_, OpEvmTypes, TxDeposit>,
) -> HandlerResult<PreparedDeposit> {
    match try_prepare_deposit(req) {
        Ok(prepared) => Ok(prepared),
        Err(error) if is_non_tx_error(&error) => Err(error),
        Err(error) => Ok(PreparedDeposit::Failed(error)),
    }
}

fn try_prepare_deposit(
    req: &mut TxRequest<'_, '_, OpEvmTypes, TxDeposit>,
) -> HandlerResult<PreparedDeposit> {
    let tx = req.tx.inner();
    let host = &mut *req.host;
    let spec = host.config_spec_id();
    if tx.is_system_transaction && spec.is_enabled_in(OpSpecId::REGOLITH) {
        return Err(HandlerError::external(OpTxError::DepositSystemTxPostRegolith));
    }

    // Deposits skip the environment checks (chain id, gas limit caps, initcode size), but not the
    // intrinsic and floor gas checks.
    let (intrinsic, floor_gas) =
        intrinsic_and_floor_gas(host.version(), tx.from, tx.to, &tx.input, 0, 0, tx.value);
    validate_intrinsic_gas(tx.gas_limit, intrinsic, 0)?;
    validate_floor_gas(tx.gas_limit, floor_gas)?;

    host.state_mut().prewarm(&tx.from);
    warm_base_accounts(host, tx.to);

    // No nonce or code checks and no fee charge: mint, then bump the nonce.
    let balance_check = host.feature(EvmFeatures::BALANCE_CHECK);
    let balance_top_up = host.feature(EvmFeatures::BALANCE_TOP_UP);
    let mut caller = host.state_mut().account(&tx.from)?;
    let mut balance = caller.balance().saturating_add(U256::from(tx.mint));
    if !balance_check && balance_top_up {
        // Not consensus critical: used in testing so the value transfer cannot fail.
        balance = balance.max(tx.value);
    }
    caller.set_balance(balance);
    let nonce = caller.nonce();
    caller.bump_nonce();

    Ok(PreparedDeposit::Ready { intrinsic, floor_gas, nonce })
}

/// Port of op-revm's deposit execution and gas accounting (`last_frame_result`, `refund`,
/// `execution_result` and `catch_error_failed_deposit`).
fn execute_deposit(
    req: TxRequest<'_, '_, OpEvmTypes, TxDeposit>,
    prepared: PreparedDeposit,
) -> HandlerResult<TxResult<OpEvmTypes>> {
    let tx = req.tx.inner();
    let host = req.host;
    let (intrinsic, floor_gas, nonce) = match prepared {
        PreparedDeposit::Ready { intrinsic, floor_gas, nonce } => (intrinsic, floor_gas, nonce),
        PreparedDeposit::Failed(error) => {
            return failed_deposit(host, tx, InstrStop::OutOfGas, Some(error));
        }
    };
    let is_regolith = host.config_spec_id().is_enabled_in(OpSpecId::REGOLITH);

    let (execution_gas_limit, reservoir) =
        initial_gas_and_reservoir(host.version(), tx.gas_limit, intrinsic, 0);
    *host.tx_env_mut() = TxEnvExt {
        origin: tx.from,
        gas_price: U256::ZERO,
        chain_id: U256::from(host.version().chain_id),
        ..TxEnvExt::default()
    };
    let mut tx_gas =
        GasTracker::new_with_execution_gas_and_reservoir(execution_gas_limit, reservoir);
    let frame =
        prepare_initial_frame(host, tx.from, nonce, tx.to, &tx.input, tx.value, &mut tx_gas)?;
    let result = execute_initial_frame(host, frame, &mut tx_gas, execution_gas_limit, reservoir)?;

    // Post-Regolith, a deposit whose top-level frame fails for any reason other than `REVERT`
    // keeps only the nonce bump and the mint. That includes `OutOfFunds` and `CallTooDeep`, which
    // the interpreter counts as frame-level reverts but op-revm treats as halts here.
    if !result.stop.is_success() && result.stop != InstrStop::Revert && is_regolith {
        return failed_deposit(host, tx, result.stop, None);
    }

    let stop = result.stop;
    let mut result = finalize_gas(
        host,
        GasSettlement {
            caller: tx.from,
            gas_price: U256::ZERO,
            gas_limit: tx.gas_limit,
            floor_gas,
            initial_state_gas: 0,
            state_refund: 0,
            result,
        },
    )?;
    if !is_regolith {
        // Bedrock: deposits report their gas limit as gas used and get no refunds, except
        // successful system transactions, which report zero.
        result.refunded = 0;
        result.total_gas_spent =
            if stop.is_success() && tx.is_system_transaction { 0 } else { tx.gas_limit };
    }
    // Deposits are pre-paid on L1: no caller reimbursement, no beneficiary reward, no vaults.
    Ok(result)
}

/// Discards all changes of a deposit except the caller nonce bump and the mint, and reports it as
/// a failed deposit.
fn failed_deposit(
    host: &mut Evm<'_, OpEvmTypes>,
    tx: &TxDeposit,
    stop: InstrStop,
    deposit_error: Option<HandlerError>,
) -> HandlerResult<TxResult<OpEvmTypes>> {
    let is_regolith = host.config_spec_id().is_enabled_in(OpSpecId::REGOLITH);
    host.state_mut().clear_transaction_state();
    let mut caller = host.state_mut().account(&tx.from)?;
    caller.bump_nonce();
    caller.add_balance(U256::from(tx.mint));

    // Gas used is the gas limit post-Regolith; pre-Regolith it is the gas limit for regular
    // deposits and zero for system transactions.
    let gas_used = if is_regolith || !tx.is_system_transaction { tx.gas_limit } else { 0 };
    Ok(TxResultExt {
        status: false,
        total_gas_spent: gas_used,
        stop,
        ext: OpTxResultExt { failed_deposit: true, deposit_error, ..Default::default() },
        ..TxResultExt::default()
    })
}

/// Returns the OP transaction registry for `spec`.
///
/// Legacy, EIP-2930, EIP-1559 and deposit transactions are always supported (every OP spec is
/// post-London); EIP-7702 from Isthmus (Prague). There is no EIP-4844 on OP.
pub fn op_tx_registry(spec: OpSpecId) -> TxRegistry<OpEvmTypes, TxResult<OpEvmTypes>> {
    let mut registry = TxRegistry::new()
        .with_handler(
            0,
            OpTxEnvelope::as_legacy,
            handler(prepare_legacy, legacy::execute_prepared::<OpEvmTypes, OpHandlerHooks>),
        )
        .with_handler(
            1,
            OpTxEnvelope::as_eip2930,
            handler(prepare_eip2930, eip2930::execute_prepared::<OpEvmTypes, OpHandlerHooks>),
        )
        .with_handler(
            2,
            OpTxEnvelope::as_eip1559,
            handler(prepare_eip1559, eip1559::execute_prepared::<OpEvmTypes, OpHandlerHooks>),
        )
        .with_handler(
            DEPOSIT_TRANSACTION_TYPE,
            OpTxEnvelope::as_deposit,
            handler(prepare_deposit, execute_deposit),
        );
    if spec.into_eth_spec().enables(SpecId::PRAGUE) {
        registry.register(
            4,
            OpTxEnvelope::as_eip7702,
            handler(prepare_eip7702, eip7702::execute_prepared::<OpEvmTypes, OpHandlerHooks>),
        );
    }
    registry
}
