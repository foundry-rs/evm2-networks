//! Monad transaction handlers.
//!
//! Port of `monad-revm` `handler.rs`:
//!
//! - Gas is charged on the full gas limit: there are no gas refunds, no caller reimbursement, and
//!   the beneficiary is paid `gas_limit * priority price`.
//! - Admission only requires the balance to cover the gas fee (`gas_limit * effective price`), not
//!   the value; the fee is deducted upfront.
//! - EIP-4844 transactions are not supported.
//! - The system sender cannot appear as an EIP-7702 authority.
//! - A call to an EIP-7702 delegated account dispatches to the precompile at the delegate.
//! - The reserve-balance tracker is initialized immediately before the first frame.
//! - With [`MonadEvmExt::protocol_replay`](crate::MonadEvmExt) enabled, legacy envelopes from the
//!   system sender execute as protocol system calls; see [`crate::protocol`].
//!
//! The standard [`EvmFeatures`] flags are honored as the evm2 Ethereum handlers do:
//! `TX_CHAIN_ID_CHECK`, `NONCE_CHECK`, `BALANCE_CHECK`, `BALANCE_TOP_UP`, `BLOCK_GAS_LIMIT_CHECK`,
//! `EIP3607`, `BASE_FEE_CHECK`, `PRIORITY_FEE_CHECK` and `FEE_CHARGE`.

use crate::{
    MonadEvmTypes, MonadHardfork, MonadTxResultExt,
    page::{self, StoragePageKey},
    protocol::{
        ProtocolSystemCall, ProtocolSystemCallError, execute_protocol_system_call,
        legacy_protocol_system_call, prepare_protocol_system_call,
    },
    reserve_balance::{
        begin_reserve_balance_tx, end_reserve_balance_tx, reserve_account, sync_reserve_balance,
    },
    staking::constants::SYSTEM_ADDRESS,
};
use alloy_consensus::{TxEip1559, TxEip2930, TxLegacy, transaction::TxEip4844Variant};
use alloy_eips::eip2930::AccessList;
use alloy_primitives::{Address, Bytes, KECCAK256_EMPTY, TxKind, U256};
use core::fmt;
use evm2::{
    Evm, EvmFeatures, TxResult,
    env::TxEnvExt,
    ethereum::{
        LazyAuthorization, LazyTxEip7702, TxEnvelope, access_list_counts, effective_gas_price,
        eip7702::{AuthRefunds, apply_auth_list},
        execute_initial_frame, finalize_gas, initial_gas_and_reservoir, intrinsic_and_floor_gas,
        prepare_initial_frame, validate_block_gas_limit, validate_chain_id,
        validate_create_initcode, validate_execution_gas_limit_cap, validate_floor_gas,
        validate_gas_price, validate_intrinsic_gas, validate_nonce_not_overflow,
        validate_priority_fee, validate_tx_gas_limit_cap, warm_access_list, warm_base_accounts,
    },
    handler::GasSettlement,
    interpreter::{GasTracker, InstrStop},
    registry::{HandlerError, HandlerResult, TxRegistry, TxRequest, handler},
    version::GasId,
};

/// Monad-specific transaction validation errors.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MonadInvalidTransaction {
    /// EIP-4844 blob transactions are not supported.
    Eip4844NotSupported,
    /// The system sender appears as an EIP-7702 authority.
    SystemTransactionSenderIsAuthority,
}

impl fmt::Display for MonadInvalidTransaction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Eip4844NotSupported => f.write_str("Eip4844 is not supported"),
            Self::SystemTransactionSenderIsAuthority => {
                f.write_str("system transaction sender is authority")
            }
        }
    }
}

impl core::error::Error for MonadInvalidTransaction {}

impl From<MonadInvalidTransaction> for HandlerError {
    fn from(error: MonadInvalidTransaction) -> Self {
        Self::external(error)
    }
}

/// Transaction fields shared by every supported transaction type.
#[derive(Debug)]
struct TxFields<'a> {
    chain_id: Option<u64>,
    allow_missing_chain_id: bool,
    nonce: u64,
    gas_limit: u64,
    max_fee_per_gas: U256,
    max_priority_fee_per_gas: Option<U256>,
    to: TxKind,
    value: U256,
    input: &'a Bytes,
    access_list: Option<&'a AccessList>,
    authorization_list: &'a [LazyAuthorization],
}

impl<'a> TxFields<'a> {
    fn legacy(tx: &'a TxLegacy) -> Self {
        Self {
            chain_id: tx.chain_id,
            allow_missing_chain_id: true,
            nonce: tx.nonce,
            gas_limit: tx.gas_limit,
            max_fee_per_gas: U256::from(tx.gas_price),
            max_priority_fee_per_gas: None,
            to: tx.to,
            value: tx.value,
            input: &tx.input,
            access_list: None,
            authorization_list: &[],
        }
    }

    fn eip2930(tx: &'a TxEip2930) -> Self {
        Self {
            chain_id: Some(tx.chain_id),
            allow_missing_chain_id: false,
            nonce: tx.nonce,
            gas_limit: tx.gas_limit,
            max_fee_per_gas: U256::from(tx.gas_price),
            max_priority_fee_per_gas: None,
            to: tx.to,
            value: tx.value,
            input: &tx.input,
            access_list: Some(&tx.access_list),
            authorization_list: &[],
        }
    }

    fn eip1559(tx: &'a TxEip1559) -> Self {
        Self {
            chain_id: Some(tx.chain_id),
            allow_missing_chain_id: false,
            nonce: tx.nonce,
            gas_limit: tx.gas_limit,
            max_fee_per_gas: U256::from(tx.max_fee_per_gas),
            max_priority_fee_per_gas: Some(U256::from(tx.max_priority_fee_per_gas)),
            to: tx.to,
            value: tx.value,
            input: &tx.input,
            access_list: Some(&tx.access_list),
            authorization_list: &[],
        }
    }

    fn eip7702(tx: &'a LazyTxEip7702) -> Self {
        Self {
            chain_id: Some(tx.chain_id),
            allow_missing_chain_id: false,
            nonce: tx.nonce,
            gas_limit: tx.gas_limit,
            max_fee_per_gas: U256::from(tx.max_fee_per_gas),
            max_priority_fee_per_gas: Some(U256::from(tx.max_priority_fee_per_gas)),
            to: TxKind::Call(tx.to),
            value: tx.value,
            input: &tx.input,
            access_list: Some(&tx.access_list),
            authorization_list: &tx.authorization_list,
        }
    }
}

/// Transaction state produced by Monad validation and pre-execution processing.
#[derive(Clone, Copy, Debug)]
pub struct MonadPreparedTx {
    caller: Address,
    gas_price: U256,
    intrinsic: u64,
    floor_gas: u64,
}

/// Validates a transaction against Monad rules and applies its pre-execution state changes.
fn prepare(
    host: &mut Evm<'_, MonadEvmTypes>,
    caller: Address,
    tx: &TxFields<'_>,
) -> HandlerResult<MonadPreparedTx> {
    let is_eip7702 = !tx.authorization_list.is_empty();
    // C++ parity (validate_monad_transaction.cpp): the system sender cannot be an authority.
    if tx.authorization_list.iter().any(|auth| auth.authority() == Some(SYSTEM_ADDRESS)) {
        return Err(MonadInvalidTransaction::SystemTransactionSenderIsAuthority.into());
    }

    let basefee = host.block().basefee;
    let gas_price = match tx.max_priority_fee_per_gas {
        Some(max_priority_fee_per_gas) => {
            validate_priority_fee(host.version(), tx.max_fee_per_gas, max_priority_fee_per_gas)?;
            effective_gas_price(tx.max_fee_per_gas, max_priority_fee_per_gas, basefee)
        }
        None => tx.max_fee_per_gas,
    };
    validate_gas_price(host.version(), gas_price, basefee)?;
    validate_chain_id(host.version(), tx.chain_id, tx.allow_missing_chain_id)?;
    validate_tx_gas_limit_cap(host.version(), tx.gas_limit)?;
    validate_block_gas_limit(host.version(), tx.gas_limit, host.block().gas_limit)?;
    validate_create_initcode(host.version(), tx.to, tx.input)?;
    validate_nonce_not_overflow(tx.nonce)?;

    let (access_list_accounts, access_list_storage_keys) =
        tx.access_list.map(access_list_counts).unwrap_or_default();
    let (mut intrinsic, floor_gas) = intrinsic_and_floor_gas(
        host.version(),
        caller,
        tx.to,
        tx.input,
        access_list_accounts,
        access_list_storage_keys,
        tx.value,
    );
    if is_eip7702 {
        let per_auth = host.version().gas_params.get(GasId::TxEip7702PerEmptyAccountCost);
        intrinsic += (tx.authorization_list.len() as u64).saturating_mul(per_auth);
    }
    validate_intrinsic_gas(tx.gas_limit, intrinsic, 0)?;
    validate_floor_gas(tx.gas_limit, floor_gas)?;
    validate_execution_gas_limit_cap(host.version(), tx.gas_limit, intrinsic, floor_gas)?;

    validate_and_charge_sender(host, caller, tx, gas_price)?;

    host.state_mut().prewarm(&caller);
    warm_base_accounts(host, tx.to);
    if let Some(access_list) = tx.access_list {
        warm_access_list(host, access_list);
        if MonadHardfork::MonadTen.is_enabled_in(host.config_spec_id()) {
            // MIP-8: access-listed slots warm their whole page.
            for item in access_list.iter() {
                for key in &item.storage_keys {
                    let key = StoragePageKey::from_slot(item.address, U256::from_be_bytes(key.0));
                    page::mark_read_accessed(host, key);
                }
            }
        }
    }

    host.state_mut().account(&caller)?.bump_nonce();

    Ok(MonadPreparedTx { caller, gas_price, intrinsic, floor_gas })
}

/// Validates the sender and deducts the upfront gas fee.
///
/// Port of `validate_monad_against_state_and_deduct_caller`: admission only requires the balance
/// to cover `gas_limit * effective_gas_price`. With the balance check disabled the balance is kept
/// high enough for the value transfer to proceed.
fn validate_and_charge_sender(
    host: &mut Evm<'_, MonadEvmTypes>,
    caller: Address,
    tx: &TxFields<'_>,
    gas_price: U256,
) -> HandlerResult<()> {
    let has_nonce_check = host.feature(EvmFeatures::NONCE_CHECK);
    let has_balance_check = host.feature(EvmFeatures::BALANCE_CHECK);
    let has_balance_top_up = host.feature(EvmFeatures::BALANCE_TOP_UP);
    let has_eip3607 = host.feature(EvmFeatures::EIP3607);
    let has_fee_charge = host.feature(EvmFeatures::FEE_CHARGE);

    let mut sender = host.state_mut().account(&caller)?;
    if has_eip3607 && sender.code_hash() != KECCAK256_EMPTY {
        let code = sender.load_code()?;
        if !code.is_empty() && !code.is_eip7702() {
            return Err(HandlerError::RejectCallerWithCode);
        }
    }
    if has_nonce_check && sender.nonce() != tx.nonce {
        return Err(HandlerError::InvalidNonce { expected: sender.nonce(), got: tx.nonce });
    }

    let gas_fee = U256::from(tx.gas_limit).saturating_mul(gas_price);
    let balance = sender.balance();
    if has_balance_check && balance < gas_fee {
        return Err(HandlerError::InsufficientFunds { fee: gas_fee, balance });
    }

    let mut new_balance = if has_fee_charge { balance.saturating_sub(gas_fee) } else { balance };
    if !has_balance_check && has_balance_top_up {
        // Preserve simulation semantics: skip rejection, but keep enough balance for the value
        // transfer to proceed.
        new_balance = new_balance.max(tx.value);
    }
    if new_balance != balance {
        sender.set_balance(new_balance);
    }
    Ok(())
}

/// Executes a prepared transaction and settles it with Monad gas rules.
fn execute(
    host: &mut Evm<'_, MonadEvmTypes>,
    tx: &TxFields<'_>,
    prepared: MonadPreparedTx,
) -> HandlerResult<TxResult<MonadEvmTypes>> {
    let result = execute_inner(host, tx, prepared);
    if result.is_err() {
        end_reserve_balance_tx(host);
    }
    result
}

fn execute_inner(
    host: &mut Evm<'_, MonadEvmTypes>,
    tx: &TxFields<'_>,
    prepared: MonadPreparedTx,
) -> HandlerResult<TxResult<MonadEvmTypes>> {
    let MonadPreparedTx { caller, gas_price, intrinsic, floor_gas } = prepared;
    let chain_id = host.version().chain_id;
    let (execution_gas_limit, reservoir) =
        initial_gas_and_reservoir(host.version(), tx.gas_limit, intrinsic, 0);
    let tx_env = TxEnvExt {
        origin: caller,
        gas_price,
        chain_id: U256::from(chain_id),
        ..TxEnvExt::default()
    };
    let mut tx_gas =
        GasTracker::new_with_execution_gas_and_reservoir(execution_gas_limit, reservoir);

    if !tx.authorization_list.is_empty() {
        // Monad disables refunds, so the authorization refunds are discarded.
        let mut refunds = AuthRefunds::new(host.version());
        apply_auth_list(host, chain_id, tx.authorization_list, &mut refunds)?;
    }

    host.ext_mut().memory_pool_offset = 0;
    let mut frame =
        prepare_initial_frame(host, caller, tx.nonce, tx.to, tx.input, tx.value, &mut tx_gas)?;
    if let Some(frame) = &mut frame {
        // Monad dispatches precompiles at the delegated address of the top-level call, while evm2
        // dispatches at the call target.
        frame.message.call_target = frame.message.code_address;
    }

    let effective_gas_price = u128::try_from(gas_price).unwrap_or(u128::MAX);
    begin_reserve_balance_tx(host, caller, effective_gas_price, tx.gas_limit)?;
    let checkpoint = host.state().checkpoint();

    let mut result =
        execute_initial_frame(host, &tx_env, frame, &mut tx_gas, execution_gas_limit, reservoir)?;

    sync_reserve_balance(host)?;
    let mut reverted_for_reserve_balance = false;
    if host.ext().revert_on_reserve_balance_violation
        && result.stop.is_success()
        && host.ext().reserve_balance.has_violation()
    {
        let features = host.version().features;
        host.state_mut().rollback(checkpoint, features);
        sync_reserve_balance(host)?;
        result.stop = InstrStop::Revert;
        result.output = Bytes::new();
        result.created_address = None;
        reverted_for_reserve_balance = true;
    }

    // Monad disables gas refunds.
    result.gas.set_refunded(0);
    let mut tx_result = finalize_gas(
        host,
        GasSettlement {
            caller,
            gas_price,
            gas_limit: tx.gas_limit,
            floor_gas,
            initial_state_gas: 0,
            state_refund: 0,
            result,
        },
    )?;

    if host.feature(EvmFeatures::FEE_CHARGE) {
        // Pay the full gas limit to the beneficiary; the caller is not reimbursed.
        let beneficiary_gas_price = if host.feature(EvmFeatures::BASE_FEE_CHECK) {
            gas_price.saturating_sub(host.block().basefee)
        } else {
            gas_price
        };
        let reward = U256::from(tx.gas_limit).saturating_mul(beneficiary_gas_price);
        let beneficiary = host.block().beneficiary;
        host.state_mut().account(&beneficiary)?.add_balance(reward);
        if host.ext().reserve_balance.tracking_enabled() {
            let view = reserve_account(host, beneficiary)?;
            host.ext_mut().reserve_balance.on_credit(Some(&view), beneficiary);
        }
    }

    tx_result.ext = MonadTxResultExt {
        dipped_into_reserve: host.ext().reserve_balance.has_violation(),
        reverted_for_reserve_balance,
    };
    end_reserve_balance_tx(host);
    Ok(tx_result)
}

/// Legacy transaction state: an ordinary transaction or a protocol system call.
#[derive(Debug)]
enum LegacyPrepared {
    Ordinary(MonadPreparedTx),
    Protocol(ProtocolSystemCall),
}

fn prepare_legacy(
    req: &mut TxRequest<'_, '_, MonadEvmTypes, TxLegacy>,
) -> HandlerResult<LegacyPrepared> {
    if req.host.ext().protocol_replay
        && let Some(call) = legacy_protocol_system_call(req.tx.signer(), req.tx.inner())?
    {
        prepare_protocol_system_call(req.host, &call)?;
        return Ok(LegacyPrepared::Protocol(call));
    }
    prepare(req.host, req.tx.signer(), &TxFields::legacy(req.tx.inner()))
        .map(LegacyPrepared::Ordinary)
}

fn execute_legacy(
    req: TxRequest<'_, '_, MonadEvmTypes, TxLegacy>,
    prepared: LegacyPrepared,
) -> HandlerResult<TxResult<MonadEvmTypes>> {
    match prepared {
        LegacyPrepared::Ordinary(prepared) => {
            execute(req.host, &TxFields::legacy(req.tx.inner()), prepared)
        }
        LegacyPrepared::Protocol(call) => execute_protocol_system_call(req.host, &call),
    }
}

/// Rejects non-legacy envelopes from the system sender while protocol replay is enabled.
fn reject_typed_protocol_tx(
    host: &Evm<'_, MonadEvmTypes>,
    caller: Address,
    tx_type: u8,
) -> HandlerResult<()> {
    if host.ext().protocol_replay && caller == SYSTEM_ADDRESS {
        return Err(ProtocolSystemCallError::NotLegacy { tx_type }.into());
    }
    Ok(())
}

fn prepare_eip2930(
    req: &mut TxRequest<'_, '_, MonadEvmTypes, TxEip2930>,
) -> HandlerResult<MonadPreparedTx> {
    reject_typed_protocol_tx(req.host, req.tx.signer(), 1)?;
    prepare(req.host, req.tx.signer(), &TxFields::eip2930(req.tx.inner()))
}

fn execute_eip2930(
    req: TxRequest<'_, '_, MonadEvmTypes, TxEip2930>,
    prepared: MonadPreparedTx,
) -> HandlerResult<TxResult<MonadEvmTypes>> {
    execute(req.host, &TxFields::eip2930(req.tx.inner()), prepared)
}

fn prepare_eip1559(
    req: &mut TxRequest<'_, '_, MonadEvmTypes, TxEip1559>,
) -> HandlerResult<MonadPreparedTx> {
    reject_typed_protocol_tx(req.host, req.tx.signer(), 2)?;
    prepare(req.host, req.tx.signer(), &TxFields::eip1559(req.tx.inner()))
}

fn execute_eip1559(
    req: TxRequest<'_, '_, MonadEvmTypes, TxEip1559>,
    prepared: MonadPreparedTx,
) -> HandlerResult<TxResult<MonadEvmTypes>> {
    execute(req.host, &TxFields::eip1559(req.tx.inner()), prepared)
}

fn prepare_eip4844(
    req: &mut TxRequest<'_, '_, MonadEvmTypes, TxEip4844Variant>,
) -> HandlerResult<MonadPreparedTx> {
    reject_typed_protocol_tx(req.host, req.tx.signer(), 3)?;
    Err(MonadInvalidTransaction::Eip4844NotSupported.into())
}

fn execute_eip4844(
    _req: TxRequest<'_, '_, MonadEvmTypes, TxEip4844Variant>,
    _prepared: MonadPreparedTx,
) -> HandlerResult<TxResult<MonadEvmTypes>> {
    Err(MonadInvalidTransaction::Eip4844NotSupported.into())
}

fn prepare_eip7702(
    req: &mut TxRequest<'_, '_, MonadEvmTypes, LazyTxEip7702>,
) -> HandlerResult<MonadPreparedTx> {
    reject_typed_protocol_tx(req.host, req.tx.signer(), 4)?;
    let tx = req.tx.inner();
    if tx.authorization_list.is_empty() {
        return Err(HandlerError::EmptyAuthorizationList);
    }
    prepare(req.host, req.tx.signer(), &TxFields::eip7702(tx))
}

fn execute_eip7702(
    req: TxRequest<'_, '_, MonadEvmTypes, LazyTxEip7702>,
    prepared: MonadPreparedTx,
) -> HandlerResult<TxResult<MonadEvmTypes>> {
    execute(req.host, &TxFields::eip7702(req.tx.inner()), prepared)
}

/// Returns the Monad transaction registry for `spec`.
///
/// Legacy, EIP-2930, EIP-1559 and EIP-7702 transactions are supported; EIP-4844 transactions are
/// rejected with [`MonadInvalidTransaction::Eip4844NotSupported`].
pub fn monad_tx_registry(
    _spec: MonadHardfork,
) -> TxRegistry<MonadEvmTypes, TxResult<MonadEvmTypes>> {
    // Every Monad hardfork inherits Prague or later, so every Ethereum type is gated in.
    TxRegistry::new()
        .with_handler(0, TxEnvelope::as_legacy, handler(prepare_legacy, execute_legacy))
        .with_handler(1, TxEnvelope::as_eip2930, handler(prepare_eip2930, execute_eip2930))
        .with_handler(2, TxEnvelope::as_eip1559, handler(prepare_eip1559, execute_eip1559))
        .with_handler(3, TxEnvelope::as_eip4844, handler(prepare_eip4844, execute_eip4844))
        .with_handler(4, TxEnvelope::as_eip7702, handler(prepare_eip7702, execute_eip7702))
}
