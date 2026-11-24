//! Arc transaction handling: the blocklist, undiscounted fees and the first frame's transfer rules.

use crate::{
    ArcEvm, ArcEvmTypes, ArcHardfork, ArcSpecId, NATIVE_COIN_CONTROL_ADDRESS,
    transfer::{self, ERR_BLOCKED_ADDRESS, ERR_ZERO_ADDRESS},
};
use alloy_consensus::Transaction;
use alloy_primitives::{Address, TxKind, U256};
use evm2::{
    EvmFeatures, HostError, SpecId, TxResult,
    ethereum::{self, TxEnvelope, eip1559, eip2930, eip4844, eip7702, legacy},
    evm::handler::{GasSettlement, TxHandlerHooks},
    interpreter::Host,
    registry::{HandlerError, HandlerResult, TxRegistry, handler},
};

/// Transaction rejected by an Arc rule.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum ArcTxError {
    /// The sender, or the recipient of a value transfer, is blocklisted.
    #[error("Blocked address")]
    BlockedAddress,
    /// The first frame moves value that arc-node would revert; evm2 offers no hook to revert it.
    #[error("first frame transfer rejected: {0}")]
    RejectedTransfer(&'static str),
    /// The fees would credit a beneficiary self-destructed in the transaction (Zero8).
    #[error("Cannot increase the balance of selfdestructed account")]
    SelfDestructedBeneficiary,
}

/// Arc transaction handler hooks.
#[derive(Clone, Copy, Debug, Default)]
pub struct ArcTxHandlerHooks;

impl TxHandlerHooks<ArcEvmTypes> for ArcTxHandlerHooks {
    fn before_execution(
        host: &mut ArcEvm<'_>,
        envelope: &TxEnvelope,
        caller: Address,
        upfront_fee: U256,
    ) -> HandlerResult<()> {
        // arc-node warms `NativeCoinControl` for every transaction.
        host.load_account(&NATIVE_COIN_CONTROL_ADDRESS, false, false).map_err(handler_error)?;
        let mut blocked = transfer::is_blocklisted(host, caller).map_err(handler_error)?;
        if let TxKind::Call(to) = envelope.kind()
            && !blocked
            && !envelope.value().is_zero()
        {
            blocked = transfer::is_blocklisted(host, to).map_err(handler_error)?;
        }
        if blocked {
            return Err(HandlerError::external(ArcTxError::BlockedAddress));
        }
        if let Some(reason) = first_frame_rejection(host, envelope, caller)? {
            return Err(HandlerError::external(ArcTxError::RejectedTransfer(reason)));
        }
        ethereum::charge_upfront(host, caller, upfront_fee)
    }

    fn settle_transaction(
        host: &mut ArcEvm<'_>,
        _envelope: &TxEnvelope,
        gas: GasSettlement<ArcEvmTypes>,
    ) -> HandlerResult<TxResult<ArcEvmTypes>> {
        let (caller, gas_price, gas_limit) = (gas.caller, gas.gas_price, gas.gas_limit);
        let result = ethereum::finalize_gas(host, gas)?;
        if !host.feature(EvmFeatures::FEE_CHARGE) {
            return Ok(result);
        }
        let gas_used = result.tx_gas_used();
        let refund = U256::from(gas_limit.saturating_sub(gas_used)) * gas_price;
        host.state_mut().account(&caller)?.add_balance(refund);
        let beneficiary = host.block().beneficiary;
        if host.config_spec_id().is_active(ArcHardfork::Zero8)
            && host.state_mut().account(&beneficiary)?.is_destructed()
        {
            return Err(HandlerError::external(ArcTxError::SelfDestructedBeneficiary));
        }
        // arc-node pays the base fee to the beneficiary instead of burning it.
        host.state_mut().account(&beneficiary)?.add_balance(U256::from(gas_used) * gas_price);
        Ok(result)
    }
}

/// Converts a host failure into a handler failure.
fn handler_error(error: HostError) -> HandlerError {
    match error {
        HostError::Execution(error) => error.into(),
        HostError::Halt(stop) => HandlerError::Fatal(format!("unexpected halt: {stop:?}").into()),
    }
}

/// Returns why arc-node reverts the first frame's value transfer, past the sender checks.
fn first_frame_rejection(
    host: &mut ArcEvm<'_>,
    envelope: &TxEnvelope,
    caller: Address,
) -> HandlerResult<Option<&'static str>> {
    if envelope.value().is_zero() {
        return Ok(None);
    }
    Ok(match envelope.kind() {
        TxKind::Call(to) if to.is_zero() => Some(ERR_ZERO_ADDRESS),
        TxKind::Call(_) => None,
        TxKind::Create => {
            let created = caller.create(envelope.nonce());
            transfer::is_blocklisted(host, created)
                .map_err(handler_error)?
                .then_some(ERR_BLOCKED_ADDRESS)
        }
    })
}

/// Returns the Arc transaction registry: the Ethereum transaction types under Arc's rules.
pub fn arc_tx_registry(spec: ArcSpecId) -> TxRegistry<ArcEvmTypes, TxResult<ArcEvmTypes>> {
    type Hooks = ArcTxHandlerHooks;
    let eth = SpecId::from(spec);
    let mut registry = TxRegistry::new().with_handler(
        0,
        TxEnvelope::as_legacy,
        handler(
            legacy::prepare_with_hooks::<ArcEvmTypes, Hooks>,
            legacy::execute_prepared::<ArcEvmTypes, Hooks>,
        ),
    );
    if eth.enables(SpecId::BERLIN) {
        registry.register(
            1,
            TxEnvelope::as_eip2930,
            handler(
                eip2930::prepare_with_hooks::<ArcEvmTypes, Hooks>,
                eip2930::execute_prepared::<ArcEvmTypes, Hooks>,
            ),
        );
    }
    if eth.enables(SpecId::LONDON) {
        registry.register(
            2,
            TxEnvelope::as_eip1559,
            handler(
                eip1559::prepare_with_hooks::<ArcEvmTypes, Hooks>,
                eip1559::execute_prepared::<ArcEvmTypes, Hooks>,
            ),
        );
    }
    if eth.enables(SpecId::CANCUN) {
        registry.register(
            3,
            TxEnvelope::as_eip4844,
            handler(
                eip4844::prepare_with_hooks::<ArcEvmTypes, Hooks>,
                eip4844::execute_prepared::<ArcEvmTypes, Hooks>,
            ),
        );
    }
    if eth.enables(SpecId::PRAGUE) {
        registry.register(
            4,
            TxEnvelope::as_eip7702,
            handler(
                eip7702::prepare_with_hooks::<ArcEvmTypes, Hooks>,
                eip7702::execute_prepared::<ArcEvmTypes, Hooks>,
            ),
        );
    }
    registry
}
