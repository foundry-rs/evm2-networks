//! Arbitrum transaction handlers.
//!
//! Port of the user-transaction parts of Nitro's `arbos/tx_processor.go` (`GasChargingHook`,
//! `EndTxHook`) and of its changes to `core/state_transition.go`. Signed Ethereum transactions
//! reuse the stock evm2 handlers with [`ArbHandlerHooks`], which:
//!
//! - drop the tip, so the transaction pays the base fee, unless ArbOS collects tips;
//! - charge the L1 poster gas ([`ArbTxEnvelope::poster_gas`]) like intrinsic gas, excluded from the
//!   refund cap;
//! - hold back the gas above the ArbOS transaction gas limit during execution;
//! - apply the EIP-7623 calldata floor only when the ArbOS feature enabling it is on;
//! - distribute the fees: the tip and the base fee on compute gas to the network fee account, the
//!   infrastructure share to the infrastructure fee account, and the poster fee to the L1 pricer
//!   funds pool;
//! - grow the L2 gas backlog by the compute gas.

use crate::{
    ArbEvm, ArbEvmExt, ArbEvmTypes, ArbOsVersion, ArbTxEnvelope, ArbTxResultExt,
    BATCH_POSTER_ADDRESS, L1_PRICER_FUNDS_POOL_ADDRESS,
    state::{ArbOsStorage, l1_pricing, l2_pricing, root},
};
use alloy_consensus::Transaction;
use alloy_primitives::{Address, U256};
use evm2::{
    DatabaseError, EvmFeatures, SpecId, TxResult,
    ethereum::{
        charge_upfront, effective_gas_price, eip1559, eip2930, eip7702, finalize_gas, legacy,
    },
    evm::State,
    handler::{GasSettlement, TxHandlerHooks},
    registry::{HandlerError, HandlerResult, TxRegistry, handler},
    version::GasId,
};

/// Feature flag bit enabling the EIP-7623 calldata floor
/// (`features.IsIncreasedCalldataPriceEnabled`).
const INCREASED_CALLDATA_PRICE_FEATURE_BIT: usize = 0;

/// Handler hooks for signed Ethereum transactions on Arbitrum.
#[derive(Clone, Copy, Debug, Default)]
pub struct ArbHandlerHooks;

impl TxHandlerHooks<ArbEvmTypes> for ArbHandlerHooks {
    /// Port of the tip dropping in `StateTransition.TransitionDb` and of `GasChargingHook`.
    fn adjust_intrinsic_gas(
        host: &mut ArbEvm<'_>,
        envelope: &ArbTxEnvelope,
        intrinsic: &mut u64,
        _initial_state_gas: &mut u64,
        floor_gas: &mut u64,
    ) -> HandlerResult<()> {
        let version = host.config_spec_id();
        let basefee = host.block().basefee;
        let tx = &envelope.tx;
        let max_fee = U256::from(tx.max_fee_per_gas());
        let max_priority_fee = tx.max_priority_fee_per_gas().map(U256::from);
        let gas_price = max_priority_fee
            .map_or(max_fee, |priority_fee| effective_gas_price(max_fee, priority_fee, basefee));

        let drop_tip = gas_price > basefee && !collect_tips(host, version)?;
        // The stock priority fee check is disabled (see `arbitrum_version`): Nitro runs it after
        // dropping the tip, which zeroes the priority fee.
        if !drop_tip
            && host.feature(EvmFeatures::BASE_FEE_CHECK)
            && max_priority_fee.is_some_and(|priority_fee| priority_fee > max_fee)
        {
            return Err(HandlerError::PriorityFeeGreaterThanMaxFee);
        }
        let paid_gas_price = if drop_tip { basefee } else { gas_price };

        let state = host.state_mut();
        if !version.enables(ArbOsVersion::V40)
            || !ArbOsStorage::FEATURES.get(state, 0)?.bit(INCREASED_CALLDATA_PRICE_FEATURE_BIT)
        {
            *floor_gas = 0;
        }

        let poster_gas = if basefee.is_zero() { 0 } else { envelope.poster_gas };
        let poster_price = if paid_gas_price.is_zero() { basefee } else { paid_gas_price };
        let poster_fee = poster_price * U256::from(poster_gas);

        let gas_cap = if version.enables(ArbOsVersion::V50) {
            let limit = ArbOsStorage::L2_PRICING.get(state, l2_pricing::PER_TX_GAS_LIMIT)?;
            limit.saturating_to::<u64>().saturating_sub(*intrinsic)
        } else {
            ArbOsStorage::L2_PRICING.get(state, l2_pricing::PER_BLOCK_GAS_LIMIT)?.saturating_to()
        };
        let charged = intrinsic.saturating_add(poster_gas);
        let held_gas = tx.gas_limit().saturating_sub(charged).saturating_sub(gas_cap);
        *intrinsic = charged.saturating_add(held_gas);

        *host.ext_mut() =
            ArbEvmExt { sender: Address::ZERO, paid_gas_price, poster_gas, poster_fee, held_gas };
        Ok(())
    }

    /// Buys gas at the price the transaction pays.
    fn before_execution(
        host: &mut ArbEvm<'_>,
        envelope: &ArbTxEnvelope,
        caller: Address,
        _upfront_fee: U256,
    ) -> HandlerResult<()> {
        host.ext_mut().sender = caller;
        let gas_limit = U256::from(envelope.tx.gas_limit());
        charge_upfront(host, caller, gas_limit * host.ext().paid_gas_price)?;
        Ok(())
    }

    /// Port of Nitro's refund calculation and of `EndTxHook` for signed transactions.
    fn settle_transaction(
        host: &mut ArbEvm<'_>,
        _envelope: &ArbTxEnvelope,
        mut gas: GasSettlement<ArbEvmTypes>,
    ) -> HandlerResult<TxResult<ArbEvmTypes>> {
        let ArbEvmExt { paid_gas_price, poster_gas, poster_fee, held_gas, .. } = *host.ext();
        let caller = gas.caller;
        let gas_limit = gas.gas_limit;

        // The held gas is returned before the refund is computed, and the poster gas does not count
        // towards the refund cap.
        gas.result.gas.erase_cost(held_gas);
        let refund_counter = gas.result.gas.refunded().max(0) as u64;
        let mut result = finalize_gas(host, gas)?;
        let quotient = u64::from(host.version().gas_params.get(GasId::MaxRefundQuotient)).max(1);
        result.refunded =
            refund_counter.min(result.total_gas_spent.saturating_sub(poster_gas) / quotient);
        result.ext = ArbTxResultExt { poster_gas, poster_fee, paid_gas_price };
        if !host.feature(EvmFeatures::FEE_CHARGE) {
            return Ok(result);
        }

        let version = host.config_spec_id();
        let basefee = host.block().basefee;
        let gas_used = result.tx_gas_used();
        let compute_gas = gas_used.saturating_sub(poster_gas);
        let state = host.state_mut();
        state
            .account(&caller)?
            .add_balance(U256::from(gas_limit.saturating_sub(gas_used)) * paid_gas_price);

        let network_fee_account =
            Address::from_word(ArbOsStorage::ROOT.get(state, root::NETWORK_FEE_ACCOUNT)?.into());
        let tip = U256::from(compute_gas) * paid_gas_price.saturating_sub(basefee);
        let mut compute_cost = U256::from(compute_gas) * basefee;
        if version.enables(ArbOsVersion::V5) {
            let infra_fee_account =
                Address::from_word(ArbOsStorage::ROOT.get(state, root::INFRA_FEE_ACCOUNT)?.into());
            if !infra_fee_account.is_zero() {
                let min_base_fee =
                    ArbOsStorage::L2_PRICING.get(state, l2_pricing::MIN_BASE_FEE_WEI)?;
                let infra_cost = U256::from(compute_gas) * min_base_fee.min(basefee);
                state.account(&infra_fee_account)?.add_balance(infra_cost);
                compute_cost -= infra_cost;
            }
        }
        state.account(&network_fee_account)?.add_balance(tip + compute_cost);

        let poster_fee_destination = if version.enables(ArbOsVersion::V2) {
            L1_PRICER_FUNDS_POOL_ADDRESS
        } else {
            host.block().beneficiary
        };
        let state = host.state_mut();
        state.account(&poster_fee_destination)?.add_balance(poster_fee);
        if version.enables(ArbOsVersion::V10) {
            let available = ArbOsStorage::L1_PRICING.get(state, l1_pricing::L1_FEES_AVAILABLE)?;
            ArbOsStorage::L1_PRICING.set(
                state,
                l1_pricing::L1_FEES_AVAILABLE,
                available + poster_fee,
            )?;
        }

        if !paid_gas_price.is_zero() {
            let compute_gas = if gas_used > poster_gas { compute_gas } else { gas_used };
            grow_backlog(state, version, compute_gas)?;
        }
        Ok(result)
    }
}

/// Returns whether the transaction pays its full effective gas price (`TxProcessor.CollectTips`).
///
/// Delayed-inbox messages, whose block coinbase is not the batch poster, never pay tips.
fn collect_tips(host: &mut ArbEvm<'_>, version: ArbOsVersion) -> Result<bool, DatabaseError> {
    if host.block().beneficiary != BATCH_POSTER_ADDRESS {
        return Ok(false);
    }
    if version == ArbOsVersion::V9 {
        return Ok(true);
    }
    if !version.enables(ArbOsVersion::V60) {
        return Ok(false);
    }
    Ok(!ArbOsStorage::ROOT.get(host.state_mut(), root::COLLECT_TIPS)?.is_zero())
}

/// Grows the L2 gas backlog of the active gas pricing model (`L2PricingState.GrowBacklog`).
///
/// The multi-gas constraint model, from ArbOS 60, prices each resource separately and needs the
/// transaction's multi-dimensional gas, which evm2 does not track. Its backlogs are not updated.
fn grow_backlog(
    state: &mut State<'_>,
    version: ArbOsVersion,
    compute_gas: u64,
) -> Result<(), DatabaseError> {
    if version.enables(ArbOsVersion::V60)
        && !ArbOsStorage::MULTI_GAS_CONSTRAINTS.get(state, 0)?.is_zero()
    {
        return Ok(());
    }
    let constraints: u64 = if version.enables(ArbOsVersion::V50) {
        ArbOsStorage::GAS_CONSTRAINTS.get(state, 0)?.saturating_to()
    } else {
        0
    };
    // The legacy model keeps one backlog; with constraints, each constraint keeps its own.
    let legacy = (constraints == 0).then_some((ArbOsStorage::L2_PRICING, l2_pricing::GAS_BACKLOG));
    let constraint_backlogs = (0..constraints).map(|index| {
        (ArbOsStorage::GAS_CONSTRAINTS.open(&index.to_be_bytes()), l2_pricing::CONSTRAINT_BACKLOG)
    });
    for (storage, offset) in legacy.into_iter().chain(constraint_backlogs) {
        let backlog = storage.get(state, offset)?.saturating_to::<u64>();
        storage.set(state, offset, U256::from(backlog.saturating_add(compute_gas)))?;
    }
    Ok(())
}

/// Returns the transaction registry for an ArbOS version.
///
/// Legacy, EIP-2930 and EIP-1559 transactions are always supported, and EIP-7702 transactions
/// from ArbOS 40 (Prague). Arbitrum does not accept EIP-4844 transactions, and Nitro's own
/// transaction types ([`is_arbitrum_tx_type`](crate::is_arbitrum_tx_type)) are not executed.
pub fn arbitrum_tx_registry(spec: ArbOsVersion) -> TxRegistry<ArbEvmTypes, TxResult<ArbEvmTypes>> {
    type T = ArbEvmTypes;
    type H = ArbHandlerHooks;
    let mut registry = TxRegistry::new()
        .with_handler(
            0,
            |tx: &ArbTxEnvelope| tx.tx.as_legacy(),
            handler(legacy::prepare_with_hooks::<T, H>, legacy::execute_prepared::<T, H>),
        )
        .with_handler(
            1,
            |tx: &ArbTxEnvelope| tx.tx.as_eip2930(),
            handler(eip2930::prepare_with_hooks::<T, H>, eip2930::execute_prepared::<T, H>),
        )
        .with_handler(
            2,
            |tx: &ArbTxEnvelope| tx.tx.as_eip1559(),
            handler(eip1559::prepare_with_hooks::<T, H>, eip1559::execute_prepared::<T, H>),
        );
    if spec.into_eth_spec().enables(SpecId::PRAGUE) {
        registry.register(
            4,
            |tx: &ArbTxEnvelope| tx.tx.as_eip7702(),
            handler(eip7702::prepare_with_hooks::<T, H>, eip7702::execute_prepared::<T, H>),
        );
    }
    registry
}
