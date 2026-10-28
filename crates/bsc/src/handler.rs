//! BSC transaction handlers.
//!
//! Port of the Parlia-specific fee settlement in bsc's `core/state_transition.go`. BSC
//! transactions reuse the stock evm2 handlers with [`BscHandlerHooks`], which credit the whole
//! transaction fee to [`BSC_SYSTEM_ADDRESS`] instead of the coinbase.

use crate::{BSC_SYSTEM_ADDRESS, BscEvm, BscEvmTypes, BscHardfork};
use alloy_consensus::Transaction;
use alloy_eips::eip4844::DATA_GAS_PER_BLOB;
use alloy_primitives::U256;
use evm2::{
    EvmFeatures, SpecId, TxResult,
    ethereum::{TxEnvelope, eip1559, eip2930, eip4844, eip7702, finalize_gas, legacy},
    handler::{GasSettlement, TxHandlerHooks},
    registry::{HandlerResult, TxRegistry, handler},
};

/// Handler hooks for BSC transactions.
#[derive(Clone, Copy, Debug, Default)]
pub struct BscHandlerHooks;

impl TxHandlerHooks<BscEvmTypes> for BscHandlerHooks {
    /// Port of Parlia's fee settlement: refunds unused gas, then credits the fee above the base
    /// fee and the blob fee to [`BSC_SYSTEM_ADDRESS`]. The base fee is burnt. The block's
    /// system transactions later distribute the collected fees to validators.
    fn settle_transaction(
        host: &mut BscEvm<'_>,
        envelope: &TxEnvelope,
        gas: GasSettlement<BscEvmTypes>,
    ) -> HandlerResult<TxResult<BscEvmTypes>> {
        let caller = gas.caller;
        let gas_price = gas.gas_price;
        let gas_limit = gas.gas_limit;
        let result = finalize_gas(host, gas)?;
        if !host.feature(EvmFeatures::FEE_CHARGE) {
            return Ok(result);
        }

        let gas_used = result.tx_gas_used();
        let caller_refund = U256::from(gas_limit.saturating_sub(gas_used)) * gas_price;
        host.state_mut().account(&caller)?.add_balance(caller_refund);

        // The base fee is capped by the gas price so the credited fee never exceeds what the
        // sender paid, which only matters when base fee validation is disabled.
        let base_fee = if host.config_spec_id().into_eth_spec().enables(SpecId::LONDON) {
            host.block().basefee.min(gas_price)
        } else {
            U256::ZERO
        };
        let blobs = envelope.blob_versioned_hashes().map_or(0, <[_]>::len) as u64;
        let blob_fee = U256::from(blobs * DATA_GAS_PER_BLOB) * host.block().blob_basefee;
        let fee = U256::from(gas_used) * (gas_price - base_fee) + blob_fee;
        host.state_mut().account(&BSC_SYSTEM_ADDRESS)?.add_balance(fee);
        Ok(result)
    }
}

/// Returns the BSC transaction registry for `spec`.
///
/// Legacy transactions are always supported, EIP-2930 from Berlin, EIP-1559 from London,
/// EIP-4844 from Cancun and EIP-7702 from Prague. System transactions
/// ([`is_bsc_system_transaction`](crate::is_bsc_system_transaction)) are applied by the Parlia
/// engine and must not be executed through this registry.
pub fn bsc_tx_registry(spec: BscHardfork) -> TxRegistry<BscEvmTypes, TxResult<BscEvmTypes>> {
    type T = BscEvmTypes;
    type H = BscHandlerHooks;
    let spec = spec.into_eth_spec();
    let mut registry = TxRegistry::new().with_handler(
        0,
        TxEnvelope::as_legacy,
        handler(legacy::prepare_with_hooks::<T, H>, legacy::execute_prepared::<T, H>),
    );
    if spec.enables(SpecId::BERLIN) {
        registry.register(
            1,
            TxEnvelope::as_eip2930,
            handler(eip2930::prepare_with_hooks::<T, H>, eip2930::execute_prepared::<T, H>),
        );
    }
    if spec.enables(SpecId::LONDON) {
        registry.register(
            2,
            TxEnvelope::as_eip1559,
            handler(eip1559::prepare_with_hooks::<T, H>, eip1559::execute_prepared::<T, H>),
        );
    }
    if spec.enables(SpecId::CANCUN) {
        registry.register(
            3,
            TxEnvelope::as_eip4844,
            handler(eip4844::prepare_with_hooks::<T, H>, eip4844::execute_prepared::<T, H>),
        );
    }
    if spec.enables(SpecId::PRAGUE) {
        registry.register(
            4,
            TxEnvelope::as_eip7702,
            handler(eip7702::prepare_with_hooks::<T, H>, eip7702::execute_prepared::<T, H>),
        );
    }
    registry
}
