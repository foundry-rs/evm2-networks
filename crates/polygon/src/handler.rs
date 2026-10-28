//! Polygon transaction handlers.
//!
//! Port of the Bor-specific parts of `core/state_transition.go`. Polygon transactions reuse the
//! stock evm2 handlers with [`PolygonHandlerHooks`], which credit the base fee to the burnt
//! contract and emit the fee transfer log.

use crate::{PolygonEvm, PolygonEvmTypes, PolygonHardfork, polygon_burnt_contract};
use alloy_primitives::{Address, B256, Log, LogData, U256, address, b256};
use evm2::{
    EvmFeatures, SpecId, TxResult,
    ethereum::{TxEnvelope, eip1559, eip2930, eip7702, finalize_gas, legacy},
    evm::DynDatabase,
    handler::{GasSettlement, TxHandlerHooks},
    registry::{HandlerResult, TxRegistry, handler},
};

/// Address emitting Bor's transfer logs (the MATIC/POL token contract).
pub const POLYGON_FEE_ADDRESS: Address = address!("0x0000000000000000000000000000000000001010");

/// Topic of Bor's fee transfer log:
/// `LogFeeTransfer(address,address,address,uint256,uint256,uint256,uint256,uint256)`.
pub const POLYGON_FEE_TRANSFER_LOG_TOPIC: B256 =
    b256!("0x4dfe1bbbcf077ddc3e01291eea2d5c70c2b422b415d95645b9adcfd678cb1d63");

/// Topic of Bor's value transfer log:
/// `LogTransfer(address,address,address,uint256,uint256,uint256,uint256,uint256)`.
///
/// Bor emits it for every value transfer between accounts. evm2 has no hook for this yet, so these
/// logs are not emitted.
pub const POLYGON_TRANSFER_LOG_TOPIC: B256 =
    b256!("0xe6497e3ee548a3372136af2fcb0696db31fc6cf20260707645068bd3fe97f3c4");

/// Transaction type of Bor's state-sync transactions (PIP-74), included in blocks from Madhugiri.
///
/// They are system transactions applied by consensus and are not executable through the
/// transaction registry.
pub const POLYGON_STATE_SYNC_TX_TYPE: u8 = 0x7f;

/// Handler hooks for Polygon transactions.
#[derive(Clone, Copy, Debug, Default)]
pub struct PolygonHandlerHooks;

impl TxHandlerHooks<PolygonEvmTypes> for PolygonHandlerHooks {
    /// Port of Bor's fee settlement: refunds unused gas, credits the base fee to the burnt
    /// contract, pays the tip to the coinbase and emits the fee transfer log.
    fn settle_transaction(
        host: &mut PolygonEvm<'_>,
        _envelope: &TxEnvelope,
        gas: GasSettlement<PolygonEvmTypes>,
    ) -> HandlerResult<TxResult<PolygonEvmTypes>> {
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

        // Bor splits the price into the base fee and the tip from London. The base fee is capped
        // by the gas price so the credited amounts never exceed what the sender paid, which only
        // matters when base fee validation is disabled.
        let spec = host.config_spec_id();
        let base_fee = if spec.into_eth_spec().enables(SpecId::LONDON) {
            host.block().basefee.min(gas_price)
        } else {
            U256::ZERO
        };
        let gas_used = U256::from(gas_used);
        let block = host.block().number.saturating_to::<u64>();
        if !base_fee.is_zero()
            && let Some(burnt_contract) = polygon_burnt_contract(host.version().chain_id, block)
        {
            host.state_mut().account(&burnt_contract)?.add_balance(gas_used * base_fee);
        }

        let tip = gas_used * (gas_price - base_fee);
        let beneficiary = host.block().beneficiary;
        host.state_mut().account(&beneficiary)?.add_balance(tip);

        if !tip.is_zero() && host.logs_observed() {
            // Bor reports the balances at the start of the transaction, before buying gas. The
            // transaction's changes are not accepted yet, so the accepted state still holds them.
            let db = host.state_mut().overlay_db_mut();
            let sender_balance = db.get_account(&caller)?.map_or(U256::ZERO, |info| info.balance);
            let coinbase_balance =
                db.get_account(&beneficiary)?.map_or(U256::ZERO, |info| info.balance);
            host.log(fee_transfer_log(caller, beneficiary, tip, sender_balance, coinbase_balance));
        }
        Ok(result)
    }
}

/// Builds Bor's fee transfer log (`AddFeeTransferLog`).
///
/// The data holds `amount`, the sender and coinbase balances before the transaction, and those
/// balances minus and plus `amount`. Bor deprecated the log but still emits it.
fn fee_transfer_log(
    sender: Address,
    coinbase: Address,
    amount: U256,
    sender_balance: U256,
    coinbase_balance: U256,
) -> Log {
    let words = [
        amount,
        sender_balance,
        coinbase_balance,
        sender_balance.saturating_sub(amount),
        coinbase_balance.saturating_add(amount),
    ];
    let data = words.iter().flat_map(|word| word.to_be_bytes::<32>()).collect::<Vec<_>>();
    Log {
        address: POLYGON_FEE_ADDRESS,
        data: LogData::new_unchecked(
            vec![
                POLYGON_FEE_TRANSFER_LOG_TOPIC,
                POLYGON_FEE_ADDRESS.into_word(),
                sender.into_word(),
                coinbase.into_word(),
            ],
            data.into(),
        ),
    }
}

/// Returns the Polygon transaction registry for `spec`.
///
/// Legacy transactions are always supported, EIP-2930 from Berlin, EIP-1559 from London and
/// EIP-7702 from Prague (Bhilai). Bor does not accept EIP-4844 transactions, and state-sync
/// transactions ([`POLYGON_STATE_SYNC_TX_TYPE`]) are applied by consensus.
pub fn polygon_tx_registry(
    spec: PolygonHardfork,
) -> TxRegistry<PolygonEvmTypes, TxResult<PolygonEvmTypes>> {
    type T = PolygonEvmTypes;
    type H = PolygonHandlerHooks;
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
    if spec.enables(SpecId::PRAGUE) {
        registry.register(
            4,
            TxEnvelope::as_eip7702,
            handler(eip7702::prepare_with_hooks::<T, H>, eip7702::execute_prepared::<T, H>),
        );
    }
    registry
}
