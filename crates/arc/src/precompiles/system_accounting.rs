//! `SystemAccounting`: per-block gas values feeding Arc's base fee, kept in a 64-slot ring buffer.

use super::{
    ERR_INVALID_CALLER, check_caller, check_delegatecall, check_static, decode, early_revert,
    input, output, read, split_selector, write,
};
use crate::{ArcEvm, ArcEvmTypes, SYSTEM_ACCOUNTING_ADDRESS};
use alloy_primitives::{U256, keccak256};
use alloy_sol_types::{SolCall, sol};
use evm2::{
    evm::SYSTEM_ADDRESS,
    interpreter::{GasTracker, Message},
    precompiles::PrecompileResult,
};

sol! {
    /// Gas values of a block.
    struct GasValues {
        uint64 gasUsed;
        uint64 gasUsedSmoothed;
        uint64 nextBaseFee;
    }

    /// `SystemAccounting` precompile interface.
    interface ISystemAccounting {
        /// Stores the gas values of `blockNumber`; system caller only.
        function storeGasValues(uint64 blockNumber, GasValues calldata gasValues) external returns (bool);
        /// Returns the ring-buffer slot of `blockNumber`, without a freshness check.
        function getGasValues(uint64 blockNumber) external view returns (GasValues calldata gasValue);
    }
}

/// Solidity mapping slot of the gas values.
const GAS_VALUES_MAPPING_SLOT: u8 = 1;
/// Ring buffer capacity.
const RING_BUFFER_SIZE: u64 = 64;

pub(super) fn run(
    evm: &mut ArcEvm<'_>,
    message: &Message<ArcEvmTypes>,
    gas: &mut GasTracker,
) -> PrecompileResult {
    let input = input(evm, message);
    let (selector, args) = split_selector(&input, gas)?;
    match selector {
        ISystemAccounting::storeGasValuesCall::SELECTOR => {
            check_static(message, gas)?;
            let ISystemAccounting::storeGasValuesCall { blockNumber, gasValues } =
                decode(args, gas)?;
            check_caller(message, gas, SYSTEM_ADDRESS, ERR_INVALID_CALLER)?;
            check_delegatecall(evm, message, gas, SYSTEM_ACCOUNTING_ADDRESS)?;
            write(evm, gas, SYSTEM_ACCOUNTING_ADDRESS, slot(blockNumber), pack(&gasValues))?;
            output(true)
        }
        ISystemAccounting::getGasValuesCall::SELECTOR => {
            let ISystemAccounting::getGasValuesCall { blockNumber } = decode(args, gas)?;
            let packed = read(evm, gas, SYSTEM_ACCOUNTING_ADDRESS, slot(blockNumber))?;
            output(unpack(packed))
        }
        _ => Err(early_revert(gas, "Invalid selector")),
    }
}

/// Returns the storage slot of `block_number` in the ring buffer.
fn slot(block_number: u64) -> U256 {
    let mut preimage = [0u8; 64];
    preimage[24..32].copy_from_slice(&(block_number % RING_BUFFER_SIZE).to_be_bytes());
    preimage[63] = GAS_VALUES_MAPPING_SLOT;
    U256::from_be_bytes(keccak256(preimage).0)
}

/// Packs gas values into one word: next base fee, smoothed gas used, then gas used.
fn pack(values: &GasValues) -> U256 {
    (U256::from(values.nextBaseFee) << 128)
        | (U256::from(values.gasUsedSmoothed) << 64)
        | U256::from(values.gasUsed)
}

/// Unpacks gas values stored by [`pack`].
fn unpack(word: U256) -> GasValues {
    let limb = |index: usize| word.as_limbs()[index];
    GasValues { gasUsed: limb(0), gasUsedSmoothed: limb(1), nextBaseFee: limb(2) }
}
