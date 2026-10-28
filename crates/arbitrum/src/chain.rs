//! Arbitrum chains, system addresses and header metadata.
//!
//! Addresses are taken from Nitro's `core/types/arbitrum_signer.go` and `arbos/l1pricing`, and the
//! header layout from `core/types/arb_types.go`.

use crate::{ArbOsVersion, InvalidArbOsVersion};
use alloy_primitives::{Address, B256, address};
use core::ops::Range;

/// Arbitrum One chain ID.
pub const ARBITRUM_ONE_CHAIN_ID: u64 = 42_161;

/// Arbitrum Nova chain ID.
pub const ARBITRUM_NOVA_CHAIN_ID: u64 = 42_170;

/// Arbitrum Sepolia chain ID.
pub const ARBITRUM_SEPOLIA_CHAIN_ID: u64 = 421_614;

/// Robinhood Chain mainnet chain ID (an Arbitrum Orbit chain).
pub const ROBINHOOD_MAINNET_CHAIN_ID: u64 = 4_663;

/// Robinhood Chain testnet chain ID (an Arbitrum Orbit chain).
pub const ROBINHOOD_TESTNET_CHAIN_ID: u64 = 46_630;

/// Account holding the ArbOS state in its storage.
pub const ARBOS_STATE_ADDRESS: Address = address!("0xA4B05FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF");

/// ArbOS system address, the sender of internal transactions.
pub const ARBOS_ADDRESS: Address = address!("0x00000000000000000000000000000000000a4b05");

/// Batch poster address, the block coinbase of sequenced (non-delayed-inbox) messages.
///
/// Only transactions in blocks with this coinbase pay the L1 poster fee, and tips are never
/// collected in blocks with another coinbase.
pub const BATCH_POSTER_ADDRESS: Address = address!("0xA4B000000000000000000073657175656e636572");

/// Pool receiving the L1 poster fee from ArbOS 2.
pub const L1_PRICER_FUNDS_POOL_ADDRESS: Address =
    address!("0xA4B00000000000000000000000000000000000f6");

/// Returns whether `chain_id` is a known Arbitrum Nitro chain.
///
/// Covers Arbitrum One, Nova and Sepolia, and the Robinhood Chain Orbit chains. Other Orbit chains
/// run the same rules but are not recognized by ID.
pub const fn is_arbitrum_chain(chain_id: u64) -> bool {
    matches!(
        chain_id,
        ARBITRUM_ONE_CHAIN_ID
            | ARBITRUM_NOVA_CHAIN_ID
            | ARBITRUM_SEPOLIA_CHAIN_ID
            | ROBINHOOD_MAINNET_CHAIN_ID
            | ROBINHOOD_TESTNET_CHAIN_ID
    )
}

/// Arbitrum Nitro block header metadata, packed into the header's `mixHash`.
///
/// Port of the execution fields of Nitro's `types.HeaderInfo`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct ArbHeaderInfo {
    /// L1 block number returned by the `NUMBER` opcode.
    pub l1_block_number: u64,
    /// ArbOS version the block was executed with.
    pub arbos_version: ArbOsVersion,
}

impl ArbHeaderInfo {
    /// Decodes the metadata of a Nitro header from its `mixHash`.
    ///
    /// The caller must only use this for Nitro blocks: Nitro headers have a difficulty of `1` and
    /// a 32-byte `extraData`.
    pub fn from_mix_hash(mix_hash: B256) -> Result<Self, InvalidArbOsVersion> {
        let word =
            |range: Range<usize>| u64::from_be_bytes(mix_hash[range].try_into().expect("8 bytes"));
        Ok(Self { l1_block_number: word(8..16), arbos_version: word(16..24).try_into()? })
    }
}
