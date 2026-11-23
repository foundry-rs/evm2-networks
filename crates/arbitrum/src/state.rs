//! ArbOS state storage.
//!
//! Port of the storage layout of Nitro's `arbos/storage`, `arbos/arbosState`, `arbos/l1pricing`,
//! `arbos/l2pricing`, `arbos/blockhash` and `arbos/features`. ArbOS keeps its state in the storage
//! of [`ARBOS_STATE_ADDRESS`], split into subspaces whose slots are hashed from the subspace key,
//! so it can be read from (and written to) any database holding the chain state, including a fork.

use crate::ARBOS_STATE_ADDRESS;
use alloy_primitives::{B256, U256, b256, keccak256};
use evm2::{DatabaseError, evm::State};

/// Root ArbOS state offsets (`arbosState` `Offset`s).
pub mod root {
    /// Network fee account.
    pub const NETWORK_FEE_ACCOUNT: u64 = 3;
    /// Infrastructure fee account.
    pub const INFRA_FEE_ACCOUNT: u64 = 6;
    /// Whether tips are collected, from ArbOS 60.
    pub const COLLECT_TIPS: u64 = 11;
}

/// L1 pricing state offsets (`l1pricing`).
pub mod l1_pricing {
    /// L1 pricer reward recipient.
    pub const PAY_REWARDS_TO: u64 = 0;
    /// Equilibration units.
    pub const EQUILIBRATION_UNITS: u64 = 1;
    /// Price inertia.
    pub const INERTIA: u64 = 2;
    /// Reward per unit.
    pub const PER_UNIT_REWARD: u64 = 3;
    /// Last update time.
    pub const LAST_UPDATE_TIME: u64 = 4;
    /// Funds due for rewards (signed).
    pub const FUNDS_DUE_FOR_REWARDS: u64 = 5;
    /// Calldata units since the last update.
    pub const UNITS_SINCE_UPDATE: u64 = 6;
    /// Price per calldata unit, the L1 base fee estimate.
    pub const PRICE_PER_UNIT: u64 = 7;
    /// Last surplus (signed).
    pub const LAST_SURPLUS: u64 = 8;
    /// Per-batch gas cost (signed 64-bit).
    pub const PER_BATCH_GAS_COST: u64 = 9;
    /// Amortized cost cap in basis points.
    pub const AMORTIZED_COST_CAP_BIPS: u64 = 10;
    /// L1 fees available.
    pub const L1_FEES_AVAILABLE: u64 = 11;
}

/// L2 pricing state offsets (`l2pricing`).
pub mod l2_pricing {
    /// Speed limit per second.
    pub const SPEED_LIMIT_PER_SECOND: u64 = 0;
    /// Per-block gas limit (the transaction gas cap before ArbOS 50).
    pub const PER_BLOCK_GAS_LIMIT: u64 = 1;
    /// Minimum L2 base fee.
    pub const MIN_BASE_FEE_WEI: u64 = 3;
    /// Legacy gas backlog.
    pub const GAS_BACKLOG: u64 = 4;
    /// Pricing inertia.
    pub const PRICING_INERTIA: u64 = 5;
    /// Backlog tolerance.
    pub const BACKLOG_TOLERANCE: u64 = 6;
    /// Per-transaction gas limit, from ArbOS 50.
    pub const PER_TX_GAS_LIMIT: u64 = 7;
    /// Backlog offset inside a single-gas constraint.
    pub const CONSTRAINT_BACKLOG: u64 = 2;
}

/// A subspace of the ArbOS state storage (Nitro's `storage.Storage`).
///
/// A sub-storage vector (Nitro's `SubStorageVector`) holds its length at offset 0 and element `i`
/// in the sub-storage opened with the big-endian bytes of `i`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ArbOsStorage {
    /// Subspace key. The root subspace has an empty key.
    key: Option<B256>,
}

impl ArbOsStorage {
    /// Root ArbOS state storage.
    pub const ROOT: Self = Self { key: None };
    /// L1 pricing state, root sub-storage 0.
    pub const L1_PRICING: Self = Self {
        key: Some(b256!("0xbc36789e7a1e281436464229828f817d6612f7b477d66591ff96a9e064bcc98a")),
    };
    /// L2 pricing state, root sub-storage 1.
    pub const L2_PRICING: Self = Self {
        key: Some(b256!("0x5fe7f977e71dba2ea1a68e21057beebb9be2ac30c6410aa38d4f3fbe41dcffd2")),
    };
    /// L1 block hashes, root sub-storage 6. Offset 0 holds the current L1 block number, and offset
    /// `1 + n % 256` the hash of L1 block `n`.
    pub const BLOCKHASHES: Self = Self {
        key: Some(b256!("0xd0591206d9e81e07f4defc5327957173572bcd1bca7838caa7be39b0c12b1873")),
    };
    /// Feature flags, root sub-storage 9.
    pub const FEATURES: Self = Self {
        key: Some(b256!("0xb2e7b7a21d986ae84d62a7de4a916f006c4e42a596358b93bad65492d174c4ff")),
    };
    /// Single-gas pricing constraints vector, L2 pricing sub-storage 0.
    pub const GAS_CONSTRAINTS: Self = Self {
        key: Some(b256!("0xe563d40b231228af482edea6196e0e623fb6719911608473439733a7b9120985")),
    };
    /// Multi-gas pricing constraints vector, L2 pricing sub-storage 1.
    pub const MULTI_GAS_CONSTRAINTS: Self = Self {
        key: Some(b256!("0xcb36b5455e39ced9308c27b7ff5e6ebe7d5c4e6e2d3277226ec1b5b8abe1848e")),
    };

    /// Opens the sub-storage with `id`.
    pub fn open(&self, id: &[u8]) -> Self {
        let parent = self.key.as_ref().map_or(&[][..], |key| key.as_slice());
        Self { key: Some(keccak256([parent, id].concat())) }
    }

    /// Returns the storage slot of `offset`.
    ///
    /// Nitro hashes the subspace key with the first 31 bytes of the offset and keeps its last byte,
    /// so 256 consecutive offsets share a hash.
    pub fn slot(&self, offset: u64) -> U256 {
        let parent = self.key.as_ref().map_or(&[][..], |key| key.as_slice());
        let offset = U256::from(offset).to_be_bytes::<32>();
        let mut slot = keccak256([parent, &offset[..31]].concat());
        slot[31] = offset[31];
        slot.into()
    }

    /// Reads the value at `offset` without loading it into the transaction overlay.
    pub fn get(&self, state: &mut State<'_>, offset: u64) -> Result<U256, DatabaseError> {
        state.storage_slot_untracked(&ARBOS_STATE_ADDRESS, &self.slot(offset))
    }

    /// Writes `value` at `offset` as a journaled change.
    pub fn set(
        &self,
        state: &mut State<'_>,
        offset: u64,
        value: U256,
    ) -> Result<(), DatabaseError> {
        state.storage_slot(&ARBOS_STATE_ADDRESS, self.slot(offset))?.set(value);
        Ok(())
    }
}
