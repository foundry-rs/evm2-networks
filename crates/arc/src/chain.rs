//! Arc chains, system addresses and hardfork schedules, from arc-node's `arc-execution-config`.

use crate::{ArcHardfork, ArcSpecId};
use alloy_primitives::{Address, address};
use evm2::SpecId;

/// Arc mainnet chain ID.
pub const ARC_MAINNET_CHAIN_ID: u64 = 5_042;

/// Arc testnet chain ID.
pub const ARC_TESTNET_CHAIN_ID: u64 = 5_042_002;

/// `NativeCoinAuthority` precompile: native USDC mint, burn, transfer and total supply.
pub const NATIVE_COIN_AUTHORITY_ADDRESS: Address =
    address!("0x1800000000000000000000000000000000000000");

/// `NativeCoinControl` precompile: the native USDC blocklist.
pub const NATIVE_COIN_CONTROL_ADDRESS: Address =
    address!("0x1800000000000000000000000000000000000001");

/// `SystemAccounting` precompile: per-block gas values for the base fee.
pub const SYSTEM_ACCOUNTING_ADDRESS: Address =
    address!("0x1800000000000000000000000000000000000002");

/// `CallFrom` subcall precompile, from Zero7.
pub const CALL_FROM_ADDRESS: Address = address!("0x1800000000000000000000000000000000000003");

/// Post-quantum signature verification precompile (SLH-DSA-SHA2-128s).
pub const PQ_ADDRESS: Address = address!("0x1800000000000000000000000000000000000004");

/// USDC ERC-20 contract, the only caller allowed to move native USDC through the precompiles.
pub const NATIVE_FIAT_TOKEN_ADDRESS: Address =
    address!("0x3600000000000000000000000000000000000000");

/// `Memo` contract, allowed to use `CallFrom`.
pub const MEMO_ADDRESS: Address = address!("0x5294E9927c3306DcBaDb03fe70b92e01cCede505");

/// `Multicall3From` contract, allowed to use `CallFrom`.
pub const MULTICALL3_FROM_ADDRESS: Address = address!("0x522fAf9A91c41c443c66765030741e4AaCe147D0");

/// Arc's own precompiles, which arc-node resolves lazily and leaves cold at transaction start.
pub const ARC_PRECOMPILE_ADDRESSES: [Address; 5] = [
    NATIVE_COIN_AUTHORITY_ADDRESS,
    NATIVE_COIN_CONTROL_ADDRESS,
    SYSTEM_ACCOUNTING_ADDRESS,
    CALL_FROM_ADDRESS,
    PQ_ADDRESS,
];

/// Returns whether `chain_id` is a known Arc chain.
pub const fn is_arc_chain(chain_id: u64) -> bool {
    matches!(chain_id, ARC_MAINNET_CHAIN_ID | ARC_TESTNET_CHAIN_ID)
}

/// Fork activation condition; a block activation also records its block's timestamp.
#[derive(Clone, Copy, Debug)]
enum Activation {
    Block(u64, u64),
    Timestamp(u64),
}

impl Activation {
    const fn is_active(self, block: Option<u64>, timestamp: u64) -> bool {
        match (self, block) {
            (Self::Block(at, _), Some(block)) => block >= at,
            (Self::Block(_, at), None) | (Self::Timestamp(at), _) => timestamp >= at,
        }
    }
}

/// Arc hardforks and Osaka activation of a chain; Prague is active from genesis.
struct Schedule {
    osaka: Activation,
    hardforks: [(ArcHardfork, Activation); 6],
}

const MAINNET: Schedule = Schedule {
    osaka: Activation::Timestamp(0),
    hardforks: [
        (ArcHardfork::Zero3, Activation::Block(0, 0)),
        (ArcHardfork::Zero4, Activation::Block(0, 0)),
        (ArcHardfork::Zero5, Activation::Block(0, 0)),
        (ArcHardfork::Zero6, Activation::Block(0, 0)),
        (ArcHardfork::Zero7, Activation::Timestamp(1_789_052_400)),
        (ArcHardfork::Zero8, Activation::Timestamp(1_789_052_400)),
    ],
};

const TESTNET: Schedule = Schedule {
    osaka: Activation::Timestamp(1_779_890_400),
    hardforks: [
        (ArcHardfork::Zero3, Activation::Block(11_172_019, 1_763_149_896)),
        (ArcHardfork::Zero4, Activation::Block(26_148_086, 1_770_651_921)),
        (ArcHardfork::Zero5, Activation::Timestamp(1_779_894_517)),
        (ArcHardfork::Zero6, Activation::Timestamp(1_779_894_517)),
        (ArcHardfork::Zero7, Activation::Timestamp(1_781_791_200)),
        (ArcHardfork::Zero8, Activation::Timestamp(1_788_447_600)),
    ],
};

/// Returns the spec of a known Arc chain at a block, or `None` for another chain.
pub fn arc_spec_at(chain_id: u64, block: u64, timestamp: u64) -> Option<ArcSpecId> {
    spec_at(chain_id, Some(block), timestamp)
}

/// Like [`arc_spec_at`] from a timestamp; only testnet block 11172018 then reads as Zero3.
pub fn arc_spec_at_timestamp(chain_id: u64, timestamp: u64) -> Option<ArcSpecId> {
    spec_at(chain_id, None, timestamp)
}

fn spec_at(chain_id: u64, block: Option<u64>, timestamp: u64) -> Option<ArcSpecId> {
    let schedule = match chain_id {
        ARC_MAINNET_CHAIN_ID => &MAINNET,
        ARC_TESTNET_CHAIN_ID => &TESTNET,
        _ => return None,
    };
    let hardfork = schedule
        .hardforks
        .iter()
        .filter(|(_, activation)| activation.is_active(block, timestamp))
        .map(|(hardfork, _)| *hardfork)
        .max();
    let eth =
        if schedule.osaka.is_active(block, timestamp) { SpecId::OSAKA } else { SpecId::PRAGUE };
    Some(ArcSpecId::new(hardfork, eth))
}
