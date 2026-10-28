//! Polygon chain schedules.
//!
//! Port of the `burntContract` and `coinbase` block schedules from Bor's `params/config.go` for
//! Polygon mainnet and Amoy.

use crate::{POLYGON_AMOY_CHAIN_ID, POLYGON_MAINNET_CHAIN_ID};
use alloy_primitives::{Address, address};

/// Mainnet burnt contract schedule: `(first block, contract)`.
const MAINNET_BURNT_CONTRACTS: [(u64, Address); 3] = [
    (23_850_000, address!("0x70bca57f4579f58670ab2d18ef16e02c17553c38")),
    (50_523_000, address!("0x7A8ed27F4C30512326878652d20fC85727401854")),
    (83_756_500, address!("0x3ef57def668054dd750bd260526105c4eeef104f")),
];

/// Amoy burnt contract schedule: `(first block, contract)`.
const AMOY_BURNT_CONTRACTS: [(u64, Address); 2] = [
    (0, address!("0x000000000000000000000000000000000000dEaD")),
    (73_100, address!("0xeCDD77cE6f146cCf5dab707941d318Bd50eeD2C9")),
];

/// Block coinbase from Rio on Polygon mainnet and Amoy.
pub const POLYGON_RIO_COINBASE: Address = address!("0x7Ee41D8A25641000661B1EF5E6AE8A00400466B0");

/// First mainnet block using [`POLYGON_RIO_COINBASE`].
const MAINNET_RIO_COINBASE_BLOCK: u64 = 77_414_656;

/// First Amoy block using [`POLYGON_RIO_COINBASE`].
const AMOY_RIO_COINBASE_BLOCK: u64 = 26_272_256;

/// Returns the contract credited with the burned base fee at `block` on `chain_id`.
///
/// From London, Bor credits `gas_used × base_fee` to this contract instead of burning it. Returns
/// `None` for unknown chains and for blocks before the first scheduled contract, where the base
/// fee is burned as on Ethereum.
pub fn polygon_burnt_contract(chain_id: u64, block: u64) -> Option<Address> {
    let schedule: &[(u64, Address)] = match chain_id {
        POLYGON_MAINNET_CHAIN_ID => &MAINNET_BURNT_CONTRACTS,
        POLYGON_AMOY_CHAIN_ID => &AMOY_BURNT_CONTRACTS,
        _ => return None,
    };
    schedule.iter().rev().find(|(start, _)| *start <= block).map(|(_, contract)| *contract)
}

/// Returns the block coinbase (`COINBASE` and the tip recipient) at `block` on `chain_id`, when it
/// is fixed by the chain configuration.
///
/// From Rio the coinbase is [`POLYGON_RIO_COINBASE`]. Before Rio it is the block signer, which is
/// not part of the header (`miner` is zero) and must be recovered from the seal (`bor_getAuthor`),
/// so this returns `None`. Also returns `None` for unknown chains.
pub const fn polygon_coinbase(chain_id: u64, block: u64) -> Option<Address> {
    let start = match chain_id {
        POLYGON_MAINNET_CHAIN_ID => MAINNET_RIO_COINBASE_BLOCK,
        POLYGON_AMOY_CHAIN_ID => AMOY_RIO_COINBASE_BLOCK,
        _ => return None,
    };
    if block >= start { Some(POLYGON_RIO_COINBASE) } else { None }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn burnt_contract_schedule() {
        assert_eq!(polygon_burnt_contract(137, 23_849_999), None);
        assert_eq!(polygon_burnt_contract(137, 23_850_000), Some(MAINNET_BURNT_CONTRACTS[0].1));
        assert_eq!(polygon_burnt_contract(137, 50_522_999), Some(MAINNET_BURNT_CONTRACTS[0].1));
        assert_eq!(polygon_burnt_contract(137, 50_523_000), Some(MAINNET_BURNT_CONTRACTS[1].1));
        assert_eq!(polygon_burnt_contract(137, 83_756_499), Some(MAINNET_BURNT_CONTRACTS[1].1));
        assert_eq!(polygon_burnt_contract(137, 83_756_500), Some(MAINNET_BURNT_CONTRACTS[2].1));
        assert_eq!(polygon_burnt_contract(80_002, 0), Some(AMOY_BURNT_CONTRACTS[0].1));
        assert_eq!(polygon_burnt_contract(80_002, 73_099), Some(AMOY_BURNT_CONTRACTS[0].1));
        assert_eq!(polygon_burnt_contract(80_002, 73_100), Some(AMOY_BURNT_CONTRACTS[1].1));
        assert_eq!(polygon_burnt_contract(1, 90_000_000), None);
    }

    #[test]
    fn coinbase_schedule() {
        assert_eq!(polygon_coinbase(137, 77_414_655), None);
        assert_eq!(polygon_coinbase(137, 77_414_656), Some(POLYGON_RIO_COINBASE));
        assert_eq!(polygon_coinbase(80_002, 26_272_255), None);
        assert_eq!(polygon_coinbase(80_002, 26_272_256), Some(POLYGON_RIO_COINBASE));
        assert_eq!(polygon_coinbase(1, 90_000_000), None);
    }
}
