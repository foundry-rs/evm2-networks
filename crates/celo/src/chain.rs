//! Celo chains, hardfork schedules and system contract addresses.

use alloy_primitives::{Address, address};
use op_evm2::OpSpecId;

/// Celo mainnet chain ID.
pub const CELO_MAINNET_CHAIN_ID: u64 = 42220;

/// Celo Sepolia chain ID.
pub const CELO_SEPOLIA_CHAIN_ID: u64 = 11142220;

/// Timestamp of the first Celo L2 block on mainnet (`cel2_time`).
pub const CELO_MAINNET_L2_TIMESTAMP: u64 = 1742957258;

/// The CELO token (`GoldToken`), the only allowed caller of the transfer precompile.
pub const CELO_TOKEN_ADDRESS: Address = address!("0x471EcE3750Da237f93B8E339c536989b8978a438");

/// The `FeeHandler` contract, which receives the base fee.
pub const CELO_FEE_HANDLER_ADDRESS: Address =
    address!("0xcD437749E43A154C07F3553504c68fBfD56B8778");

/// Celo mainnet `FeeCurrencyDirectory`.
pub const CELO_MAINNET_FEE_CURRENCY_DIRECTORY: Address =
    address!("0x15F344b9E6c3Cb6F0376A36A64928b13F62C6276");

/// Celo Sepolia `FeeCurrencyDirectory`.
pub const CELO_SEPOLIA_FEE_CURRENCY_DIRECTORY: Address =
    address!("0x9212Fb72ae65367A7c887eC4Ad9bE310BAC611BF");

/// Maximum deployed contract code size (64 KiB). The initcode limit is twice this.
pub const CELO_MAX_CODE_SIZE: usize = 0x10000;

/// Returns the `FeeCurrencyDirectory` address of `chain_id`.
///
/// Unknown chains use the mainnet address, like celo-revm.
pub const fn fee_currency_directory(chain_id: u64) -> Address {
    match chain_id {
        CELO_SEPOLIA_CHAIN_ID => CELO_SEPOLIA_FEE_CURRENCY_DIRECTORY,
        _ => CELO_MAINNET_FEE_CURRENCY_DIRECTORY,
    }
}

/// Returns the OP hardfork active on a Celo L2 chain at `timestamp`.
///
/// Returns `None` for unknown chains and for mainnet blocks before the L2 migration, which ran
/// different execution rules.
pub const fn celo_spec(chain_id: u64, timestamp: u64) -> Option<OpSpecId> {
    let (l2, isthmus, jovian) = match chain_id {
        CELO_MAINNET_CHAIN_ID => (CELO_MAINNET_L2_TIMESTAMP, 1752073200, 1774958788),
        CELO_SEPOLIA_CHAIN_ID => (0, 0, 1773749037),
        _ => return None,
    };
    if timestamp < l2 {
        return None;
    }
    Some(if timestamp >= jovian {
        OpSpecId::JOVIAN
    } else if timestamp >= isthmus {
        // Holocene and Isthmus activated together.
        OpSpecId::ISTHMUS
    } else {
        OpSpecId::GRANITE
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn schedule() {
        let mainnet = |timestamp| celo_spec(CELO_MAINNET_CHAIN_ID, timestamp);
        assert_eq!(mainnet(CELO_MAINNET_L2_TIMESTAMP - 1), None);
        assert_eq!(mainnet(CELO_MAINNET_L2_TIMESTAMP), Some(OpSpecId::GRANITE));
        assert_eq!(mainnet(1752073199), Some(OpSpecId::GRANITE));
        assert_eq!(mainnet(1752073200), Some(OpSpecId::ISTHMUS));
        assert_eq!(mainnet(1774958787), Some(OpSpecId::ISTHMUS));
        assert_eq!(mainnet(1774958788), Some(OpSpecId::JOVIAN));

        let sepolia = |timestamp| celo_spec(CELO_SEPOLIA_CHAIN_ID, timestamp);
        assert_eq!(sepolia(0), Some(OpSpecId::ISTHMUS));
        assert_eq!(sepolia(1773749036), Some(OpSpecId::ISTHMUS));
        assert_eq!(sepolia(1773749037), Some(OpSpecId::JOVIAN));

        assert_eq!(celo_spec(10, 1774958788), None);
    }

    #[test]
    fn directory() {
        assert_eq!(
            fee_currency_directory(CELO_SEPOLIA_CHAIN_ID),
            CELO_SEPOLIA_FEE_CURRENCY_DIRECTORY
        );
        assert_eq!(
            fee_currency_directory(CELO_MAINNET_CHAIN_ID),
            CELO_MAINNET_FEE_CURRENCY_DIRECTORY
        );
        assert_eq!(fee_currency_directory(1), CELO_MAINNET_FEE_CURRENCY_DIRECTORY);
    }
}
