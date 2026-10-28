//! ArbOS versions, Arbitrum Nitro's hardfork identifiers.
//!
//! Nitro gates every protocol change on the ArbOS version stored in the ArbOS state and recorded in
//! each block header (see [`ArbHeaderInfo`](crate::ArbHeaderInfo)), rather than on block numbers
//! or timestamps. The Ethereum forks map onto ArbOS versions as in Nitro's `params/config.go`.

use core::{error::Error, fmt, str::FromStr};
use evm2::SpecId;

/// ArbOS version.
///
/// Variants are the versions Nitro defines an upgrade for (`ArbosState.UpgradeArbosVersion`),
/// and their discriminant is the version number, so a higher discriminant is a later version. Nitro
/// also reserves the versions in between (12 to 19, 21 to 29, 33 to 39, 42 to 49 and 52 to 58) as
/// upgrades without changes, which no chain runs; they are not represented.
#[repr(u8)]
#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq, PartialOrd, Ord, Default)]
pub enum ArbOsVersion {
    /// Initial Nitro rules.
    V1 = 1,
    /// Poster fees go to the L1 pricer funds pool instead of the coinbase.
    V2 = 2,
    /// `GASPRICE` returns the price actually paid.
    V3 = 3,
    /// L1 pricing changes.
    V4 = 4,
    /// The infrastructure fee account receives part of the base fee.
    V5 = 5,
    /// Address aliasing fix (Arbitrum One genesis).
    V6 = 6,
    /// L1 pricing changes.
    V7 = 7,
    /// L1 pricing changes.
    V8 = 8,
    /// Collects tips, the only version doing so before 60.
    V9 = 9,
    /// Poster fees are added to the L1 fees available.
    V10 = 10,
    /// Ethereum Shanghai.
    V11 = 11,
    /// Ethereum Cancun (Atlas), without the KZG precompile.
    V20 = 20,
    /// Stylus (Bianca): the Cancun precompiles, including KZG, and RIP-7212 P256.
    V30 = 30,
    /// Stylus fixes.
    V31 = 31,
    /// Stylus charging fixes.
    V32 = 32,
    /// Ethereum Prague (Callisto), with the Cancun precompile set.
    V40 = 40,
    /// Native token owners.
    V41 = 41,
    /// Ethereum Osaka (Dia): the Osaka precompiles, a per-transaction gas limit and single-gas
    /// pricing constraints.
    V50 = 50,
    /// Pricing constraint fixes.
    V51 = 51,
    /// Stylus activation gas.
    V59 = 59,
    /// Configurable tip collection and multi-gas pricing constraints.
    V60 = 60,
    /// Multi-gas refund fix.
    #[default]
    V61 = 61,
}

impl ArbOsVersion {
    /// All ArbOS versions in order.
    pub const ALL: [Self; 22] = [
        Self::V1,
        Self::V2,
        Self::V3,
        Self::V4,
        Self::V5,
        Self::V6,
        Self::V7,
        Self::V8,
        Self::V9,
        Self::V10,
        Self::V11,
        Self::V20,
        Self::V30,
        Self::V31,
        Self::V32,
        Self::V40,
        Self::V41,
        Self::V50,
        Self::V51,
        Self::V59,
        Self::V60,
        Self::V61,
    ];

    /// Returns `true` if `version` is active when `self` is the current version.
    pub const fn enables(self, version: Self) -> bool {
        self as u8 >= version as u8
    }

    /// Returns the Ethereum [`SpecId`] this version builds on.
    ///
    /// Nitro enables the Merge rules (`PREVRANDAO`) from the first ArbOS version.
    pub const fn into_eth_spec(self) -> SpecId {
        if self.enables(Self::V50) {
            SpecId::OSAKA
        } else if self.enables(Self::V40) {
            SpecId::PRAGUE
        } else if self.enables(Self::V20) {
            SpecId::CANCUN
        } else if self.enables(Self::V11) {
            SpecId::SHANGHAI
        } else {
            SpecId::MERGE
        }
    }
}

impl From<ArbOsVersion> for SpecId {
    fn from(version: ArbOsVersion) -> Self {
        version.into_eth_spec()
    }
}

impl From<ArbOsVersion> for u64 {
    fn from(version: ArbOsVersion) -> Self {
        version as Self
    }
}

impl TryFrom<u64> for ArbOsVersion {
    type Error = InvalidArbOsVersion;

    fn try_from(version: u64) -> Result<Self, Self::Error> {
        Self::ALL.into_iter().find(|v| *v as u64 == version).ok_or(InvalidArbOsVersion)
    }
}

impl fmt::Display for ArbOsVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ArbOS {}", *self as u8)
    }
}

/// Error returned for a number or name that is not an ArbOS version.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InvalidArbOsVersion;

impl fmt::Display for InvalidArbOsVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("invalid ArbOS version")
    }
}

impl Error for InvalidArbOsVersion {}

impl FromStr for ArbOsVersion {
    type Err = InvalidArbOsVersion;

    /// Parses a version number with an optional `ArbOS` prefix, ignoring ASCII case and a `_`, `-`
    /// or space separator (`61`, `arbos61`, `ArbOS 61` and `arbos-61` are equivalent).
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let number = match s.get(..5) {
            Some(prefix) if prefix.eq_ignore_ascii_case("arbos") => {
                let rest = &s[5..];
                rest.strip_prefix(['_', '-', ' ']).unwrap_or(rest)
            }
            _ => s,
        };
        if number.is_empty() || !number.bytes().all(|b| b.is_ascii_digit()) {
            return Err(InvalidArbOsVersion);
        }
        number.parse::<u64>().map_err(|_| InvalidArbOsVersion)?.try_into()
    }
}
