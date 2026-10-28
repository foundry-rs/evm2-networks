//! BSC hardforks.
//!
//! Activation points come from bsc's `params/config.go` (`BSCChainConfig` and
//! `ChapelChainConfig`). Forks up to HertzFix activate by block number, later forks by timestamp.

use core::{fmt, str::FromStr};
use evm2::SpecId;

/// BSC mainnet chain ID.
pub const BSC_MAINNET_CHAIN_ID: u64 = 56;

/// BSC testnet (Chapel) chain ID.
pub const BSC_TESTNET_CHAIN_ID: u64 = 97;

/// Activation condition of a BSC hardfork.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BscForkCondition {
    /// Active from this block number.
    Block(u64),
    /// Active from this block timestamp.
    Timestamp(u64),
}

impl BscForkCondition {
    /// Returns `true` if the condition holds for a block with `number` and `timestamp`.
    pub const fn is_active_at(self, number: u64, timestamp: u64) -> bool {
        match self {
            Self::Block(block) => number >= block,
            Self::Timestamp(time) => timestamp >= time,
        }
    }
}

/// BSC hardforks, in activation order on mainnet.
///
/// Jenner (CAS20 native tokens and the BEP-706 millisecond timestamp precompile) is not
/// supported, so [`Self::Pasteur`] is the latest hardfork.
#[repr(u8)]
#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq, PartialOrd, Ord, Default)]
pub enum BscHardfork {
    /// Genesis rules: Istanbul (with Muir Glacier).
    Istanbul,
    /// Parlia consensus.
    Ramanujan,
    /// Consensus-only.
    Niels,
    /// Consensus-only.
    MirrorSync,
    /// Consensus-only.
    Bruno,
    /// Consensus-only.
    Euler,
    /// Deprecates the light-client precompiles `0x64` and `0x65`.
    Nano,
    /// Restores `0x64` and `0x65`.
    Moran,
    /// Consensus-only.
    Gibbs,
    /// Updates `0x65`.
    Planck,
    /// Adds BLS signature verification (`0x66`) and CometBFT light block validation (`0x67`).
    Luban,
    /// Updates `0x65`.
    Plato,
    /// Berlin.
    Berlin,
    /// London.
    London,
    /// Updates `0x67`.
    Hertz,
    /// Consensus-only.
    HertzFix,
    /// Shanghai.
    Shanghai,
    /// Consensus-only.
    Kepler,
    /// Adds double-sign evidence verification (`0x68`) and Tendermint secp256k1 recovery
    /// (`0x69`).
    Feynman,
    /// Consensus-only.
    FeynmanFix,
    /// Cancun.
    Cancun,
    /// Adds RIP-7212 P256 verification (`0x100`).
    Haber,
    /// Consensus-only.
    HaberFix,
    /// Consensus-only.
    Bohr,
    /// Pascal, activated with Prague.
    Pascal,
    /// Prague.
    Prague,
    /// Consensus-only.
    Lorentz,
    /// Consensus-only.
    Maxwell,
    /// Consensus-only.
    Fermi,
    /// Osaka.
    Osaka,
    /// Consensus-only (blob base fee).
    Mendel,
    /// Deprecates `0x64` and `0x65` again and updates `0x67`.
    #[default]
    Pasteur,
}

impl BscHardfork {
    /// All hardforks in activation order.
    pub const ALL: [Self; 32] = [
        Self::Istanbul,
        Self::Ramanujan,
        Self::Niels,
        Self::MirrorSync,
        Self::Bruno,
        Self::Euler,
        Self::Nano,
        Self::Moran,
        Self::Gibbs,
        Self::Planck,
        Self::Luban,
        Self::Plato,
        Self::Berlin,
        Self::London,
        Self::Hertz,
        Self::HertzFix,
        Self::Shanghai,
        Self::Kepler,
        Self::Feynman,
        Self::FeynmanFix,
        Self::Cancun,
        Self::Haber,
        Self::HaberFix,
        Self::Bohr,
        Self::Pascal,
        Self::Prague,
        Self::Lorentz,
        Self::Maxwell,
        Self::Fermi,
        Self::Osaka,
        Self::Mendel,
        Self::Pasteur,
    ];

    /// Returns the Ethereum [`SpecId`] this hardfork builds on.
    pub const fn into_eth_spec(self) -> SpecId {
        match self {
            Self::Istanbul
            | Self::Ramanujan
            | Self::Niels
            | Self::MirrorSync
            | Self::Bruno
            | Self::Euler
            | Self::Nano
            | Self::Moran
            | Self::Gibbs
            | Self::Planck
            | Self::Luban
            | Self::Plato => SpecId::ISTANBUL,
            Self::Berlin => SpecId::BERLIN,
            Self::London | Self::Hertz | Self::HertzFix => SpecId::LONDON,
            Self::Shanghai | Self::Kepler | Self::Feynman | Self::FeynmanFix => SpecId::SHANGHAI,
            Self::Cancun | Self::Haber | Self::HaberFix | Self::Bohr => SpecId::CANCUN,
            Self::Pascal | Self::Prague | Self::Lorentz | Self::Maxwell | Self::Fermi => {
                SpecId::PRAGUE
            }
            Self::Osaka | Self::Mendel | Self::Pasteur => SpecId::OSAKA,
        }
    }

    /// Returns the first BSC hardfork running on Ethereum `spec`.
    ///
    /// Specs BSC skipped map to the first hardfork on the latest earlier spec it adopted (for
    /// example Merge to London), specs before Istanbul map to Istanbul, and specs after Osaka map
    /// to the latest hardfork.
    pub fn from_eth_spec(spec: SpecId) -> Self {
        if spec > SpecId::OSAKA {
            return Self::ALL[Self::ALL.len() - 1];
        }
        let base = Self::ALL
            .into_iter()
            .rev()
            .map(Self::into_eth_spec)
            .find(|base| *base <= spec)
            .unwrap_or(SpecId::ISTANBUL);
        Self::ALL.into_iter().find(|fork| fork.into_eth_spec() == base).unwrap_or(Self::Istanbul)
    }

    /// Returns `true` if `fork` is active when `self` is the current hardfork.
    pub const fn enables(self, fork: Self) -> bool {
        self as u8 >= fork as u8
    }

    /// Returns the hardfork for a raw discriminant.
    pub const fn try_from_u8(value: u8) -> Option<Self> {
        if (value as usize) < Self::ALL.len() { Some(Self::ALL[value as usize]) } else { None }
    }

    /// Returns the activation condition of `self` on `chain_id`, or `None` for unknown chains.
    pub const fn activation(self, chain_id: u64) -> Option<BscForkCondition> {
        match chain_id {
            BSC_MAINNET_CHAIN_ID => Some(self.mainnet_activation()),
            BSC_TESTNET_CHAIN_ID => Some(self.testnet_activation()),
            _ => None,
        }
    }

    /// Returns the hardfork active for a block with `number` and `timestamp` on `chain_id`, or
    /// `None` for unknown chains.
    ///
    /// This is the latest hardfork whose predecessors are all active. Chapel activated Gibbs
    /// before Nano, so a Chapel block between the two resolves to Euler; both are
    /// consensus-only, so execution is unaffected.
    pub const fn from_chain_block_and_timestamp(
        chain_id: u64,
        number: u64,
        timestamp: u64,
    ) -> Option<Self> {
        if !matches!(chain_id, BSC_MAINNET_CHAIN_ID | BSC_TESTNET_CHAIN_ID) {
            return None;
        }
        let mut active = Self::Istanbul;
        let mut i = 0;
        while i < Self::ALL.len() {
            let fork = Self::ALL[i];
            let Some(condition) = fork.activation(chain_id) else { return None };
            if !condition.is_active_at(number, timestamp) {
                break;
            }
            active = fork;
            i += 1;
        }
        Some(active)
    }

    const fn mainnet_activation(self) -> BscForkCondition {
        use BscForkCondition::{Block, Timestamp};
        match self {
            Self::Istanbul | Self::Ramanujan | Self::Niels => Block(0),
            Self::MirrorSync => Block(5_184_000),
            Self::Bruno => Block(13_082_000),
            Self::Euler => Block(18_907_621),
            Self::Nano => Block(21_962_149),
            Self::Moran => Block(22_107_423),
            Self::Gibbs => Block(23_846_001),
            Self::Planck => Block(27_281_024),
            Self::Luban => Block(29_020_050),
            Self::Plato => Block(30_720_096),
            Self::Berlin | Self::London | Self::Hertz => Block(31_302_048),
            Self::HertzFix => Block(34_140_700),
            Self::Shanghai | Self::Kepler => Timestamp(1_705_996_800),
            Self::Feynman | Self::FeynmanFix => Timestamp(1_713_419_340),
            Self::Cancun | Self::Haber => Timestamp(1_718_863_500),
            Self::HaberFix => Timestamp(1_727_316_120),
            Self::Bohr => Timestamp(1_727_317_200),
            Self::Pascal | Self::Prague => Timestamp(1_742_436_600),
            Self::Lorentz => Timestamp(1_745_903_100),
            Self::Maxwell => Timestamp(1_751_250_600),
            Self::Fermi => Timestamp(1_768_357_800),
            Self::Osaka | Self::Mendel => Timestamp(1_777_343_400),
            Self::Pasteur => Timestamp(1_787_625_000),
        }
    }

    const fn testnet_activation(self) -> BscForkCondition {
        use BscForkCondition::{Block, Timestamp};
        match self {
            Self::Istanbul => Block(0),
            Self::Ramanujan => Block(1_010_000),
            Self::Niels => Block(1_014_369),
            Self::MirrorSync => Block(5_582_500),
            Self::Bruno => Block(13_837_000),
            Self::Euler => Block(19_203_503),
            Self::Nano => Block(23_482_428),
            Self::Moran => Block(23_603_940),
            Self::Gibbs => Block(22_800_220),
            Self::Planck => Block(28_196_022),
            Self::Luban => Block(29_295_050),
            Self::Plato => Block(29_861_024),
            Self::Berlin | Self::London | Self::Hertz => Block(31_103_030),
            Self::HertzFix => Block(35_682_300),
            Self::Shanghai | Self::Kepler => Timestamp(1_702_972_800),
            Self::Feynman => Timestamp(1_710_136_800),
            Self::FeynmanFix => Timestamp(1_711_342_800),
            Self::Cancun => Timestamp(1_713_330_442),
            Self::Haber => Timestamp(1_716_962_820),
            Self::HaberFix => Timestamp(1_719_986_788),
            Self::Bohr => Timestamp(1_724_116_996),
            Self::Pascal | Self::Prague => Timestamp(1_740_452_880),
            Self::Lorentz => Timestamp(1_744_097_580),
            Self::Maxwell => Timestamp(1_748_243_100),
            Self::Fermi => Timestamp(1_762_741_500),
            Self::Osaka | Self::Mendel => Timestamp(1_774_319_400),
            Self::Pasteur => Timestamp(1_784_601_000),
        }
    }

    /// Returns the hardfork name.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Istanbul => "Istanbul",
            Self::Ramanujan => "Ramanujan",
            Self::Niels => "Niels",
            Self::MirrorSync => "MirrorSync",
            Self::Bruno => "Bruno",
            Self::Euler => "Euler",
            Self::Nano => "Nano",
            Self::Moran => "Moran",
            Self::Gibbs => "Gibbs",
            Self::Planck => "Planck",
            Self::Luban => "Luban",
            Self::Plato => "Plato",
            Self::Berlin => "Berlin",
            Self::London => "London",
            Self::Hertz => "Hertz",
            Self::HertzFix => "HertzFix",
            Self::Shanghai => "Shanghai",
            Self::Kepler => "Kepler",
            Self::Feynman => "Feynman",
            Self::FeynmanFix => "FeynmanFix",
            Self::Cancun => "Cancun",
            Self::Haber => "Haber",
            Self::HaberFix => "HaberFix",
            Self::Bohr => "Bohr",
            Self::Pascal => "Pascal",
            Self::Prague => "Prague",
            Self::Lorentz => "Lorentz",
            Self::Maxwell => "Maxwell",
            Self::Fermi => "Fermi",
            Self::Osaka => "Osaka",
            Self::Mendel => "Mendel",
            Self::Pasteur => "Pasteur",
        }
    }
}

impl From<BscHardfork> for SpecId {
    fn from(spec: BscHardfork) -> Self {
        spec.into_eth_spec()
    }
}

/// Error returned when parsing an unknown BSC hardfork name.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UnknownBscHardfork;

impl fmt::Display for UnknownBscHardfork {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("unknown BSC hardfork")
    }
}

impl core::error::Error for UnknownBscHardfork {}

impl FromStr for BscHardfork {
    type Err = UnknownBscHardfork;

    /// Parses a hardfork name, ignoring ASCII case, `_` and `-` (`haber-fix`, `HABER_FIX` and
    /// `HaberFix` are equivalent).
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let normalized =
            s.bytes().filter(|b| !matches!(b, b'_' | b'-')).map(|b| b.to_ascii_lowercase());
        Self::ALL
            .into_iter()
            .find(|fork| {
                fork.as_str().bytes().map(|b| b.to_ascii_lowercase()).eq(normalized.clone())
            })
            .ok_or(UnknownBscHardfork)
    }
}

impl From<BscHardfork> for &'static str {
    fn from(spec: BscHardfork) -> Self {
        spec.as_str()
    }
}

impl fmt::Display for BscHardfork {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use BscHardfork::*;

    #[test]
    fn mainnet_boundaries() {
        let fork = |number, timestamp| {
            BscHardfork::from_chain_block_and_timestamp(BSC_MAINNET_CHAIN_ID, number, timestamp)
        };
        assert_eq!(fork(0, 0), Some(Niels));
        assert_eq!(fork(21_962_148, 0), Some(Euler));
        assert_eq!(fork(21_962_149, 0), Some(Nano));
        assert_eq!(fork(31_302_047, 0), Some(Plato));
        assert_eq!(fork(31_302_048, 0), Some(Hertz));
        // Timestamp forks also require every block fork before them.
        assert_eq!(fork(34_140_699, 1_800_000_000), Some(Hertz));
        assert_eq!(fork(34_140_700, 1_705_996_799), Some(HertzFix));
        assert_eq!(fork(34_140_700, 1_705_996_800), Some(Kepler));
        assert_eq!(fork(40_000_000, 1_718_863_500), Some(Haber));
        assert_eq!(fork(50_000_000, 1_742_436_600), Some(Prague));
        assert_eq!(fork(90_000_000, 1_777_343_399), Some(Fermi));
        assert_eq!(fork(90_000_000, 1_777_343_400), Some(Mendel));
        assert_eq!(fork(90_000_000, 1_787_624_999), Some(Mendel));
        assert_eq!(fork(90_000_000, 1_787_625_000), Some(Pasteur));
        assert_eq!(BscHardfork::from_chain_block_and_timestamp(1, 90_000_000, u64::MAX), None);
    }

    #[test]
    fn testnet_out_of_order_forks() {
        let fork =
            |number| BscHardfork::from_chain_block_and_timestamp(BSC_TESTNET_CHAIN_ID, number, 0);
        assert_eq!(fork(1_009_999), Some(Istanbul));
        // Gibbs is active but Nano is not yet.
        assert_eq!(fork(22_800_220), Some(Euler));
        assert_eq!(fork(23_482_428), Some(Nano));
        assert_eq!(fork(23_603_940), Some(Gibbs));
        assert_eq!(fork(31_103_030), Some(Hertz));
    }

    #[test]
    fn eth_spec_mapping() {
        assert_eq!(Plato.into_eth_spec(), SpecId::ISTANBUL);
        assert_eq!(Hertz.into_eth_spec(), SpecId::LONDON);
        assert_eq!(Haber.into_eth_spec(), SpecId::CANCUN);
        assert_eq!(Pascal.into_eth_spec(), SpecId::PRAGUE);
        assert_eq!(Pasteur.into_eth_spec(), SpecId::OSAKA);
        for (spec, fork) in [
            (SpecId::FRONTIER, Istanbul),
            (SpecId::ISTANBUL, Istanbul),
            (SpecId::BERLIN, Berlin),
            (SpecId::LONDON, London),
            (SpecId::MERGE, London),
            (SpecId::SHANGHAI, Shanghai),
            (SpecId::CANCUN, Cancun),
            (SpecId::PRAGUE, Pascal),
            (SpecId::OSAKA, Osaka),
            (SpecId::AMSTERDAM, Pasteur),
        ] {
            assert_eq!(BscHardfork::from_eth_spec(spec), fork, "{spec:?}");
        }
    }

    #[test]
    fn names_round_trip() {
        for fork in BscHardfork::ALL {
            assert_eq!(fork.to_string().parse::<BscHardfork>(), Ok(fork));
            assert_eq!(BscHardfork::try_from_u8(fork as u8), Some(fork));
        }
        assert_eq!("haber-fix".parse::<BscHardfork>(), Ok(HaberFix));
        assert_eq!("HERTZ_FIX".parse::<BscHardfork>(), Ok(HertzFix));
        assert!("Jenner".parse::<BscHardfork>().is_err());
        assert!("haber fix".parse::<BscHardfork>().is_err());
        assert_eq!(BscHardfork::default(), Pasteur);
    }
}
