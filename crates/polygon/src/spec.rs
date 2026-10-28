//! Polygon PoS hardfork identifiers.
//!
//! Activation blocks are taken from Bor's `params.BorMainnetChainConfig` and
//! `params.AmoyChainConfig`.

use core::{fmt, str::FromStr};
use evm2::SpecId;

/// Polygon PoS mainnet chain ID.
pub const POLYGON_MAINNET_CHAIN_ID: u64 = 137;

/// Polygon Amoy testnet chain ID.
pub const POLYGON_AMOY_CHAIN_ID: u64 = 80002;

/// Polygon PoS hardfork identifier.
///
/// Variants are the Polygon activation points in activation order, including the Ethereum forks
/// Polygon adopted by block number. A lower discriminant is an earlier hardfork. Forks without an
/// execution change (base fee, consensus or header changes) are kept so that every Bor fork name
/// resolves.
#[repr(u8)]
#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq, PartialOrd, Ord, Default)]
pub enum PolygonHardfork {
    /// Genesis rules of Polygon mainnet.
    Petersburg = 0,
    /// Ethereum Istanbul.
    Istanbul,
    /// Ethereum Berlin.
    Berlin,
    /// Ethereum London (EIP-1559).
    Jaipur,
    /// Base fee and sprint changes.
    Delhi,
    /// State-sync confirmation delay.
    Indore,
    /// Ethereum Shanghai.
    Shanghai,
    /// Ethereum Cancun, with the RIP-7212 P256 precompile and without KZG.
    Cancun,
    /// 32 KiB maximum contract code size.
    Ahmedabad,
    /// Ethereum Prague, with the RIP-7212 P256 precompile and without KZG.
    Bhilai,
    /// Configured block coinbase.
    Rio,
    /// EIP-7825 transaction gas cap, Osaka modexp and KZG; drops P256.
    Madhugiri,
    /// Restores the RIP-7212 P256 precompile.
    MadhugiriPro,
    /// Base fee target change.
    Dandeli,
    /// CLZ opcode and EIP-7951 P256 pricing.
    Lisovo,
    /// Drops the KZG precompile.
    LisovoPro,
    /// Header base fee parameters.
    Giugliano,
    /// PIP-88 cold storage and precompile repricing.
    Chicago,
    /// Header transaction dependency change.
    Valencia,
    /// Header extra data change.
    #[default]
    Austin,
}

impl PolygonHardfork {
    /// All Polygon hardforks in activation order.
    pub const ALL: [Self; 20] = [
        Self::Petersburg,
        Self::Istanbul,
        Self::Berlin,
        Self::Jaipur,
        Self::Delhi,
        Self::Indore,
        Self::Shanghai,
        Self::Cancun,
        Self::Ahmedabad,
        Self::Bhilai,
        Self::Rio,
        Self::Madhugiri,
        Self::MadhugiriPro,
        Self::Dandeli,
        Self::Lisovo,
        Self::LisovoPro,
        Self::Giugliano,
        Self::Chicago,
        Self::Valencia,
        Self::Austin,
    ];

    /// Returns the Ethereum [`SpecId`] this hardfork builds on.
    pub const fn into_eth_spec(self) -> SpecId {
        match self {
            Self::Petersburg => SpecId::PETERSBURG,
            Self::Istanbul => SpecId::ISTANBUL,
            Self::Berlin => SpecId::BERLIN,
            Self::Jaipur | Self::Delhi | Self::Indore => SpecId::LONDON,
            Self::Shanghai => SpecId::SHANGHAI,
            Self::Cancun | Self::Ahmedabad => SpecId::CANCUN,
            Self::Bhilai
            | Self::Rio
            | Self::Madhugiri
            | Self::MadhugiriPro
            | Self::Dandeli
            | Self::Lisovo
            | Self::LisovoPro
            | Self::Giugliano
            | Self::Chicago
            | Self::Valencia
            | Self::Austin => SpecId::PRAGUE,
        }
    }

    /// Returns the first Polygon hardfork running on Ethereum `spec`.
    ///
    /// Specs Polygon skipped map to the first hardfork on the latest earlier spec it adopted (for
    /// example Merge to Jaipur), specs before Petersburg map to Petersburg, and specs after Prague,
    /// which Polygon never adopted, map to the latest hardfork.
    pub fn from_eth_spec(spec: SpecId) -> Self {
        if spec > SpecId::PRAGUE {
            return Self::ALL[Self::ALL.len() - 1];
        }
        let base = Self::ALL
            .into_iter()
            .rev()
            .map(Self::into_eth_spec)
            .find(|base| *base <= spec)
            .unwrap_or(SpecId::PETERSBURG);
        Self::ALL.into_iter().find(|fork| fork.into_eth_spec() == base).unwrap_or(Self::Petersburg)
    }

    /// Returns `true` if `fork` is active when `self` is the current hardfork.
    pub const fn enables(self, fork: Self) -> bool {
        self as u8 >= fork as u8
    }

    /// Returns the hardfork for a raw discriminant.
    pub const fn try_from_u8(value: u8) -> Option<Self> {
        if (value as usize) < Self::ALL.len() { Some(Self::ALL[value as usize]) } else { None }
    }

    /// Returns the activation block of `self` on `chain_id`, or `None` for unknown chains.
    pub const fn activation_block(self, chain_id: u64) -> Option<u64> {
        match chain_id {
            POLYGON_MAINNET_CHAIN_ID => Some(self.mainnet_activation_block()),
            POLYGON_AMOY_CHAIN_ID => Some(self.amoy_activation_block()),
            _ => None,
        }
    }

    /// Returns the hardfork active at `block` on `chain_id`, or `None` for unknown chains.
    pub const fn from_chain_and_block(chain_id: u64, block: u64) -> Option<Self> {
        if !matches!(chain_id, POLYGON_MAINNET_CHAIN_ID | POLYGON_AMOY_CHAIN_ID) {
            return None;
        }
        let mut i = Self::ALL.len();
        while i > 0 {
            i -= 1;
            let fork = Self::ALL[i];
            if let Some(activation) = fork.activation_block(chain_id)
                && activation <= block
            {
                return Some(fork);
            }
        }
        None
    }

    /// Activation block on Polygon mainnet.
    const fn mainnet_activation_block(self) -> u64 {
        match self {
            Self::Petersburg => 0,
            Self::Istanbul => 3_395_000,
            Self::Berlin => 14_750_000,
            Self::Jaipur => 23_850_000,
            Self::Delhi => 38_189_056,
            Self::Indore => 44_934_656,
            Self::Shanghai => 50_523_000,
            Self::Cancun => 54_876_000,
            Self::Ahmedabad => 62_278_656,
            Self::Bhilai => 73_440_256,
            Self::Rio => 77_414_656,
            Self::Madhugiri | Self::MadhugiriPro => 80_084_800,
            Self::Dandeli => 81_424_000,
            Self::Lisovo | Self::LisovoPro => 83_756_500,
            Self::Giugliano => 85_268_500,
            Self::Chicago => 87_218_600,
            Self::Valencia => 89_531_000,
            Self::Austin => 91_949_700,
        }
    }

    /// Activation block on Amoy.
    const fn amoy_activation_block(self) -> u64 {
        match self {
            Self::Petersburg | Self::Istanbul | Self::Berlin => 0,
            Self::Jaipur | Self::Delhi | Self::Indore | Self::Shanghai => 73_100,
            Self::Cancun => 5_423_600,
            Self::Ahmedabad => 11_865_856,
            Self::Bhilai => 22_765_056,
            Self::Rio => 26_272_256,
            Self::Madhugiri => 28_899_616,
            Self::MadhugiriPro => 29_287_400,
            Self::Dandeli => 31_890_000,
            Self::Lisovo => 33_634_700,
            Self::LisovoPro => 34_062_000,
            Self::Giugliano => 35_573_500,
            Self::Chicago => 38_358_000,
            Self::Valencia => 40_776_000,
            Self::Austin => 44_120_000,
        }
    }

    /// Returns the hardfork name.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Petersburg => name::PETERSBURG,
            Self::Istanbul => name::ISTANBUL,
            Self::Berlin => name::BERLIN,
            Self::Jaipur => name::JAIPUR,
            Self::Delhi => name::DELHI,
            Self::Indore => name::INDORE,
            Self::Shanghai => name::SHANGHAI,
            Self::Cancun => name::CANCUN,
            Self::Ahmedabad => name::AHMEDABAD,
            Self::Bhilai => name::BHILAI,
            Self::Rio => name::RIO,
            Self::Madhugiri => name::MADHUGIRI,
            Self::MadhugiriPro => name::MADHUGIRI_PRO,
            Self::Dandeli => name::DANDELI,
            Self::Lisovo => name::LISOVO,
            Self::LisovoPro => name::LISOVO_PRO,
            Self::Giugliano => name::GIUGLIANO,
            Self::Chicago => name::CHICAGO,
            Self::Valencia => name::VALENCIA,
            Self::Austin => name::AUSTIN,
        }
    }
}

impl From<PolygonHardfork> for SpecId {
    fn from(spec: PolygonHardfork) -> Self {
        spec.into_eth_spec()
    }
}

/// Error returned when parsing an unknown Polygon hardfork name.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UnknownPolygonHardfork;

impl fmt::Display for UnknownPolygonHardfork {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("unknown Polygon hardfork")
    }
}

impl core::error::Error for UnknownPolygonHardfork {}

impl FromStr for PolygonHardfork {
    type Err = UnknownPolygonHardfork;

    /// Parses a hardfork name, ignoring ASCII case, `_` and `-` (`madhugiri-pro`, `MADHUGIRI_PRO`
    /// and `MadhugiriPro` are equivalent).
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let normalized =
            s.bytes().filter(|b| !matches!(b, b'_' | b'-')).map(|b| b.to_ascii_lowercase());
        Self::ALL
            .into_iter()
            .find(|fork| {
                fork.as_str().bytes().map(|b| b.to_ascii_lowercase()).eq(normalized.clone())
            })
            .ok_or(UnknownPolygonHardfork)
    }
}

impl From<PolygonHardfork> for &'static str {
    fn from(spec: PolygonHardfork) -> Self {
        spec.as_str()
    }
}

impl fmt::Display for PolygonHardfork {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// String identifiers for Polygon hardforks.
pub mod name {
    /// Petersburg.
    pub const PETERSBURG: &str = "Petersburg";
    /// Istanbul.
    pub const ISTANBUL: &str = "Istanbul";
    /// Berlin.
    pub const BERLIN: &str = "Berlin";
    /// Jaipur.
    pub const JAIPUR: &str = "Jaipur";
    /// Delhi.
    pub const DELHI: &str = "Delhi";
    /// Indore.
    pub const INDORE: &str = "Indore";
    /// Shanghai.
    pub const SHANGHAI: &str = "Shanghai";
    /// Cancun.
    pub const CANCUN: &str = "Cancun";
    /// Ahmedabad.
    pub const AHMEDABAD: &str = "Ahmedabad";
    /// Bhilai.
    pub const BHILAI: &str = "Bhilai";
    /// Rio.
    pub const RIO: &str = "Rio";
    /// Madhugiri.
    pub const MADHUGIRI: &str = "Madhugiri";
    /// MadhugiriPro.
    pub const MADHUGIRI_PRO: &str = "MadhugiriPro";
    /// Dandeli.
    pub const DANDELI: &str = "Dandeli";
    /// Lisovo.
    pub const LISOVO: &str = "Lisovo";
    /// LisovoPro.
    pub const LISOVO_PRO: &str = "LisovoPro";
    /// Giugliano.
    pub const GIUGLIANO: &str = "Giugliano";
    /// Chicago.
    pub const CHICAGO: &str = "Chicago";
    /// Valencia.
    pub const VALENCIA: &str = "Valencia";
    /// Austin.
    pub const AUSTIN: &str = "Austin";
}

#[cfg(test)]
mod tests {
    use super::*;
    use PolygonHardfork::*;

    #[test]
    fn activation_order_is_monotonic() {
        for chain in [POLYGON_MAINNET_CHAIN_ID, POLYGON_AMOY_CHAIN_ID] {
            for pair in PolygonHardfork::ALL.windows(2) {
                let (earlier, later) = (pair[0], pair[1]);
                assert!(
                    earlier.activation_block(chain) <= later.activation_block(chain),
                    "chain {chain}: {earlier} activates after {later}"
                );
            }
        }
    }

    #[test]
    fn fork_boundaries() {
        // (chain, first block of the fork, fork active at that block, fork active one block
        // earlier), from Bor's chain configs. Coinciding forks resolve to the later one.
        let cases = [
            (POLYGON_MAINNET_CHAIN_ID, 23_850_000, Jaipur, Berlin),
            (POLYGON_MAINNET_CHAIN_ID, 54_876_000, Cancun, Shanghai),
            (POLYGON_MAINNET_CHAIN_ID, 62_278_656, Ahmedabad, Cancun),
            (POLYGON_MAINNET_CHAIN_ID, 73_440_256, Bhilai, Ahmedabad),
            (POLYGON_MAINNET_CHAIN_ID, 80_084_800, MadhugiriPro, Rio),
            (POLYGON_MAINNET_CHAIN_ID, 83_756_500, LisovoPro, Dandeli),
            (POLYGON_MAINNET_CHAIN_ID, 87_218_600, Chicago, Giugliano),
            (POLYGON_MAINNET_CHAIN_ID, 91_949_700, Austin, Valencia),
            (POLYGON_AMOY_CHAIN_ID, 73_100, Shanghai, Berlin),
            (POLYGON_AMOY_CHAIN_ID, 28_899_616, Madhugiri, Rio),
            (POLYGON_AMOY_CHAIN_ID, 29_287_400, MadhugiriPro, Madhugiri),
            (POLYGON_AMOY_CHAIN_ID, 33_634_700, Lisovo, Dandeli),
            (POLYGON_AMOY_CHAIN_ID, 34_062_000, LisovoPro, Lisovo),
            (POLYGON_AMOY_CHAIN_ID, 38_358_000, Chicago, Giugliano),
        ];
        for (chain, block, at, before) in cases {
            assert_eq!(PolygonHardfork::from_chain_and_block(chain, block - 1), Some(before));
            assert_eq!(PolygonHardfork::from_chain_and_block(chain, block), Some(at));
            assert_eq!(PolygonHardfork::from_chain_and_block(chain, block + 1), Some(at));
        }
        assert_eq!(
            PolygonHardfork::from_chain_and_block(POLYGON_MAINNET_CHAIN_ID, 0),
            Some(Petersburg)
        );
        assert_eq!(PolygonHardfork::from_chain_and_block(POLYGON_AMOY_CHAIN_ID, 0), Some(Berlin));
        assert_eq!(PolygonHardfork::from_chain_and_block(1, 90_000_000), None);
    }

    #[test]
    fn eth_spec_mapping() {
        assert_eq!(Indore.into_eth_spec(), SpecId::LONDON);
        assert_eq!(Ahmedabad.into_eth_spec(), SpecId::CANCUN);
        assert_eq!(Bhilai.into_eth_spec(), SpecId::PRAGUE);
        // Bor never adopted Osaka.
        assert!(PolygonHardfork::ALL.iter().all(|fork| fork.into_eth_spec() <= SpecId::PRAGUE));
    }

    #[test]
    fn from_eth_spec() {
        for (spec, fork) in [
            (SpecId::FRONTIER, Petersburg),
            (SpecId::PETERSBURG, Petersburg),
            (SpecId::ISTANBUL, Istanbul),
            (SpecId::BERLIN, Berlin),
            (SpecId::LONDON, Jaipur),
            (SpecId::MERGE, Jaipur),
            (SpecId::SHANGHAI, Shanghai),
            (SpecId::CANCUN, Cancun),
            (SpecId::PRAGUE, Bhilai),
            (SpecId::OSAKA, Austin),
            (SpecId::AMSTERDAM, Austin),
        ] {
            assert_eq!(PolygonHardfork::from_eth_spec(spec), fork, "{spec:?}");
        }
    }

    #[test]
    fn names_round_trip() {
        for fork in PolygonHardfork::ALL {
            assert_eq!(fork.to_string().parse::<PolygonHardfork>(), Ok(fork));
            assert_eq!(PolygonHardfork::try_from_u8(fork as u8), Some(fork));
        }
        assert_eq!("madhugiripro".parse::<PolygonHardfork>(), Ok(MadhugiriPro));
        assert_eq!("madhugiri-pro".parse::<PolygonHardfork>(), Ok(MadhugiriPro));
        assert_eq!("MADHUGIRI_PRO".parse::<PolygonHardfork>(), Ok(MadhugiriPro));
        assert_eq!("lisovo_pro".parse::<PolygonHardfork>(), Ok(LisovoPro));
        assert!("madhugiri pro".parse::<PolygonHardfork>().is_err());
        assert!("madhugir".parse::<PolygonHardfork>().is_err());
        assert!("madhugiriprox".parse::<PolygonHardfork>().is_err());
        assert!("Hampi".parse::<PolygonHardfork>().is_err());
        assert_eq!(PolygonHardfork::try_from_u8(PolygonHardfork::ALL.len() as u8), None);
        assert_eq!(PolygonHardfork::default(), Austin);
    }
}
