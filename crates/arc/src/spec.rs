//! Arc hardforks and the Ethereum specification they run on.

use core::{fmt, str::FromStr};
use evm2::SpecId;

/// Arc hardfork, ordered by activation.
#[repr(u8)]
#[derive(Clone, Copy, Debug, Default, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub enum ArcHardfork {
    /// Arc v0.3.
    Zero3 = 3,
    /// Arc v0.4.
    Zero4 = 4,
    /// Arc v0.5, paired with Ethereum Osaka.
    Zero5 = 5,
    /// Arc v0.6.
    Zero6 = 6,
    /// Arc v0.7: `callFrom`, fail-closed blocklist reads and cold-preserving transfer probes.
    Zero7 = 7,
    /// Arc v0.8: delegatecall penalty, draining to empty and transaction-warm `SELFDESTRUCT`.
    #[default]
    Zero8 = 8,
}

impl ArcHardfork {
    /// All Arc hardforks in activation order.
    pub const ALL: [Self; 6] =
        [Self::Zero3, Self::Zero4, Self::Zero5, Self::Zero6, Self::Zero7, Self::Zero8];

    /// Latest Arc hardfork.
    pub const LATEST: Self = Self::Zero8;

    /// Returns the hardfork name, as arc-node spells it.
    pub const fn name(self) -> &'static str {
        match self {
            Self::Zero3 => "Zero3",
            Self::Zero4 => "Zero4",
            Self::Zero5 => "Zero5",
            Self::Zero6 => "Zero6",
            Self::Zero7 => "Zero7",
            Self::Zero8 => "Zero8",
        }
    }

    /// Returns the Ethereum specification arc-node pairs with this hardfork.
    pub const fn eth_spec(self) -> SpecId {
        match self {
            Self::Zero3 | Self::Zero4 => SpecId::PRAGUE,
            Self::Zero5 | Self::Zero6 | Self::Zero7 | Self::Zero8 => SpecId::OSAKA,
        }
    }
}

impl fmt::Display for ArcHardfork {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// Error returned when parsing an unknown Arc hardfork name.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[error("unknown Arc hardfork: {0}")]
pub struct UnknownArcHardfork(pub String);

impl FromStr for ArcHardfork {
    type Err = UnknownArcHardfork;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::ALL
            .into_iter()
            .find(|hardfork| hardfork.name().eq_ignore_ascii_case(s))
            .ok_or_else(|| UnknownArcHardfork(s.to_owned()))
    }
}

/// evm2 spec id of Arc: the active Arc hardfork and the Ethereum specification it runs on.
#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
pub struct ArcSpecId {
    hardfork: Option<ArcHardfork>,
    eth: SpecId,
}

impl ArcSpecId {
    /// Creates a spec id; `None` is a block before Zero3.
    pub const fn new(hardfork: Option<ArcHardfork>, eth: SpecId) -> Self {
        Self { hardfork, eth }
    }

    /// Returns the latest Arc hardfork active, if any.
    pub const fn hardfork(self) -> Option<ArcHardfork> {
        self.hardfork
    }

    /// Returns the Ethereum specification in effect.
    pub const fn eth_spec(self) -> SpecId {
        self.eth
    }

    /// Returns whether `hardfork` is active.
    pub const fn is_active(self, hardfork: ArcHardfork) -> bool {
        match self.hardfork {
            Some(active) => active as u8 >= hardfork as u8,
            None => false,
        }
    }
}

impl Default for ArcSpecId {
    fn default() -> Self {
        ArcHardfork::LATEST.into()
    }
}

impl From<ArcHardfork> for ArcSpecId {
    fn from(hardfork: ArcHardfork) -> Self {
        Self::new(Some(hardfork), hardfork.eth_spec())
    }
}

impl From<ArcSpecId> for SpecId {
    fn from(spec: ArcSpecId) -> Self {
        spec.eth
    }
}

impl fmt::Display for ArcSpecId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.hardfork {
            Some(hardfork) => write!(f, "{hardfork}"),
            None => write!(f, "{:?}", self.eth),
        }
    }
}

impl FromStr for ArcSpecId {
    type Err = UnknownArcHardfork;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        s.parse::<ArcHardfork>().map(Into::into)
    }
}
