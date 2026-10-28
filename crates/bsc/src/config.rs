//! BSC evm2 type family, runtime version and configuration selection.

use crate::{BSC_MAINNET_CHAIN_ID, BscHardfork};
use evm2::{
    Evm, EvmConfig, EvmConfigSelector, EvmTypesHost, ExecutionConfig, OpcodeConfig, SpecId,
    Version, ethereum::TxEnvelope,
};

/// Maximum blobs per transaction. BSC keeps Cancun's limit through Prague and Osaka.
pub const BSC_MAX_BLOBS_PER_TX: usize = 6;

/// evm2 type family used by BSC execution.
#[derive(Clone, Copy, Debug)]
pub struct BscEvmTypes;

impl EvmTypesHost for BscEvmTypes {
    type ConfigSelector = BscConfigSelector;
    type SpecId = BscHardfork;
    type Tx = TxEnvelope;
    type EvmExt = ();
    type MessageExt = ();
    type MessageResultExt = ();
    type TxEnvExt = ();
    type TxResultExt = ();
    type BlockEnvExt = ();
    type Host<'a> = Evm<'a, Self>;
}

/// BSC EVM instance.
pub type BscEvm<'a> = Evm<'a, BscEvmTypes>;

/// BSC block environment.
pub type BscBlockEnv = evm2::env::BlockEnv<BscEvmTypes>;

/// BSC opcode configuration: the Ethereum table of the inherited specification.
#[derive(Clone, Copy, Debug)]
pub struct BscConfig<const BASE_SPEC_ID: u32>(());

impl<const BASE_SPEC_ID: u32> EvmConfig<BscEvmTypes> for BscConfig<BASE_SPEC_ID> {
    const BASE_SPEC_ID: SpecId =
        SpecId::try_from_u32(BASE_SPEC_ID).expect("invalid BSC base spec id");
    const OPCODE_CONFIG: &'static OpcodeConfig<BscEvmTypes> =
        &OpcodeConfig::<BscEvmTypes>::base::<Self>();
}

/// Selects the opcode table of the Ethereum specification a BSC hardfork builds on.
#[derive(Clone, Copy, Debug)]
pub struct BscConfigSelector;

impl EvmConfigSelector<BscEvmTypes> for BscConfigSelector {
    type Config<const BASE_SPEC_ID: u32, const CUSTOM_SPEC_ID: u32> = BscConfig<BASE_SPEC_ID>;

    fn execution_config(spec_id: BscHardfork) -> ExecutionConfig<BscEvmTypes> {
        let base = spec_id.into_eth_spec();
        evm2::spec_to_generic!(base, |SPEC_ID| ExecutionConfig::for_config::<BscConfig<SPEC_ID>>())
            .with_version(bsc_version(spec_id, BSC_MAINNET_CHAIN_ID))
    }
}

/// Returns the evm2 runtime version for a BSC hardfork and chain ID.
///
/// BSC uses Ethereum's limits and gas parameters for the inherited spec, except for the blob
/// limit ([`BSC_MAX_BLOBS_PER_TX`]).
pub const fn bsc_version(spec: BscHardfork, chain_id: u64) -> Version {
    let mut version = Version::new(spec.into_eth_spec());
    version.chain_id = chain_id;
    version.max_blobs_per_tx = BSC_MAX_BLOBS_PER_TX;
    version
}

/// Builds the evm2 execution config for a BSC hardfork with dynamic runtime version data.
///
/// `version` is usually [`bsc_version`], adjusted by the caller (for example with test-only
/// [`evm2::EvmFeatures`] removed).
pub fn bsc_execution_config(spec: BscHardfork, version: Version) -> ExecutionConfig<BscEvmTypes> {
    ExecutionConfig::for_spec_and_version(spec, version)
}
