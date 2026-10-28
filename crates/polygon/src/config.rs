//! Polygon evm2 type family, opcode configuration and runtime selection.

use crate::{PolygonHardfork, instructions, polygon_version};
use evm2::{
    Evm, EvmConfig, EvmConfigSelector, EvmTypesHost, ExecutionConfig, OpcodeConfig, SpecId,
    Version, ethereum::TxEnvelope, interpreter::op,
};

/// evm2 type family used by Polygon execution.
#[derive(Clone, Copy, Debug)]
pub struct PolygonEvmTypes;

impl EvmTypesHost for PolygonEvmTypes {
    type ConfigSelector = PolygonConfigSelector;
    type SpecId = PolygonHardfork;
    type Tx = TxEnvelope;
    type EvmExt = ();
    type MessageExt = ();
    type MessageResultExt = ();
    type TxEnvExt = ();
    type TxResultExt = ();
    type BlockEnvExt = ();
    type Host<'a> = Evm<'a, Self>;
}

/// Polygon EVM instance.
pub type PolygonEvm<'a> = Evm<'a, PolygonEvmTypes>;

/// Polygon block environment.
pub type PolygonBlockEnv = evm2::env::BlockEnv<PolygonEvmTypes>;

/// Polygon opcode configuration over an inherited Ethereum specification.
///
/// `POLYGON_SPEC` is the [`PolygonHardfork`] discriminant whose overlays apply; `u32::MAX`
/// selects the plain base table.
#[derive(Clone, Copy, Debug)]
pub struct PolygonConfig<const BASE_SPEC_ID: u32, const POLYGON_SPEC: u32>(());

impl<const BASE_SPEC_ID: u32, const POLYGON_SPEC: u32> EvmConfig<PolygonEvmTypes>
    for PolygonConfig<BASE_SPEC_ID, POLYGON_SPEC>
{
    const BASE_SPEC_ID: SpecId =
        SpecId::try_from_u32(BASE_SPEC_ID).expect("invalid Polygon base spec id");
    const OPCODE_CONFIG: &'static OpcodeConfig<PolygonEvmTypes> =
        &polygon_opcode_config::<BASE_SPEC_ID, POLYGON_SPEC>();
}

/// EIP-7939 `CLZ` static gas.
const CLZ_GAS: u16 = 5;

/// Returns Polygon's opcode configuration for a Polygon hardfork over an inherited specification.
pub const fn polygon_opcode_config<const BASE_SPEC_ID: u32, const POLYGON_SPEC: u32>()
-> OpcodeConfig<PolygonEvmTypes> {
    let mut config = OpcodeConfig::base::<PolygonConfig<BASE_SPEC_ID, POLYGON_SPEC>>();
    if POLYGON_SPEC > u8::MAX as u32 {
        return config;
    }
    let Some(spec) = PolygonHardfork::try_from_u8(POLYGON_SPEC as u8) else {
        return config;
    };

    if spec.enables(PolygonHardfork::Lisovo) {
        config.set_instruction::<evm2::interpreter::instructions::clz<PolygonEvmTypes>>(
            op::CLZ,
            CLZ_GAS,
        );
    }
    if spec.enables(PolygonHardfork::Chicago) {
        let static_gas = config.static_gas(op::SLOAD);
        config.set_instruction::<instructions::pip88_sload>(op::SLOAD, static_gas);
    }
    config
}

/// Selects Polygon's opcode table for the active Polygon hardfork.
#[derive(Clone, Copy, Debug)]
pub struct PolygonConfigSelector;

impl EvmConfigSelector<PolygonEvmTypes> for PolygonConfigSelector {
    type Config<const BASE_SPEC_ID: u32, const CUSTOM_SPEC_ID: u32> =
        PolygonConfig<BASE_SPEC_ID, CUSTOM_SPEC_ID>;

    fn execution_config(spec_id: PolygonHardfork) -> ExecutionConfig<PolygonEvmTypes> {
        const PRAGUE: u32 = SpecId::PRAGUE as u32;
        const LISOVO: u32 = PolygonHardfork::Lisovo as u32;
        const CHICAGO: u32 = PolygonHardfork::Chicago as u32;
        // Only Lisovo and Chicago change the opcode table; later forks reuse their table.
        let config = if spec_id.enables(PolygonHardfork::Chicago) {
            ExecutionConfig::for_config::<PolygonConfig<PRAGUE, CHICAGO>>()
        } else if spec_id.enables(PolygonHardfork::Lisovo) {
            ExecutionConfig::for_config::<PolygonConfig<PRAGUE, LISOVO>>()
        } else {
            let base = spec_id.into_eth_spec();
            evm2::spec_to_generic!(base, |SPEC_ID| ExecutionConfig::for_config::<
                PolygonConfig<SPEC_ID, { u32::MAX }>,
            >())
        };
        config.with_version(polygon_version(spec_id, 1))
    }
}

/// Builds the evm2 execution config for a Polygon hardfork with dynamic runtime version data.
///
/// `version` is usually [`polygon_version`], adjusted by the caller (for example with test-only
/// [`evm2::EvmFeatures`] removed).
pub fn polygon_execution_config(
    spec: PolygonHardfork,
    version: Version,
) -> ExecutionConfig<PolygonEvmTypes> {
    ExecutionConfig::for_spec_and_version(spec, version)
}
