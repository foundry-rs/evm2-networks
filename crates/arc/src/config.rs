//! Arc evm2 type family, opcode configuration and runtime version.

use crate::{ArcSpecId, instructions};
use evm2::{
    Evm, EvmConfig, EvmConfigSelector, EvmFeatures, EvmTypesHost, ExecutionConfig, OpcodeConfig,
    SpecId, Version, ethereum::TxEnvelope, interpreter::op, spec_to_generic,
};

/// evm2 type family used by Arc execution.
#[derive(Clone, Copy, Debug)]
pub struct ArcEvmTypes;

impl EvmTypesHost for ArcEvmTypes {
    type ConfigSelector = ArcConfigSelector;
    type SpecId = ArcSpecId;
    type Tx = TxEnvelope;
    type EvmExt = ();
    type MessageExt = ();
    type MessageResultExt = ();
    type TxEnvExt = ();
    type TxResultExt = ();
    type BlockEnvExt = ();
    type Host<'a> = Evm<'a, Self>;
}

/// Arc EVM instance.
pub type ArcEvm<'a> = Evm<'a, ArcEvmTypes>;

/// Arc opcode configuration over an inherited Ethereum specification.
#[derive(Clone, Copy, Debug)]
pub struct ArcConfig<const BASE_SPEC_ID: u32>(());

impl<const BASE_SPEC_ID: u32> EvmConfig<ArcEvmTypes> for ArcConfig<BASE_SPEC_ID> {
    const BASE_SPEC_ID: SpecId =
        SpecId::try_from_u32(BASE_SPEC_ID).expect("invalid Arc base spec id");
    const OPCODE_CONFIG: &'static OpcodeConfig<ArcEvmTypes> = &arc_opcode_config::<BASE_SPEC_ID>();
}

/// Returns Arc's opcode table, whose value-moving opcodes enforce the native USDC transfer rules.
pub const fn arc_opcode_config<const BASE_SPEC_ID: u32>() -> OpcodeConfig<ArcEvmTypes> {
    let mut config = OpcodeConfig::base::<ArcConfig<BASE_SPEC_ID>>();
    config.set_instruction::<instructions::call>(op::CALL, config.static_gas(op::CALL));
    config
        .set_instruction::<instructions::create<false>>(op::CREATE, config.static_gas(op::CREATE));
    config
        .set_instruction::<instructions::create<true>>(op::CREATE2, config.static_gas(op::CREATE2));
    config.set_instruction::<instructions::ArcSelfDestruct>(
        op::SELFDESTRUCT,
        config.static_gas(op::SELFDESTRUCT),
    );
    config
}

/// Selects the Arc opcode table for the Ethereum specification of an [`ArcSpecId`].
#[derive(Clone, Copy, Debug)]
pub struct ArcConfigSelector;

impl EvmConfigSelector<ArcEvmTypes> for ArcConfigSelector {
    type Config<const BASE_SPEC_ID: u32, const CUSTOM_SPEC_ID: u32> = ArcConfig<BASE_SPEC_ID>;

    fn execution_config(spec_id: ArcSpecId) -> ExecutionConfig<ArcEvmTypes> {
        let base = spec_id.eth_spec();
        spec_to_generic!(base, |SPEC_ID| ExecutionConfig::for_config::<ArcConfig<SPEC_ID>>())
            .with_version(arc_version(spec_id, 1))
    }
}

/// Returns the evm2 runtime version of an Arc spec on `chain_id`, with EIP-7708 transfer logs.
pub const fn arc_version(spec: ArcSpecId, chain_id: u64) -> Version {
    let mut version = Version::new(spec.eth_spec());
    version.chain_id = chain_id;
    version.features.insert(EvmFeatures::EIP7708);
    version
}
