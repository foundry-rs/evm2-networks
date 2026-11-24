//! Arc EVM factory.

use crate::{
    ArcEvm, ArcEvmTypes, ArcPrecompiles, ArcSpecId, arc_precompiles, arc_tx_registry, arc_version,
};
use evm2::{
    Evm, ExecutionConfig, TxResult, Version, env::BlockEnv, evm::DynDatabase, registry::TxRegistry,
};

/// Factory for Arc evm2 instances, following the naming of reth's evm2 `EvmFactory` trait.
#[derive(Clone, Copy, Debug, Default)]
pub struct ArcEvmFactory;

impl ArcEvmFactory {
    /// Returns the runtime version of `spec` on `chain_id`.
    pub const fn version(&self, spec: ArcSpecId, chain_id: u64) -> Version {
        arc_version(spec, chain_id)
    }

    /// Returns the execution config of `spec` with the runtime `version`.
    pub fn execution_config(
        &self,
        spec: ArcSpecId,
        version: Version,
    ) -> ExecutionConfig<ArcEvmTypes> {
        ExecutionConfig::for_spec_and_version(spec, version)
    }

    /// Returns the transaction registry of `spec`.
    pub fn tx_registry(&self, spec: ArcSpecId) -> TxRegistry<ArcEvmTypes, TxResult<ArcEvmTypes>> {
        arc_tx_registry(spec)
    }

    /// Returns the precompiles of `spec`.
    pub fn precompiles(&self, spec: ArcSpecId) -> ArcPrecompiles {
        arc_precompiles(spec)
    }

    /// Installs the precompiles of the EVM's active spec; call it after the spec changes.
    pub fn configure_evm(&self, evm: &mut ArcEvm<'_>) {
        let spec = evm.config_spec_id();
        evm.set_precompiles(self.precompiles(spec));
    }

    /// Creates an Arc EVM for `spec`, a runtime version, a block environment and a database.
    pub fn create_evm<'a>(
        &self,
        spec: ArcSpecId,
        version: Version,
        block: BlockEnv<ArcEvmTypes>,
        db: impl DynDatabase + 'a,
    ) -> ArcEvm<'a> {
        Evm::new_with_execution_config_and_ext(
            self.execution_config(spec, version),
            spec,
            block,
            self.tx_registry(spec),
            db,
            self.precompiles(spec),
            (),
        )
    }
}
