//! Celo EVM factory.

use crate::{
    CeloBlockEnv, CeloEvm, CeloEvmExt, CeloEvmTypes, celo_execution_config, celo_precompiles,
    celo_tx_registry, celo_version,
};
use evm2::{
    Evm, ExecutionConfig, Precompiles, TxResult, Version, evm::DynDatabase, registry::TxRegistry,
};
use op_evm2::OpSpecId;

/// Factory for Celo evm2 instances.
///
/// The inherent methods follow the naming of reth's evm2 `EvmFactory` trait.
#[derive(Clone, Debug, Default)]
pub struct CeloEvmFactory;

impl CeloEvmFactory {
    /// Returns the runtime version for an OP hardfork and Celo chain ID.
    pub const fn version(&self, spec: OpSpecId, chain_id: u64) -> Version {
        celo_version(spec, chain_id)
    }

    /// Returns the execution config for an OP hardfork and runtime version.
    pub fn execution_config(
        &self,
        spec: OpSpecId,
        version: Version,
    ) -> ExecutionConfig<CeloEvmTypes> {
        celo_execution_config(spec, version)
    }

    /// Returns the transaction registry for an OP hardfork.
    pub fn tx_registry(&self, spec: OpSpecId) -> TxRegistry<CeloEvmTypes, TxResult<CeloEvmTypes>> {
        celo_tx_registry(spec)
    }

    /// Returns the precompiles for an OP hardfork.
    pub fn precompiles(&self, spec: OpSpecId) -> Precompiles<CeloEvmTypes> {
        celo_precompiles(spec)
    }

    /// Installs the Celo precompiles for the EVM's active hardfork.
    ///
    /// Call this after the EVM's execution config changes hardfork.
    pub fn configure_evm(&self, evm: &mut CeloEvm<'_>) {
        let spec = evm.config_spec_id();
        evm.set_precompiles(self.precompiles(spec));
    }

    /// Creates a Celo EVM for an OP hardfork, runtime version, block environment and database.
    pub fn create_evm<'a>(
        &self,
        spec: OpSpecId,
        version: Version,
        block: CeloBlockEnv,
        db: impl DynDatabase + 'a,
    ) -> CeloEvm<'a> {
        Evm::new_with_execution_config_and_ext(
            self.execution_config(spec, version),
            spec,
            block,
            self.tx_registry(spec),
            db,
            self.precompiles(spec),
            CeloEvmExt::default(),
        )
    }
}
