//! BSC EVM factory.

use crate::{
    BscBlockEnv, BscEvm, BscEvmTypes, BscHardfork, bsc_execution_config, bsc_precompiles,
    bsc_tx_registry, bsc_version,
};
use evm2::{
    Evm, ExecutionConfig, Precompiles, TxResult, Version, evm::DynDatabase, registry::TxRegistry,
};

/// Factory for BSC evm2 instances.
///
/// The inherent methods follow the naming of reth's evm2 `EvmFactory` trait.
#[derive(Clone, Debug, Default)]
pub struct BscEvmFactory;

impl BscEvmFactory {
    /// Returns the runtime version for a BSC hardfork and chain ID.
    pub const fn version(&self, spec: BscHardfork, chain_id: u64) -> Version {
        bsc_version(spec, chain_id)
    }

    /// Returns the execution config for a BSC hardfork and runtime version.
    pub fn execution_config(
        &self,
        spec: BscHardfork,
        version: Version,
    ) -> ExecutionConfig<BscEvmTypes> {
        bsc_execution_config(spec, version)
    }

    /// Returns the transaction registry for a BSC hardfork.
    pub fn tx_registry(&self, spec: BscHardfork) -> TxRegistry<BscEvmTypes, TxResult<BscEvmTypes>> {
        bsc_tx_registry(spec)
    }

    /// Returns the precompiles for a BSC hardfork.
    pub fn precompiles(&self, spec: BscHardfork) -> Precompiles<BscEvmTypes> {
        bsc_precompiles(spec)
    }

    /// Installs the BSC precompiles for the EVM's active hardfork.
    ///
    /// Call this after the EVM's execution config changes hardfork.
    pub fn configure_evm(&self, evm: &mut BscEvm<'_>) {
        let spec = evm.config_spec_id();
        evm.set_precompiles(self.precompiles(spec));
    }

    /// Creates a BSC EVM for a hardfork, runtime version, block environment and database.
    pub fn create_evm<'a>(
        &self,
        spec: BscHardfork,
        version: Version,
        block: BscBlockEnv,
        db: impl DynDatabase + 'a,
    ) -> BscEvm<'a> {
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
