//! Polygon EVM factory.

use crate::{
    PolygonBlockEnv, PolygonEvm, PolygonEvmTypes, PolygonHardfork, polygon_execution_config,
    polygon_precompiles, polygon_tx_registry, polygon_version,
};
use evm2::{
    Evm, ExecutionConfig, Precompiles, TxResult, Version, evm::DynDatabase, registry::TxRegistry,
};

/// Factory for Polygon evm2 instances.
///
/// The inherent methods follow the naming of reth's evm2 `EvmFactory` trait.
#[derive(Clone, Debug, Default)]
pub struct PolygonEvmFactory;

impl PolygonEvmFactory {
    /// Returns the runtime version for a Polygon hardfork and chain ID.
    pub const fn version(&self, spec: PolygonHardfork, chain_id: u64) -> Version {
        polygon_version(spec, chain_id)
    }

    /// Returns the execution config for a Polygon hardfork and runtime version.
    pub fn execution_config(
        &self,
        spec: PolygonHardfork,
        version: Version,
    ) -> ExecutionConfig<PolygonEvmTypes> {
        polygon_execution_config(spec, version)
    }

    /// Returns the transaction registry for a Polygon hardfork.
    pub fn tx_registry(
        &self,
        spec: PolygonHardfork,
    ) -> TxRegistry<PolygonEvmTypes, TxResult<PolygonEvmTypes>> {
        polygon_tx_registry(spec)
    }

    /// Returns the precompiles for a Polygon hardfork.
    pub fn precompiles(&self, spec: PolygonHardfork) -> Precompiles<PolygonEvmTypes> {
        polygon_precompiles(spec)
    }

    /// Installs the Polygon precompiles for the EVM's active hardfork.
    ///
    /// Call this after the EVM's execution config changes hardfork.
    pub fn configure_evm(&self, evm: &mut PolygonEvm<'_>) {
        let spec = evm.config_spec_id();
        evm.set_precompiles(self.precompiles(spec));
    }

    /// Creates a Polygon EVM for a hardfork, runtime version, block environment and database.
    pub fn create_evm<'a>(
        &self,
        spec: PolygonHardfork,
        version: Version,
        block: PolygonBlockEnv,
        db: impl DynDatabase + 'a,
    ) -> PolygonEvm<'a> {
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
