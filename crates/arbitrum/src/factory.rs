//! Arbitrum EVM factory.

use crate::{
    ArbBlockEnv, ArbEvm, ArbEvmExt, ArbEvmTypes, ArbOsVersion, arbitrum_precompiles,
    arbitrum_tx_registry, arbitrum_version,
};
use evm2::{
    Evm, ExecutionConfig, Precompiles, TxResult, Version, evm::DynDatabase, registry::TxRegistry,
};

/// Factory for Arbitrum evm2 instances.
///
/// The inherent methods follow the naming of reth's evm2 `EvmFactory` trait.
#[derive(Clone, Debug, Default)]
pub struct ArbEvmFactory;

impl ArbEvmFactory {
    /// Returns the runtime version for an ArbOS version and chain ID.
    pub const fn version(&self, spec: ArbOsVersion, chain_id: u64) -> Version {
        arbitrum_version(spec, chain_id)
    }

    /// Returns the execution config for an ArbOS version and runtime version.
    pub fn execution_config(
        &self,
        spec: ArbOsVersion,
        version: Version,
    ) -> ExecutionConfig<ArbEvmTypes> {
        ExecutionConfig::for_spec_and_version(spec, version)
    }

    /// Returns the transaction registry for an ArbOS version.
    pub fn tx_registry(
        &self,
        spec: ArbOsVersion,
    ) -> TxRegistry<ArbEvmTypes, TxResult<ArbEvmTypes>> {
        arbitrum_tx_registry(spec)
    }

    /// Returns the precompiles for an ArbOS version.
    pub fn precompiles(&self, spec: ArbOsVersion) -> Precompiles<ArbEvmTypes> {
        arbitrum_precompiles(spec)
    }

    /// Installs the Arbitrum precompiles for the EVM's active ArbOS version.
    ///
    /// Call this after the EVM's execution config changes ArbOS version.
    pub fn configure_evm(&self, evm: &mut ArbEvm<'_>) {
        let spec = evm.config_spec_id();
        evm.set_precompiles(self.precompiles(spec));
    }

    /// Creates an Arbitrum EVM for an ArbOS version, runtime version, block environment and
    /// database.
    pub fn create_evm<'a>(
        &self,
        spec: ArbOsVersion,
        version: Version,
        block: ArbBlockEnv,
        db: impl DynDatabase + 'a,
    ) -> ArbEvm<'a> {
        Evm::new_with_execution_config_and_ext(
            self.execution_config(spec, version),
            spec,
            block,
            self.tx_registry(spec),
            db,
            self.precompiles(spec),
            ArbEvmExt::default(),
        )
    }
}
