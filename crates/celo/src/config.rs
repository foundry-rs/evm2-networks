//! Celo evm2 type family, runtime version and configuration selection.

use crate::{CELO_MAINNET_CHAIN_ID, CELO_MAX_CODE_SIZE, CeloTxEnvelope, FeeCurrencyContext};
use alloy_primitives::U256;
use evm2::{
    Evm, EvmConfig, EvmConfigSelector, EvmTypesHost, ExecutionConfig, OpcodeConfig, SpecId,
    Version, registry::HandlerError,
};
use op_evm2::{L1BlockInfo, OpSpecId};

/// evm2 type family used by Celo execution.
///
/// Celo L2 runs the OP Stack hardforks ([`OpSpecId`]).
#[derive(Clone, Copy, Debug)]
pub struct CeloEvmTypes;

impl EvmTypesHost for CeloEvmTypes {
    type ConfigSelector = CeloConfigSelector;
    type SpecId = OpSpecId;
    type Tx = CeloTxEnvelope;
    type EvmExt = CeloEvmExt;
    type MessageExt = ();
    type MessageResultExt = ();
    type TxEnvExt = ();
    type TxResultExt = CeloTxResultExt;
    type BlockEnvExt = ();
    type Host<'a> = Evm<'a, Self>;
}

/// Celo EVM instance.
pub type CeloEvm<'a> = Evm<'a, CeloEvmTypes>;

/// Celo block environment.
pub type CeloBlockEnv = evm2::env::BlockEnv<CeloEvmTypes>;

/// Celo opcode configuration: the Ethereum table of the inherited specification.
#[derive(Clone, Copy, Debug)]
pub struct CeloConfig<const BASE_SPEC_ID: u32>(());

impl<const BASE_SPEC_ID: u32> EvmConfig<CeloEvmTypes> for CeloConfig<BASE_SPEC_ID> {
    const BASE_SPEC_ID: SpecId =
        SpecId::try_from_u32(BASE_SPEC_ID).expect("invalid Celo base spec id");
    const OPCODE_CONFIG: &'static OpcodeConfig<CeloEvmTypes> =
        &OpcodeConfig::<CeloEvmTypes>::base::<Self>();
}

/// Selects the opcode table of the Ethereum specification an OP hardfork builds on.
#[derive(Clone, Copy, Debug)]
pub struct CeloConfigSelector;

impl EvmConfigSelector<CeloEvmTypes> for CeloConfigSelector {
    type Config<const BASE_SPEC_ID: u32, const CUSTOM_SPEC_ID: u32> = CeloConfig<BASE_SPEC_ID>;

    fn execution_config(spec_id: OpSpecId) -> ExecutionConfig<CeloEvmTypes> {
        let base = spec_id.into_eth_spec();
        evm2::spec_to_generic!(base, |SPEC_ID| ExecutionConfig::for_config::<CeloConfig<SPEC_ID>>())
            .with_version(celo_version(spec_id, CELO_MAINNET_CHAIN_ID))
    }
}

/// EVM instance-wide extension state for Celo.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CeloEvmExt {
    /// Cached L1 block info, reloaded from the `L1Block` predeploy when the block changes.
    pub l1_block_info: L1BlockInfo,
    /// Fee currencies of the current block, reloaded from the `FeeCurrencyDirectory` before the
    /// first transaction of a block.
    ///
    /// Set it with [`FeeCurrencyContext::block`] equal to the block number to inject the context
    /// without a reload.
    pub fee_currency_context: FeeCurrencyContext,
}

/// Transaction-result extension data for Celo transactions.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CeloTxResultExt {
    /// Whether this is a failed deposit, which keeps only the mint and the sender nonce bump and
    /// consumes its full gas limit.
    pub failed_deposit: bool,
    /// Validation error that caused [`Self::failed_deposit`], if the deposit did not execute.
    pub deposit_error: Option<HandlerError>,
    /// L1 data fee credited to the L1 fee vault.
    pub l1_fee: U256,
    /// Operator fee credited to the operator fee vault.
    pub operator_fee: U256,
    /// For CIP-64 transactions, the base fee in the fee currency, as recorded in the receipt.
    pub base_fee_in_erc20: Option<u128>,
}

/// Returns the evm2 runtime version for an OP hardfork on a Celo chain.
///
/// Celo raises the contract code size limit to [`CELO_MAX_CODE_SIZE`] and the initcode limit to
/// twice that.
pub const fn celo_version(spec: OpSpecId, chain_id: u64) -> Version {
    let mut version = Version::new(spec.into_eth_spec());
    version.chain_id = chain_id;
    version.max_code_size = CELO_MAX_CODE_SIZE;
    version.max_initcode_size = 2 * CELO_MAX_CODE_SIZE;
    version
}

/// Builds the evm2 execution config for an OP hardfork with dynamic runtime version data.
pub fn celo_execution_config(spec: OpSpecId, version: Version) -> ExecutionConfig<CeloEvmTypes> {
    ExecutionConfig::for_spec_and_version(spec, version)
}
