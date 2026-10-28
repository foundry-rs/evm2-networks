//! Arbitrum evm2 type family, opcode configuration and runtime version.

use crate::{ArbOsVersion, ArbTxEnvelope, instructions};
use alloy_primitives::{Address, U256};
use evm2::{
    Evm, EvmConfig, EvmConfigSelector, EvmFeatures, EvmTypesHost, ExecutionConfig, OpcodeConfig,
    SpecId, Version, env::BlockEnv, interpreter::op, spec_to_generic,
};

/// First byte of Stylus programs, an undefined opcode.
const STYLUS_EOF_MAGIC: u8 = 0xef;

/// evm2 type family used by Arbitrum execution.
#[derive(Clone, Copy, Debug)]
pub struct ArbEvmTypes;

impl EvmTypesHost for ArbEvmTypes {
    type ConfigSelector = ArbConfigSelector;
    type SpecId = ArbOsVersion;
    type Tx = ArbTxEnvelope;
    type EvmExt = ArbEvmExt;
    type MessageExt = ();
    type MessageResultExt = ();
    type TxEnvExt = ();
    type TxResultExt = ArbTxResultExt;
    type BlockEnvExt = ArbBlockEnvExt;
    type Host<'a> = Evm<'a, Self>;
}

/// Arbitrum EVM instance.
pub type ArbEvm<'a> = Evm<'a, ArbEvmTypes>;

/// Arbitrum block environment.
///
/// `number` is the L2 block number, which `ArbSys.arbBlockNumber()` returns. The `NUMBER` opcode
/// returns the L1 block number instead ([`ArbBlockEnvExt::l1_block_number`]). Nitro sets
/// `prevrandao` to the header difficulty, `1`, and `blob_basefee` to zero.
pub type ArbBlockEnv = BlockEnv<ArbEvmTypes>;

/// Arbitrum block environment extension.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ArbBlockEnvExt {
    /// L1 block number returned by `NUMBER` and bounding `BLOCKHASH`.
    ///
    /// Nitro reads it from the ArbOS state, where the block's `startBlock` internal transaction
    /// records it; the header carries the same value
    /// ([`ArbHeaderInfo::l1_block_number`](crate::ArbHeaderInfo::l1_block_number)). `None` reads
    /// the ArbOS state, which is the right choice when the state already includes the internal
    /// transaction. Set it from the header when replaying a block without its internal
    /// transactions.
    pub l1_block_number: Option<u64>,
}

/// Arbitrum state owned by an EVM instance: the fee context of the current transaction (part of
/// Nitro's `TxProcessor`).
///
/// The transaction handler resets it before every transaction.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ArbEvmExt {
    /// Transaction sender, which `ArbSys.myCallersAddressWithoutAliasing()` returns to the
    /// top-level frame.
    pub sender: Address,
    /// Gas price the transaction pays.
    pub paid_gas_price: U256,
    /// L1 poster gas charged before execution.
    pub poster_gas: u64,
    /// L1 poster fee, `poster_gas * paid_gas_price`, returned by
    /// `ArbGasInfo.getCurrentTxL1GasFees()`.
    pub poster_fee: U256,
    /// Gas withheld from execution to cap it at the ArbOS gas limit, returned after execution.
    pub held_gas: u64,
}

/// Arbitrum-specific transaction result fields.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ArbTxResultExt {
    /// L1 poster gas included in the gas used, the receipt's `gasUsedForL1`.
    pub poster_gas: u64,
    /// L1 poster fee credited to the L1 pricer funds pool.
    pub poster_fee: U256,
    /// Gas price the transaction paid, the receipt's `effectiveGasPrice`.
    pub paid_gas_price: U256,
}

/// Arbitrum opcode configuration over an inherited Ethereum specification.
#[derive(Clone, Copy, Debug)]
pub struct ArbConfig<const BASE_SPEC_ID: u32>(());

impl<const BASE_SPEC_ID: u32> EvmConfig<ArbEvmTypes> for ArbConfig<BASE_SPEC_ID> {
    const BASE_SPEC_ID: SpecId =
        SpecId::try_from_u32(BASE_SPEC_ID).expect("invalid Arbitrum base spec id");
    const OPCODE_CONFIG: &'static OpcodeConfig<ArbEvmTypes> =
        &arbitrum_opcode_config::<BASE_SPEC_ID>();
}

/// Returns Arbitrum's opcode configuration over an inherited specification.
///
/// Port of Nitro's opcode changes (`core/vm/instructions.go`, `core/vm/eips.go`,
/// `core/vm/interpreter.go`): `NUMBER` and `BLOCKHASH` use L1 blocks, `GASPRICE` returns the
/// price paid, `BLOBBASEFEE` fails, and Stylus programs are rejected.
pub const fn arbitrum_opcode_config<const BASE_SPEC_ID: u32>() -> OpcodeConfig<ArbEvmTypes> {
    let mut config = OpcodeConfig::base::<ArbConfig<BASE_SPEC_ID>>();
    let number_gas = config.static_gas(op::NUMBER);
    config.set_instruction::<instructions::l1_block_number>(op::NUMBER, number_gas);
    let blockhash_gas = config.static_gas(op::BLOCKHASH);
    config.set_instruction::<instructions::l1_blockhash>(op::BLOCKHASH, blockhash_gas);
    let gasprice_gas = config.static_gas(op::GASPRICE);
    config.set_instruction::<instructions::paid_gasprice>(op::GASPRICE, gasprice_gas);
    if BASE_SPEC_ID >= SpecId::CANCUN as u32 {
        let blobbasefee_gas = config.static_gas(op::BLOBBASEFEE);
        config.set_instruction::<instructions::blobbasefee>(op::BLOBBASEFEE, blobbasefee_gas);
    }
    config.set_instruction::<instructions::stylus_or_invalid>(STYLUS_EOF_MAGIC, 0);
    config
}

/// Selects the Arbitrum opcode table for the inherited Ethereum specification of an ArbOS
/// version.
#[derive(Clone, Copy, Debug)]
pub struct ArbConfigSelector;

impl EvmConfigSelector<ArbEvmTypes> for ArbConfigSelector {
    type Config<const BASE_SPEC_ID: u32, const CUSTOM_SPEC_ID: u32> = ArbConfig<BASE_SPEC_ID>;

    fn execution_config(spec_id: ArbOsVersion) -> ExecutionConfig<ArbEvmTypes> {
        let base = spec_id.into_eth_spec();
        spec_to_generic!(base, |SPEC_ID| ExecutionConfig::for_config::<ArbConfig<SPEC_ID>>())
            .with_version(arbitrum_version(spec_id, 1))
    }
}

/// Returns the evm2 runtime version for an ArbOS version and chain ID.
///
/// Nitro uses the gas parameters of the inherited Ethereum specification, with two differences:
///
/// - No EIP-7825 transaction gas limit cap. ArbOS caps execution gas itself (see
///   [`ArbHandlerHooks`](crate::ArbHandlerHooks)).
/// - No priority fee check during validation. ArbOS drops the tip before validating unless it
///   collects tips, and the handler checks the priority fee when it does.
///
/// The EIP-7623 calldata floor stays enabled; the handler only applies it when the ArbOS
/// calldata price increase feature is on.
pub const fn arbitrum_version(spec: ArbOsVersion, chain_id: u64) -> Version {
    let mut version = Version::new(spec.into_eth_spec());
    version.chain_id = chain_id;
    version.tx_gas_limit_cap = u64::MAX;
    version.features.remove(EvmFeatures::PRIORITY_FEE_CHECK);
    version
}
