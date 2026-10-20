//! Monad evm2 type family, opcode configuration and runtime selection.

use crate::{
    MonadChainContext, MonadHardfork, instructions as monad,
    reserve_balance::{ReserveBalanceSync, tracker::ReserveBalanceTracker},
};
use evm2::{
    Evm, EvmConfig, EvmConfigSelector, EvmTypesHost, ExecutionConfig, OpcodeConfig, SpecId,
    Version, ethereum::TxEnvelope, interpreter::op,
};

/// evm2 type family used by Monad execution.
#[derive(Clone, Copy, Debug)]
pub struct MonadEvmTypes;

impl EvmTypesHost for MonadEvmTypes {
    type ConfigSelector = MonadConfigSelector;
    type SpecId = MonadHardfork;
    type Tx = TxEnvelope;
    type EvmExt = MonadEvmExt;
    type MessageExt = ();
    type MessageResultExt = ();
    type TxEnvExt = ();
    type TxResultExt = MonadTxResultExt;
    type BlockEnvExt = MonadBlockExt;
    type Host<'a> = Evm<'a, Self>;
}

/// Monad EVM instance.
pub type MonadEvm<'a> = Evm<'a, MonadEvmTypes>;

/// Monad transaction envelope: the Ethereum envelope, with EIP-4844 rejected by the handlers.
pub type MonadTxEnvelope = TxEnvelope;

/// Monad block environment.
pub type MonadBlockEnv = evm2::env::BlockEnv<MonadEvmTypes>;

/// Monad block-environment extension.
///
/// Monad has no block-level execution fields beyond Ethereum's. The chain context (parent senders
/// and authorities) is not `Copy`, so it lives in [`MonadEvmExt::chain`] instead.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct MonadBlockExt;

/// Monad-specific state owned by an evm2 instance.
#[derive(Clone, Debug, Default)]
pub struct MonadEvmExt {
    /// Chain context used for reserve-balance decisions.
    pub chain: MonadChainContext,
    /// Reserve-balance tracker for the current transaction.
    pub reserve_balance: ReserveBalanceTracker,
    /// Whether transaction boundaries preserve the reserve-balance tracker.
    ///
    /// Intended for synthetic transactions that model an internal call while retaining the
    /// enclosing transaction's reserve-balance state. Restore this to `false` before executing
    /// the next ordinary transaction.
    pub preserve_reserve_balance_tracker: bool,
    /// Reverts a successful transaction that ends with a reserve-balance violation.
    ///
    /// Off by default: `monad-revm` 0.8.0 only exposes the violation through the
    /// `dippedIntoReserve()` precompile and [`MonadTxResultExt::dipped_into_reserve`].
    pub revert_on_reserve_balance_violation: bool,
    /// Memory held by suspended ancestor frames, counted against the pooled MIP-3 memory limit.
    pub memory_pool_offset: u64,
    /// Journal cursor feeding the reserve-balance tracker.
    pub reserve_balance_sync: ReserveBalanceSync,
    /// Executes canonical legacy envelopes from the Monad system sender as protocol system calls.
    ///
    /// Off by default. Enable it only to replay trusted historical blocks; with it disabled every
    /// transaction keeps the ordinary handler behavior. See [`crate::protocol`].
    pub protocol_replay: bool,
}

impl MonadEvmExt {
    /// Creates extension state for a chain context.
    pub fn new(chain: MonadChainContext) -> Self {
        Self { chain, ..Default::default() }
    }

    /// Returns a copy of the reserve-balance tracker.
    pub fn capture_reserve_balance(&self) -> ReserveBalanceTracker {
        self.reserve_balance.clone()
    }

    /// Replaces the reserve-balance tracker.
    pub fn restore_reserve_balance(&mut self, tracker: ReserveBalanceTracker) {
        self.reserve_balance = tracker;
    }

    /// Sets whether transaction boundaries preserve the reserve-balance tracker.
    pub const fn set_preserve_reserve_balance_tracker(&mut self, preserve: bool) {
        self.preserve_reserve_balance_tracker = preserve;
    }

    /// Sets whether legacy envelopes from the system sender replay as protocol system calls.
    pub const fn set_protocol_replay(&mut self, enabled: bool) {
        self.protocol_replay = enabled;
    }
}

/// Monad-specific transaction result fields.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct MonadTxResultExt {
    /// Whether the transaction ended with a reserve-balance violation.
    pub dipped_into_reserve: bool,
    /// Whether the transaction was reverted because of a reserve-balance violation.
    ///
    /// Only set when [`MonadEvmExt::revert_on_reserve_balance_violation`] is enabled.
    pub reverted_for_reserve_balance: bool,
}

/// Monad opcode configuration over an inherited Ethereum specification.
///
/// `MONAD_SPEC` is a [`MonadHardfork`] discriminant; `u32::MAX` selects the plain base table.
#[derive(Clone, Copy, Debug)]
pub struct MonadConfig<const BASE_SPEC_ID: u32, const MONAD_SPEC: u32>(());

impl<const BASE_SPEC_ID: u32, const MONAD_SPEC: u32> EvmConfig<MonadEvmTypes>
    for MonadConfig<BASE_SPEC_ID, MONAD_SPEC>
{
    const BASE_SPEC_ID: SpecId =
        SpecId::try_from_u32(BASE_SPEC_ID).expect("invalid Monad base spec id");
    const OPCODE_CONFIG: &'static OpcodeConfig<MonadEvmTypes> =
        &monad_opcode_config::<BASE_SPEC_ID, MONAD_SPEC>();
}

/// Returns Monad's opcode configuration for a Monad hardfork over an inherited specification.
pub const fn monad_opcode_config<const BASE_SPEC_ID: u32, const MONAD_SPEC: u32>()
-> OpcodeConfig<MonadEvmTypes> {
    let mut config = OpcodeConfig::base::<MonadConfig<BASE_SPEC_ID, MONAD_SPEC>>();
    if MONAD_SPEC > u8::MAX as u32 {
        return config;
    }
    let Some(spec) = MonadHardfork::try_from_u8(MONAD_SPEC as u8) else {
        return config;
    };

    if MonadHardfork::MonadNine.is_enabled_in(spec) {
        set_call_family::<true>(&mut config);

        // MIP-3: replace memory-expanding opcodes with linear-cost variants.
        let c = &mut config;
        c.set_instruction::<monad::mload>(op::MLOAD, c.static_gas(op::MLOAD));
        c.set_instruction::<monad::mstore>(op::MSTORE, c.static_gas(op::MSTORE));
        c.set_instruction::<monad::mstore8>(op::MSTORE8, c.static_gas(op::MSTORE8));
        c.set_instruction::<monad::mcopy>(op::MCOPY, c.static_gas(op::MCOPY));
        c.set_instruction::<monad::keccak256_mip3>(op::KECCAK256, c.static_gas(op::KECCAK256));
        c.set_instruction::<monad::calldatacopy>(op::CALLDATACOPY, c.static_gas(op::CALLDATACOPY));
        c.set_instruction::<monad::codecopy>(op::CODECOPY, c.static_gas(op::CODECOPY));
        c.set_instruction::<monad::returndatacopy>(
            op::RETURNDATACOPY,
            c.static_gas(op::RETURNDATACOPY),
        );
        c.set_instruction::<monad::extcodecopy>(op::EXTCODECOPY, c.static_gas(op::EXTCODECOPY));
        c.set_instruction::<monad::log<0>>(op::LOG0, c.static_gas(op::LOG0));
        c.set_instruction::<monad::log<1>>(op::LOG1, c.static_gas(op::LOG1));
        c.set_instruction::<monad::log<2>>(op::LOG2, c.static_gas(op::LOG2));
        c.set_instruction::<monad::log<3>>(op::LOG3, c.static_gas(op::LOG3));
        c.set_instruction::<monad::log<4>>(op::LOG4, c.static_gas(op::LOG4));
        c.set_instruction::<monad::ret>(op::RETURN, 0);
        c.set_instruction::<monad::revert>(op::REVERT, 0);
    } else {
        set_call_family::<false>(&mut config);
    }

    if MonadHardfork::MonadTen.is_enabled_in(spec) {
        // MIP-8: page-based storage warmth and SSTORE pricing.
        let static_gas = config.static_gas(op::SLOAD);
        config.set_instruction::<monad::sload>(op::SLOAD, static_gas);
        config.set_instruction::<monad::sstore>(op::SSTORE, 0);
    }

    config
}

const fn set_call_family<const MIP3: bool>(config: &mut OpcodeConfig<MonadEvmTypes>) {
    config.set_instruction::<monad::create<false, MIP3>>(op::CREATE, 0);
    config.set_instruction::<monad::create<true, MIP3>>(op::CREATE2, 0);
    let static_gas = config.static_gas(op::CALL);
    config.set_instruction::<monad::call<MIP3>>(op::CALL, static_gas);
    let static_gas = config.static_gas(op::CALLCODE);
    config.set_instruction::<monad::callcode<MIP3>>(op::CALLCODE, static_gas);
    let static_gas = config.static_gas(op::DELEGATECALL);
    config.set_instruction::<monad::delegatecall<MIP3>>(op::DELEGATECALL, static_gas);
    let static_gas = config.static_gas(op::STATICCALL);
    config.set_instruction::<monad::staticcall<MIP3>>(op::STATICCALL, static_gas);
}

/// Selects Monad's opcode table for the active Monad hardfork.
#[derive(Clone, Copy, Debug)]
pub struct MonadConfigSelector;

impl EvmConfigSelector<MonadEvmTypes> for MonadConfigSelector {
    type Config<const BASE_SPEC_ID: u32, const CUSTOM_SPEC_ID: u32> =
        MonadConfig<BASE_SPEC_ID, CUSTOM_SPEC_ID>;

    fn execution_config(spec_id: MonadHardfork) -> ExecutionConfig<MonadEvmTypes> {
        const PRAGUE: u32 = SpecId::PRAGUE as u32;
        const OSAKA: u32 = SpecId::OSAKA as u32;
        const EIGHT: u32 = MonadHardfork::MonadEight as u32;
        const NINE: u32 = MonadHardfork::MonadNine as u32;
        const TEN: u32 = MonadHardfork::MonadTen as u32;
        const NEXT: u32 = MonadHardfork::MonadNext as u32;
        let config = match spec_id {
            MonadHardfork::MonadEight => {
                ExecutionConfig::for_config::<MonadConfig<PRAGUE, EIGHT>>()
            }
            MonadHardfork::MonadNine => ExecutionConfig::for_config::<MonadConfig<OSAKA, NINE>>(),
            MonadHardfork::MonadTen => ExecutionConfig::for_config::<MonadConfig<OSAKA, TEN>>(),
            MonadHardfork::MonadNext => ExecutionConfig::for_config::<MonadConfig<OSAKA, NEXT>>(),
        };
        config.with_version(crate::monad_version(spec_id, 1))
    }
}

/// Builds the evm2 execution config for a Monad hardfork with dynamic runtime version data.
///
/// `version` is usually [`monad_version`](crate::monad_version), adjusted by the caller (for
/// example with test-only [`evm2::EvmFeatures`] removed).
pub fn monad_execution_config(
    spec: MonadHardfork,
    version: Version,
) -> ExecutionConfig<MonadEvmTypes> {
    ExecutionConfig::for_spec_and_version(spec, version)
}
