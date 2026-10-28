//! evm2-backed storage provider for Base's native precompile business logic.
//!
//! [`BaseStorageProvider`] implements `base_precompile_storage::PrecompileStorageProvider` over a
//! live [`Evm`], so the `#[contract]` storage types and dispatchers of `base-common-precompiles`
//! (B-20 factory and tokens, policy registry) read and write evm2 state directly. Only revm data
//! types (account info, bytecode, journal checkpoints) cross the provider boundary; they are
//! converted to and from evm2 types here, and revm never executes.
//!
//! The provider runs in one of two modes:
//!
//! - Metered, mirroring `base_precompile_storage::EvmPrecompileStorageProvider` inside the
//!   reference `base_precompile!` wrapper: every storage, log, code, and account access is charged
//!   with the EVM-equivalent gas schedule under the Osaka gas parameters the reference's
//!   `GasParams::default()` selects.
//! - Unmetered, mirroring `base_precompile_storage::JournalStorageProvider`: nothing is charged,
//!   for enshrined EIP-8130 pre-call processing whose gas is owned by the intrinsic schedule.
//!
//! Database failures are recorded on the provider and surface as evm2 database or fatal errors,
//! never as reverts. Checkpoints are evm2 state checkpoints and revert through native evm2
//! rollback.

use alloy_primitives::{Address, B256, Bytes, KECCAK256_EMPTY, Log, LogData, U256};
use alloy_sol_types::SolError;
use base_precompile_storage::{
    BasePrecompileError, DelegateCallNotAllowed, PrecompileResult as BasePrecompileResult,
    PrecompileStatus, PrecompileStorageProvider, Result, StorageCtx, StorageFeatures,
    validate_loaded_code_presence,
};
use evm2::{
    Evm, EvmFeatures, ExecutionError, HostError, SpecId, Version,
    bytecode::Bytecode,
    evm::{StateCheckpoint, precompile::PrecompileOutput},
    interpreter::{GasTracker, Host, Message, MessageKind},
    precompiles::{PrecompileError, PrecompileHalt, PrecompileResult},
    version::{GasId, GasParams},
};
use revm::{
    context::journaled_state::JournalCheckpoint,
    state::{AccountInfo as RevmAccountInfo, Bytecode as RevmBytecode},
};

use crate::BaseEvmTypes;

/// Static `LOG` gas.
const LOG_GAS: u64 = 375;
/// Static `KECCAK256` gas.
const KECCAK256_GAS: u64 = 30;

/// Gas counters of a metered provider, mirroring revm's `Gas` as the reference provider uses it.
#[derive(Clone, Copy, Debug)]
struct Meter {
    limit: u64,
    remaining: u64,
    refunded: i64,
    state_gas_used: u64,
}

/// [`PrecompileStorageProvider`] backed by a live evm2 [`Evm`].
///
/// Build one with [`Self::metered`] for a precompile call or [`Self::unmetered`] for enshrined
/// pre-call processing, then pass `&mut provider` to [`StorageCtx::enter`]. After the closure
/// returns, check [`Self::take_host_error`] (or use [`Self::finish`] for precompile results): a
/// database failure inside the closure surfaces there as the original evm2 error, while the Base
/// logic only saw a `BasePrecompileError::Fatal`.
pub(crate) struct BaseStorageProvider<'e, 'a> {
    evm: &'e mut Evm<'a, BaseEvmTypes>,
    meter: Option<Meter>,
    params: &'static GasParams,
    caller: Address,
    call_value: U256,
    is_static: bool,
    origin: Address,
    storage_features: StorageFeatures,
    host_error: Option<ExecutionError>,
}

impl core::fmt::Debug for BaseStorageProvider<'_, '_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("BaseStorageProvider")
            .field("meter", &self.meter)
            .field("caller", &self.caller)
            .field("call_value", &self.call_value)
            .field("is_static", &self.is_static)
            .field("origin", &self.origin)
            .field("storage_features", &self.storage_features)
            .field("host_error", &self.host_error)
            .finish_non_exhaustive()
    }
}

impl<'e, 'a> BaseStorageProvider<'e, 'a> {
    /// Builds a metered provider for a precompile call of `message` with `gas_limit` gas, like
    /// `EvmPrecompileStorageProvider::new_with_storage_features` in the reference wrapper.
    ///
    /// The caller, value, and static flag come from `message`; `tx.origin` is the origin of the
    /// transaction currently executing.
    pub(crate) fn metered(
        evm: &'e mut Evm<'a, BaseEvmTypes>,
        message: &Message<BaseEvmTypes>,
        gas_limit: u64,
        storage_features: StorageFeatures,
    ) -> Self {
        let origin = evm.ext().tx_origin;
        Self {
            evm,
            meter: Some(Meter {
                limit: gas_limit,
                remaining: gas_limit,
                refunded: 0,
                state_gas_used: 0,
            }),
            params: osaka_gas_params(),
            caller: message.caller,
            call_value: message.value,
            is_static: message.caller_is_static || message.kind == MessageKind::StaticCall,
            origin,
            storage_features,
            host_error: None,
        }
    }

    /// Builds an unmetered provider attributing storage access to `caller`, like
    /// `JournalStorageProvider::new`.
    ///
    /// Nothing is charged, the context is never static, the call value is zero, and the
    /// persistent-storage features are [`StorageFeatures::Legacy`]. No precompile is active,
    /// so `origin` is explicit.
    pub(crate) fn unmetered(
        evm: &'e mut Evm<'a, BaseEvmTypes>,
        caller: Address,
        origin: Address,
    ) -> Self {
        Self {
            evm,
            meter: None,
            params: osaka_gas_params(),
            caller,
            call_value: U256::ZERO,
            is_static: false,
            origin,
            storage_features: StorageFeatures::Legacy,
            host_error: None,
        }
    }

    /// Takes the first database or fatal host error hit through this provider, if any.
    ///
    /// The Base logic only observed it as `BasePrecompileError::Fatal`; this is the original evm2
    /// error, which must abort execution.
    pub(crate) fn take_host_error(&mut self) -> Option<ExecutionError> {
        self.host_error.take()
    }

    /// Converts the Base result of a metered precompile call into an evm2 precompile result,
    /// spending the gas used and recording the refund on `gas`.
    ///
    /// A recorded host error takes precedence over the Base result, so database failures stay
    /// fatal even if the Base logic swallowed the error.
    pub(crate) fn finish(
        mut self,
        result: BasePrecompileResult,
        gas: &mut GasTracker,
    ) -> PrecompileResult {
        if let Some(error) = self.host_error.take() {
            return Err(error.into());
        }
        let output = match result {
            Ok(output) => output,
            Err(base_precompile_storage::PrecompileError::Fatal(message)) => {
                return Err(PrecompileError::Fatal(message.into()));
            }
        };
        let success = match output.status {
            PrecompileStatus::Success => true,
            PrecompileStatus::Revert => false,
            PrecompileStatus::Halt(_) => return Err(PrecompileHalt::OutOfGas.into()),
        };
        if gas.spend(output.gas_used).is_err() {
            return Err(PrecompileHalt::OutOfGas.into());
        }
        // revm rebuilds the frame's gas from the output (`PrecompileOutput::to_gas_tracker`),
        // including the reservoir the reference reports. Base specs predate EIP-8037, so these
        // are all zero in practice.
        gas.set_reservoir(output.reservoir);
        gas.add_state_gas_spent(output.state_gas_used);
        gas.add_state_gas_spilled(output.state_gas_spilled);
        if success {
            gas.record_refund(output.gas_refunded);
            Ok(PrecompileOutput::new(output.bytes))
        } else {
            Err(PrecompileError::Revert(output.bytes))
        }
    }

    /// Records a host failure. Database and fatal errors are kept for [`Self::finish`] and
    /// [`Self::take_host_error`]; a non-fatal halt (a skipped cold load) is out of gas, as in the
    /// reference's `JournalLoadError` conversion.
    fn host_failure(&mut self, error: HostError) -> BasePrecompileError {
        let error = match error {
            HostError::Halt(stop) if !stop.is_fatal() => return BasePrecompileError::OutOfGas,
            HostError::Halt(_) => ExecutionError::Fatal("fatal external error".into()),
            HostError::Execution(error) => error,
        };
        let message = error.to_string();
        self.host_error.get_or_insert(error);
        BasePrecompileError::Fatal(message)
    }

    fn gas(&self, id: GasId) -> u64 {
        self.params.get(id)
    }

    const fn is_metered(&self) -> bool {
        self.meter.is_some()
    }

    fn rollback(&mut self, checkpoint: StateCheckpoint) {
        let features = self.evm.version().features;
        self.evm.state_mut().rollback(checkpoint, features);
    }

    /// Loads `address`, warming it like revm's journal `load_account`.
    fn load_account(
        &mut self,
        address: Address,
        load_code: bool,
    ) -> Result<evm2::evm::AccountLoad> {
        self.evm.load_account(&address, load_code, false).map_err(|e| self.host_failure(e))
    }

    fn sload_inner(&mut self, address: Address, key: U256) -> Result<U256> {
        let load = self.evm.sload(&address, &key, false).map_err(|e| self.host_failure(e))?;
        if self.is_metered() {
            // EIP-2929: the warm base cost is always charged, plus the cold penalty.
            self.deduct_gas(self.gas(GasId::WarmStorageReadCost))?;
            if load.is_cold {
                self.deduct_gas(self.gas(GasId::ColdStorageAdditionalCost))?;
            }
        }
        Ok(load.value)
    }

    fn sstore_inner(&mut self, address: Address, key: U256, value: U256) -> Result<()> {
        let store =
            self.evm.sstore(&address, &key, &value, false).map_err(|e| self.host_failure(e))?;
        if self.is_metered() {
            self.deduct_gas(self.gas(GasId::SstoreStatic))?;
            self.deduct_gas(self.params.sstore_dynamic_gas(true, &store))?;
            self.refund_gas(self.params.sstore_refund(true, &store));
        }
        Ok(())
    }
}

impl PrecompileStorageProvider for BaseStorageProvider<'_, '_> {
    fn chain_id(&self) -> u64 {
        self.evm.version().chain_id
    }

    fn timestamp(&self) -> U256 {
        self.evm.block().timestamp
    }

    fn beneficiary(&self) -> Address {
        self.evm.block().beneficiary
    }

    fn block_number(&self) -> u64 {
        self.evm.block().number.saturating_to()
    }

    fn origin(&self) -> Address {
        self.origin
    }

    fn set_code(&mut self, address: Address, code: RevmBytecode) -> Result<()> {
        if self.is_metered() {
            if self.is_static {
                return Err(BasePrecompileError::StaticCallViolation);
            }
            let code_len = code.len();
            // Yellow Paper G_codedeposit per byte of deployed bytecode.
            self.deduct_gas(self.gas(GasId::CodeDepositCost).saturating_mul(code_len as u64))?;
            // CREATE-equivalent costs whenever code lands on an account without code, regardless
            // of its balance.
            let code_hash = self.load_account(address, false)?.code_hash;
            if is_empty_code_hash(code_hash) {
                self.deduct_gas(self.gas(GasId::Create))?;
                let words = code_len.div_ceil(32) as u64;
                self.deduct_gas(
                    KECCAK256_GAS
                        .saturating_add(self.gas(GasId::Keccak256PerWord).saturating_mul(words)),
                )?;
            }
        } else {
            self.load_account(address, false)?;
        }
        let code = Bytecode::new_raw_checked(code.original_bytes())
            .map_err(|e| BasePrecompileError::Fatal(e.to_string()))?;
        let result =
            self.evm.state_mut().account(&address).map(|mut account| account.set_code_slow(code));
        result.map_err(|e| self.host_failure(e.into()))
    }

    fn with_account_info(
        &mut self,
        address: Address,
        f: &mut dyn FnMut(&RevmAccountInfo),
    ) -> Result<()> {
        let load = self.load_account(address, false)?;
        if self.is_metered() {
            // EIP-2929 account access: warm base cost plus the cold penalty.
            self.deduct_gas(self.gas(GasId::WarmStorageReadCost))?;
            if load.is_cold {
                self.deduct_gas(self.gas(GasId::ColdAccountAdditionalCost))?;
            }
        }
        let info = RevmAccountInfo {
            balance: load.balance,
            nonce: load.nonce,
            code_hash: normalize_code_hash(load.code_hash),
            ..Default::default()
        };
        f(&info);
        Ok(())
    }

    fn with_account_code(
        &mut self,
        address: Address,
        f: &mut dyn FnMut(&RevmBytecode),
    ) -> Result<()> {
        let load = self.load_account(address, true)?;
        let code = RevmBytecode::new_raw_checked(load.code.original_bytes())
            .map_err(|e| BasePrecompileError::Fatal(e.to_string()))?;
        validate_loaded_code_presence(normalize_code_hash(load.code_hash), &code)?;
        if self.is_metered() {
            self.deduct_gas(self.gas(GasId::WarmStorageReadCost))?;
            if load.is_cold {
                self.deduct_gas(self.gas(GasId::ColdAccountAdditionalCost))?;
            }
        }
        f(&code);
        Ok(())
    }

    fn sload(&mut self, address: Address, key: U256) -> Result<U256> {
        // A failed read must not leave the slot warm.
        let checkpoint = self.evm.state().checkpoint();
        let result = self.sload_inner(address, key);
        if result.is_err() {
            self.rollback(checkpoint);
        }
        result
    }

    fn tload(&mut self, address: Address, key: U256) -> Result<U256> {
        if self.is_metered() {
            self.deduct_gas(self.gas(GasId::WarmStorageReadCost))?;
        }
        Ok(self.evm.tload(&address, &key))
    }

    fn tload_unmetered(&mut self, address: Address, key: U256) -> Result<U256> {
        Ok(self.evm.tload(&address, &key))
    }

    fn sstore(&mut self, address: Address, key: U256, value: U256) -> Result<()> {
        if let Some(meter) = self.meter {
            if self.is_static {
                return Err(BasePrecompileError::StaticCallViolation);
            }
            // EIP-2200 reentrancy sentry.
            if meter.remaining <= self.gas(GasId::CallStipend) {
                return Err(BasePrecompileError::OutOfGas);
            }
        }
        let checkpoint = self.evm.state().checkpoint();
        let result = self.sstore_inner(address, key, value);
        if result.is_err() {
            self.rollback(checkpoint);
        }
        result
    }

    fn tstore(&mut self, address: Address, key: U256, value: U256) -> Result<()> {
        if self.is_metered() {
            if self.is_static {
                return Err(BasePrecompileError::StaticCallViolation);
            }
            self.deduct_gas(self.gas(GasId::WarmStorageReadCost))?;
        }
        self.evm.tstore(&address, &key, &value);
        Ok(())
    }

    fn emit_event(&mut self, address: Address, event: LogData) -> Result<()> {
        let log = Log { address, data: event };
        if self.is_metered() {
            if self.is_static {
                return Err(BasePrecompileError::StaticCallViolation);
            }
            let cost =
                LOG_GAS + self.params.log_cost(log.topics().len() as u8, log.data.data.len());
            self.deduct_gas(cost)?;
            self.evm.log(log);
        } else {
            // Base's JournalStorageProvider writes pre-call events directly to the journal,
            // before the synthetic trace root exists. Keep receipt logs without firing hooks.
            if self.evm.feature(EvmFeatures::LOG_COLLECTION) {
                self.evm.state_mut().logs_mut().push(log);
            }
        }
        Ok(())
    }

    fn deduct_gas(&mut self, gas: u64) -> Result<()> {
        let Some(meter) = &mut self.meter else { return Ok(()) };
        // revm's `Gas::record_regular_cost`: a failed charge leaves the counter unchanged.
        meter.remaining = meter.remaining.checked_sub(gas).ok_or(BasePrecompileError::OutOfGas)?;
        Ok(())
    }

    fn deduct_state_gas(&mut self, gas: u64) -> Result<()> {
        if !self.is_metered() {
            return Ok(());
        }
        // No reservoir in the precompile context: state gas is drawn from regular gas.
        self.deduct_gas(gas)?;
        if let Some(meter) = &mut self.meter {
            meter.state_gas_used = meter.state_gas_used.saturating_add(gas);
        }
        Ok(())
    }

    fn refund_gas(&mut self, gas: i64) {
        if let Some(meter) = &mut self.meter {
            meter.refunded += gas;
        }
    }

    fn gas_limit(&self) -> u64 {
        self.meter.map_or(u64::MAX, |meter| meter.limit)
    }

    fn gas_used(&self) -> u64 {
        self.meter.map_or(0, |meter| meter.limit - meter.remaining)
    }

    fn state_gas_used(&self) -> u64 {
        self.meter.map_or(0, |meter| meter.state_gas_used)
    }

    fn gas_refunded(&self) -> i64 {
        self.meter.map_or(0, |meter| meter.refunded)
    }

    fn reservoir(&self) -> u64 {
        0
    }

    fn storage_features(&self) -> StorageFeatures {
        self.storage_features
    }

    fn is_static(&self) -> bool {
        self.is_static
    }

    fn call_value(&self) -> U256 {
        self.call_value
    }

    fn caller(&self) -> Address {
        self.caller
    }

    fn replace_caller(&mut self, caller: Address) -> Address {
        core::mem::replace(&mut self.caller, caller)
    }

    fn checkpoint(&mut self) -> JournalCheckpoint {
        let checkpoint = self.evm.state().checkpoint();
        JournalCheckpoint {
            log_i: checkpoint.logs_len(),
            journal_i: checkpoint.journal_len(),
            selfdestructed_i: 0,
        }
    }

    fn commit_latest_checkpoint(&mut self) {
        // evm2 checkpoints are journal cursors: committing keeps the entries for the enclosing
        // frame's rollback and needs no bookkeeping.
    }

    fn checkpoint_revert(&mut self, checkpoint: JournalCheckpoint) {
        self.rollback(StateCheckpoint::new(checkpoint.journal_i, checkpoint.log_i));
    }
}

/// Runs a Base native precompile body with the reference `base_precompile!` wrapper semantics.
///
/// `DELEGATECALL` and `CALLCODE` revert with `DelegateCallNotAllowed` at no gas cost; otherwise
/// `body` runs with a metered provider over the remaining gas and its result is applied to `gas`.
pub(crate) fn run_native(
    evm: &mut Evm<'_, BaseEvmTypes>,
    message: &Message<BaseEvmTypes>,
    gas: &mut GasTracker,
    storage_features: StorageFeatures,
    body: impl for<'ctx> FnOnce(StorageCtx<'ctx>, &[u8]) -> BasePrecompileResult,
) -> PrecompileResult {
    if message.destination != message.code_address {
        return Err(PrecompileError::Revert(DelegateCallNotAllowed {}.abi_encode().into()));
    }
    let calldata: Bytes = message.input.clone();
    let mut provider =
        BaseStorageProvider::metered(evm, message, gas.remaining(), storage_features);
    let result = StorageCtx::enter(&mut provider, |ctx| body(ctx, &calldata));
    provider.finish(result, gas)
}

/// The gas parameters selected by the reference's `GasParams::default()`.
fn osaka_gas_params() -> &'static GasParams {
    &Version::base(SpecId::OSAKA).gas_params
}

/// Whether `code_hash` denotes an account without code.
fn is_empty_code_hash(code_hash: B256) -> bool {
    code_hash == KECCAK256_EMPTY || code_hash == B256::ZERO
}

/// Maps evm2's zero code hash of a missing account to revm's empty code hash.
fn normalize_code_hash(code_hash: B256) -> B256 {
    if code_hash == B256::ZERO { KECCAK256_EMPTY } else { code_hash }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{BaseEvm, BaseEvmFactory, BaseSpecId};
    use base_common_genesis::BaseUpgrade;
    use evm2::{env::BlockEnv, evm::InMemoryDB};

    const ACCOUNT: Address = Address::repeat_byte(0x42);
    const SLOT: U256 = U256::from_limbs([7, 0, 0, 0]);

    fn evm() -> BaseEvm<'static> {
        let spec = BaseSpecId::new(BaseUpgrade::Cobalt);
        let factory = BaseEvmFactory::default();
        factory.create_evm(
            spec,
            factory.version(spec, 8453),
            BlockEnv::<BaseEvmTypes>::default(),
            InMemoryDB::default(),
        )
    }

    fn metered_sload_gas(evm: &mut BaseEvm<'_>, gas_limit: u64) -> Result<u64> {
        let message = Message::<BaseEvmTypes>::default();
        let mut provider =
            BaseStorageProvider::metered(evm, &message, gas_limit, StorageFeatures::Legacy);
        provider.sload(ACCOUNT, SLOT)?;
        Ok(provider.gas_used())
    }

    #[test]
    fn unmetered_checkpoints_roll_back_natively() {
        let mut evm = evm();
        let origin = Address::repeat_byte(0x0a);
        let mut provider = BaseStorageProvider::unmetered(&mut evm, Address::ZERO, origin);
        StorageCtx::enter(&mut provider, |ctx| {
            assert_eq!(ctx.origin(), origin);
            assert!(!ctx.is_static());
            ctx.sstore(ACCOUNT, SLOT, U256::from(1)).unwrap();
            {
                let _reverted = ctx.checkpoint();
                ctx.sstore(ACCOUNT, SLOT, U256::from(2)).unwrap();
                ctx.set_code(ACCOUNT, RevmBytecode::new_legacy(Bytes::from_static(&[0xef])))
                    .unwrap();
            }
            assert_eq!(ctx.sload(ACCOUNT, SLOT).unwrap(), U256::from(1));
            assert!(ctx.with_account_info(ACCOUNT, |info| Ok(info.is_empty_code_hash())).unwrap());
            let committed = ctx.checkpoint();
            ctx.sstore(ACCOUNT, SLOT, U256::from(3)).unwrap();
            committed.commit();
            assert_eq!(ctx.sload(ACCOUNT, SLOT).unwrap(), U256::from(3));
            assert_eq!(ctx.gas_used(), 0);
        });
        assert!(provider.take_host_error().is_none());
        assert_eq!(evm.state().get_storage(&ACCOUNT, &SLOT), Some(U256::from(3)));
    }

    #[test]
    fn metered_failed_sload_leaves_the_slot_cold() {
        let mut evm = evm();
        let cold = metered_sload_gas(&mut evm, u64::MAX).unwrap();
        let warm = metered_sload_gas(&mut evm, u64::MAX).unwrap();
        assert_eq!((cold, warm), (2_100, 100));

        let mut evm = self::evm();
        assert_eq!(metered_sload_gas(&mut evm, cold - 1), Err(BasePrecompileError::OutOfGas));
        assert_eq!(metered_sload_gas(&mut evm, u64::MAX).unwrap(), cold);
    }

    #[test]
    fn metered_static_context_rejects_writes() {
        let mut evm = evm();
        let message =
            Message::<BaseEvmTypes> { kind: MessageKind::StaticCall, ..Default::default() };
        let mut provider =
            BaseStorageProvider::metered(&mut evm, &message, 1_000_000, StorageFeatures::Legacy);
        assert_eq!(
            provider.sstore(ACCOUNT, SLOT, U256::ONE),
            Err(BasePrecompileError::StaticCallViolation)
        );
        assert_eq!(
            provider.set_code(ACCOUNT, RevmBytecode::new_legacy(Bytes::from_static(&[0xef]))),
            Err(BasePrecompileError::StaticCallViolation)
        );
        assert_eq!(provider.gas_used(), 0);
    }
}
