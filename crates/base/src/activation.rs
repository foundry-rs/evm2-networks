//! The Beryl activation registry precompile.
//!
//! Port of `base_common_precompiles::ActivationRegistry` and the parts of
//! `base-precompile-storage` it relies on: the namespaced storage layout, the EVM-equivalent gas
//! schedule for storage reads, writes, logs, and code writes (with the Osaka gas parameters the
//! reference's `GasParams::default()` selects), and the mapping of precompile errors to outputs.

use alloy_primitives::{Address, B256, Bytes, KECCAK256_EMPTY, Log, U256, b256, keccak256};
use alloy_sol_types::{Panic, PanicKind, SolCall, SolError, SolEvent, SolInterface, sol};
use base_common_genesis::BaseUpgrade;
use evm2::{
    Evm, SpecId, Version,
    bytecode::Bytecode,
    evm::precompile::PrecompileOutput,
    interpreter::{GasTracker, Host, Message, MessageKind},
    precompiles::{PrecompileError, PrecompileHalt, PrecompileResult},
    version::{GasId, GasParams},
};

use crate::{ActivationAdminConfig, BaseEvmTypes};

sol! {
    /// Activation registry ABI.
    #[allow(missing_docs)]
    interface IActivationRegistry {
        event FeatureActivated(bytes32 indexed feature, address indexed caller);
        event FeatureDeactivated(bytes32 indexed feature, address indexed caller);
        event AdminChanged(
            address indexed previousAdmin,
            address indexed newAdmin,
            address indexed caller
        );

        error Unauthorized(address caller);
        error AlreadyActivated(bytes32 feature);
        error FeatureNotActivated(bytes32 feature);
        error StaticCallNotAllowed();
        error AdminStorageNotEnabled();
        error ZeroAdminAddress();
        error NonPayable();

        function isActivated(bytes32 feature) external view returns (bool);
        function checkActivated(bytes32 feature) external view;
        function admin() external view returns (address);
        function setAdmin(address newAdmin) external;
        function activate(bytes32 feature) external;
        function deactivate(bytes32 feature) external;
    }

    /// Reverted when a native precompile is reached through `DELEGATECALL` or `CALLCODE`.
    #[allow(missing_docs)]
    error DelegateCallNotAllowed();
}

use IActivationRegistry::IActivationRegistryCalls as Call;

/// Precompile id of the activation registry.
pub(crate) const ACTIVATION_REGISTRY_ID: &str = "ActivationRegistry";

/// ERC-7201 root of the `base.activation_registry` storage namespace.
const NAMESPACE_ROOT: U256 = U256::from_be_bytes(
    b256!("0x43ee1bbe25e988521cccd8b2c8fbd38c8287ebff8e074e825a70dfd3885cce00").0,
);
/// Slot of the `features` mapping.
const FEATURES_SLOT: U256 = NAMESPACE_ROOT;
/// Slot of the state-backed `admin` address.
const ADMIN_SLOT: U256 = NAMESPACE_ROOT.wrapping_add(U256::ONE);

/// Gas per 32-byte calldata word charged by native precompile dispatch.
const CALLDATA_WORD_GAS: u64 = 6;
/// Static `LOG` gas.
const LOG_GAS: u64 = 375;
/// Static `KECCAK256` gas.
const KECCAK256_GAS: u64 = 30;
/// Code the registry plants on its own account on the first mutation.
const INITIALIZED_CODE: [u8; 1] = [0xef];

/// Errors of the native precompile storage layer, mirroring
/// `base_precompile_storage::BasePrecompileError`.
#[derive(Debug)]
enum Error {
    Panic(PanicKind),
    OutOfGas,
    UnknownFunctionSelector([u8; 4]),
    AbiDecodeFailed { selector: [u8; 4], error: String },
    StaticCallViolation,
    Revert(Bytes),
    Fatal(PrecompileError),
}

impl Error {
    fn revert(error: impl SolError) -> Self {
        Self::Revert(error.abi_encode().into())
    }
}

type Result<T> = core::result::Result<T, Error>;

/// Execution context of one activation registry call.
struct Ctx<'e, 'a> {
    evm: &'e mut Evm<'a, BaseEvmTypes>,
    address: Address,
    caller: Address,
    is_static: bool,
    params: &'static GasParams,
    limit: u64,
    used: u64,
    refund: i64,
}

impl Ctx<'_, '_> {
    const fn remaining(&self) -> u64 {
        self.limit - self.used
    }

    const fn charge(&mut self, gas: u64) -> Result<()> {
        if self.remaining() < gas {
            return Err(Error::OutOfGas);
        }
        self.used += gas;
        Ok(())
    }

    fn gas(&self, id: GasId) -> u64 {
        self.params.get(id)
    }

    fn sload(&mut self, key: U256) -> Result<U256> {
        let load =
            self.evm.sload(&self.address, &key, false).map_err(|e| Error::Fatal(e.into()))?;
        self.charge(self.gas(GasId::WarmStorageReadCost))?;
        if load.is_cold {
            self.charge(self.gas(GasId::ColdStorageAdditionalCost))?;
        }
        Ok(load.value)
    }

    fn sstore(&mut self, key: U256, value: U256) -> Result<()> {
        if self.is_static {
            return Err(Error::StaticCallViolation);
        }
        // EIP-2200 reentrancy sentry.
        if self.remaining() <= self.gas(GasId::CallStipend) {
            return Err(Error::OutOfGas);
        }
        let store = self
            .evm
            .sstore(&self.address, &key, &value, false)
            .map_err(|e| Error::Fatal(e.into()))?;
        self.charge(self.gas(GasId::SstoreStatic))?;
        self.charge(self.params.sstore_dynamic_gas(true, &store))?;
        self.refund += self.params.sstore_refund(true, &store);
        Ok(())
    }

    fn read_bool(&mut self, key: U256) -> Result<bool> {
        match self.sload(key)? {
            value if value.is_zero() => Ok(false),
            value if value == U256::ONE => Ok(true),
            _ => Err(Error::Panic(PanicKind::EnumConversionError)),
        }
    }

    fn emit(&mut self, event: impl SolEvent) -> Result<()> {
        if self.is_static {
            return Err(Error::StaticCallViolation);
        }
        let data = event.encode_log_data();
        let cost = LOG_GAS + self.params.log_cost(data.topics().len() as u8, data.data.len());
        self.charge(cost)?;
        self.evm.log(Log { address: self.address, data });
        Ok(())
    }

    /// Plants the registry's code marker, charging the code deposit and, for a code-less account,
    /// the create and code-hash costs (`__initialize` and
    /// `EvmPrecompileStorageProvider::set_code`).
    fn initialize(&mut self) -> Result<()> {
        if self.is_static {
            return Err(Error::StaticCallViolation);
        }
        let code = Bytecode::new_legacy(Bytes::from_static(&INITIALIZED_CODE));
        self.charge(self.gas(GasId::CodeDepositCost) * INITIALIZED_CODE.len() as u64)?;
        let address = self.address;
        let code_hash =
            self.evm.state_mut().account(&address).map_err(|e| Error::Fatal(e.into()))?.code_hash();
        if code_hash == KECCAK256_EMPTY || code_hash == B256::ZERO {
            self.charge(self.gas(GasId::Create))?;
            let words = INITIALIZED_CODE.len().div_ceil(32) as u64;
            self.charge(KECCAK256_GAS + self.gas(GasId::Keccak256PerWord) * words)?;
        }
        self.evm
            .state_mut()
            .account(&address)
            .map_err(|e| Error::Fatal(e.into()))?
            .set_code_slow(code);
        Ok(())
    }

    fn feature_slot(feature: B256) -> U256 {
        let mut buf = [0u8; 64];
        buf[..32].copy_from_slice(feature.as_slice());
        buf[32..].copy_from_slice(&FEATURES_SLOT.to_be_bytes::<32>());
        U256::from_be_bytes(keccak256(buf).0)
    }

    fn admin(&mut self, config: ActivationAdminConfig) -> Result<Address> {
        if config.state_enabled {
            let stored = Address::from_slice(&self.sload(ADMIN_SLOT)?.to_be_bytes::<32>()[12..]);
            if !stored.is_zero() {
                return Ok(stored);
            }
        }
        Ok(config.fallback.unwrap_or(Address::ZERO))
    }

    fn require_admin_caller(&mut self, config: ActivationAdminConfig) -> Result<Address> {
        let caller = self.caller;
        if caller.is_zero() {
            return Err(Error::revert(IActivationRegistry::Unauthorized { caller }));
        }
        let admin = self.admin(config)?;
        if admin.is_zero() || caller != admin {
            return Err(Error::revert(IActivationRegistry::Unauthorized { caller }));
        }
        Ok(caller)
    }

    fn set_activated(
        &mut self,
        feature: B256,
        activate: bool,
        config: ActivationAdminConfig,
    ) -> Result<()> {
        if self.is_static {
            return Err(Error::revert(IActivationRegistry::StaticCallNotAllowed {}));
        }
        let caller = self.require_admin_caller(config)?;
        let slot = Self::feature_slot(feature);
        let current = self.read_bool(slot)?;
        if activate && current {
            return Err(Error::revert(IActivationRegistry::AlreadyActivated { feature }));
        }
        if !activate && !current {
            return Err(Error::revert(IActivationRegistry::FeatureNotActivated { feature }));
        }
        if activate {
            self.initialize()?;
            self.sstore(slot, U256::ONE)?;
            self.emit(IActivationRegistry::FeatureActivated { feature, caller })
        } else {
            self.sstore(slot, U256::ZERO)?;
            self.emit(IActivationRegistry::FeatureDeactivated { feature, caller })
        }
    }

    fn set_admin(&mut self, new_admin: Address, config: ActivationAdminConfig) -> Result<()> {
        if self.is_static {
            return Err(Error::revert(IActivationRegistry::StaticCallNotAllowed {}));
        }
        if !config.state_enabled {
            return Err(Error::revert(IActivationRegistry::AdminStorageNotEnabled {}));
        }
        if new_admin.is_zero() {
            return Err(Error::revert(IActivationRegistry::ZeroAdminAddress {}));
        }
        let caller = self.require_admin_caller(config)?;
        self.initialize()?;
        self.sstore(ADMIN_SLOT, U256::from_be_bytes(new_admin.into_word().0))?;
        self.emit(IActivationRegistry::AdminChanged {
            previousAdmin: caller,
            newAdmin: new_admin,
            caller,
        })
    }

    fn dispatch(&mut self, calldata: &[u8], config: ActivationAdminConfig) -> Result<Bytes> {
        let set_admin = IActivationRegistry::setAdminCall::SELECTOR;
        if !config.state_enabled && calldata.get(..4) == Some(set_admin.as_slice()) {
            return Err(Error::UnknownFunctionSelector(set_admin));
        }
        let Some(selector) = calldata.get(..4) else {
            return Err(Error::UnknownFunctionSelector([0; 4]));
        };
        let selector: [u8; 4] = selector.try_into().expect("four bytes");
        let call = match Call::abi_decode_validate(calldata) {
            Ok(call) => call,
            Err(error) if Call::valid_selector(selector) => {
                return Err(Error::AbiDecodeFailed { selector, error: error.to_string() });
            }
            Err(_) => return Err(Error::UnknownFunctionSelector(selector)),
        };
        match call {
            Call::isActivated(call) => {
                let activated = self.read_bool(Self::feature_slot(call.feature))?;
                Ok(IActivationRegistry::isActivatedCall::abi_encode_returns(&activated).into())
            }
            Call::checkActivated(call) => {
                if self.read_bool(Self::feature_slot(call.feature))? {
                    Ok(Bytes::new())
                } else {
                    Err(Error::revert(IActivationRegistry::FeatureNotActivated {
                        feature: call.feature,
                    }))
                }
            }
            Call::activate(call) => {
                self.set_activated(call.feature, true, config).map(|()| Bytes::new())
            }
            Call::deactivate(call) => {
                self.set_activated(call.feature, false, config).map(|()| Bytes::new())
            }
            Call::setAdmin(call) => self.set_admin(call.newAdmin, config).map(|()| Bytes::new()),
            Call::admin(_) => {
                let admin = self.admin(config)?;
                Ok(IActivationRegistry::adminCall::abi_encode_returns(&admin).into())
            }
        }
    }
}

/// Executes the activation registry precompile.
///
/// Mirrors `ActivationRegistryStorage::dispatch_with_observer` wrapped in `base_precompile!`.
pub(crate) fn run_activation_registry(
    evm: &mut Evm<'_, BaseEvmTypes>,
    message: &Message<BaseEvmTypes>,
    gas: &mut GasTracker,
    config: ActivationAdminConfig,
    upgrade: BaseUpgrade,
) -> PrecompileResult {
    // Native precompiles only run as direct calls; `DELEGATECALL` and `CALLCODE` revert at no
    // gas cost.
    if message.destination != message.code_address {
        return Err(PrecompileError::Revert(DelegateCallNotAllowed {}.abi_encode().into()));
    }

    let mut ctx = Ctx {
        evm,
        address: message.code_address,
        caller: message.caller,
        is_static: message.caller_is_static || message.kind == MessageKind::StaticCall,
        params: &Version::base(SpecId::OSAKA).gas_params,
        limit: gas.remaining(),
        used: 0,
        refund: 0,
    };

    // Activation registry selectors are nonpayable from Cobalt on.
    let result = if upgrade as u8 >= BaseUpgrade::Cobalt as u8 && !message.value.is_zero() {
        Err(Error::revert(IActivationRegistry::NonPayable {}))
    } else {
        let words = (message.input.len() as u64).div_ceil(32);
        ctx.charge(words.saturating_mul(CALLDATA_WORD_GAS))
            .and_then(|()| ctx.dispatch(&message.input, config))
    };

    let (used, refund) = (ctx.used, ctx.refund);
    let output = match result {
        Ok(output) => {
            gas.record_refund(refund);
            Ok(PrecompileOutput::new(output))
        }
        Err(Error::OutOfGas) => return Err(PrecompileHalt::OutOfGas.into()),
        Err(Error::Fatal(error)) => return Err(error),
        Err(Error::Revert(bytes)) => Err(PrecompileError::Revert(bytes)),
        Err(Error::Panic(kind)) => Err(PrecompileError::Revert(
            Panic { code: U256::from(kind as u32) }.abi_encode().into(),
        )),
        Err(Error::StaticCallViolation) => Err(PrecompileError::Revert(Bytes::new())),
        Err(Error::UnknownFunctionSelector(selector)) => {
            Err(PrecompileError::Revert(Bytes::copy_from_slice(&selector)))
        }
        Err(Error::AbiDecodeFailed { selector, error }) => {
            let mut bytes = selector.to_vec();
            bytes.extend_from_slice(error.as_bytes());
            Err(PrecompileError::Revert(bytes.into()))
        }
    };
    if gas.spend(used).is_err() {
        return Err(PrecompileHalt::OutOfGas.into());
    }
    output
}
