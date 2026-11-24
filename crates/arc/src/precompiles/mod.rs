//! Arc precompiles: the Ethereum set plus native USDC, system accounting, `callFrom` and PQ.

mod call_from;
mod native_coin_authority;
mod native_coin_control;
mod pq;
mod system_accounting;

pub use call_from::ICallFrom;
pub use native_coin_authority::INativeCoinAuthority;
pub use native_coin_control::INativeCoinControl;
pub use pq::IPQ;
pub use system_accounting::{GasValues, ISystemAccounting};

use crate::{
    ARC_PRECOMPILE_ADDRESSES, ArcEvm, ArcEvmTypes, ArcHardfork, ArcSpecId, CALL_FROM_ADDRESS,
    NATIVE_COIN_AUTHORITY_ADDRESS, NATIVE_COIN_CONTROL_ADDRESS, PQ_ADDRESS,
    SYSTEM_ACCOUNTING_ADDRESS, transfer::revert_reason,
};
use alloc::{borrow::Cow, vec::Vec};
use alloy_primitives::{Address, Bytes, KECCAK256_EMPTY, Log, LogData, U256};
use alloy_sol_types::{SolCall, SolEvent};
use evm2::{
    ExecutionError, HostError, Precompiles,
    evm::{
        PrewarmSet,
        precompile::{PrecompileOutput, PrecompileProvider},
    },
    interpreter::{GasTracker, Host, Message, MessageKind},
    precompiles::{
        MovePrecompileError, Precompile, PrecompileError, PrecompileHalt, PrecompileId,
        PrecompileResult,
    },
};

/// Gas arc-node charges for each balance write of a native transfer.
const BALANCE_WRITE_GAS: u64 = 2_900;
/// Gas arc-node charges for crediting an empty account.
const EMPTY_ACCOUNT_GAS: u64 = 25_000;
/// Gas penalty of early reverts, so that probing a precompile is never free.
const EARLY_REVERT_GAS: u64 = 200;
/// EIP-2929 cold storage read.
const COLD_SLOAD_GAS: u64 = 2_100;
/// EIP-2929 warm storage read.
const WARM_READ_GAS: u64 = 100;
/// EIP-2929 cold account access.
const COLD_ACCOUNT_GAS: u64 = 2_600;
/// EIP-2200 `SSTORE` stipend sentry.
const CALL_STIPEND: u64 = 2_300;
/// EIP-2200 `SSTORE` of a new non-zero slot.
const SSTORE_SET_GAS: u64 = 20_000;
/// EIP-2200 `SSTORE` overwriting a non-zero slot.
const SSTORE_RESET_GAS: u64 = 2_900;

const ERR_EXECUTION_REVERTED: &str = "Execution reverted";
const ERR_INSUFFICIENT_FUNDS: &str = "Insufficient funds";
const ERR_OVERFLOW: &str = "Arithmetic overflow";
pub(super) const ERR_INVALID_CALLER: &str = "Invalid caller";
const ERR_CLEAR_EMPTY: &str = "Cannot clear balance of empty account";
const ERR_DELEGATE_CALL_NOT_ALLOWED: &str = "Delegate call not allowed";
const ERR_STATE_CHANGE_DURING_STATIC_CALL: &str = "State change during static call";

/// Returns Arc's precompiles for `spec`.
pub fn arc_precompiles(spec: ArcSpecId) -> ArcPrecompiles {
    let mut map = Precompiles::<ArcEvmTypes>::base(spec.eth_spec()).as_map().clone();
    map.extend([
        Precompile::new(
            NATIVE_COIN_AUTHORITY_ADDRESS,
            PrecompileId::custom("NATIVE_COIN_AUTHORITY"),
            native_coin_authority::run,
        ),
        Precompile::new(
            NATIVE_COIN_CONTROL_ADDRESS,
            PrecompileId::custom("NATIVE_COIN_CONTROL"),
            native_coin_control::run,
        ),
        Precompile::new(
            SYSTEM_ACCOUNTING_ADDRESS,
            PrecompileId::custom("SYSTEM_ACCOUNTING"),
            system_accounting::run,
        ),
        Precompile::new(PQ_ADDRESS, PrecompileId::custom("PQ"), pq::run),
    ]);
    if spec.is_active(ArcHardfork::Zero7) {
        map.insert(Precompile::new(
            CALL_FROM_ADDRESS,
            PrecompileId::custom("CALL_FROM"),
            call_from::run,
        ));
    }
    ArcPrecompiles(Precompiles::new(Cow::Owned(map)))
}

/// Arc precompile provider; arc-node resolves its own precompiles lazily, so they start cold.
#[derive(Clone, Debug)]
pub struct ArcPrecompiles(Precompiles<ArcEvmTypes>);

impl ArcPrecompiles {
    /// Returns the underlying provider.
    pub const fn inner(&self) -> &Precompiles<ArcEvmTypes> {
        &self.0
    }
}

impl PrecompileProvider<ArcEvmTypes> for ArcPrecompiles {
    fn addresses(&self) -> Vec<Address> {
        self.0.addresses()
    }

    fn warm_addresses(&self, warm: &mut PrewarmSet) {
        for address in self.0.addresses() {
            if !ARC_PRECOMPILE_ADDRESSES.contains(&address) {
                warm.warm(&address);
            }
        }
    }

    fn precompile_ids(&self) -> Vec<(Address, PrecompileId)> {
        self.0.precompile_ids()
    }

    fn contains(&self, address: &Address) -> bool {
        self.0.contains(address)
    }

    fn move_precompiles(
        &mut self,
        moves: &[(Address, Address)],
    ) -> Result<(), MovePrecompileError> {
        self.0.move_precompiles(moves)
    }

    fn execute(
        &mut self,
        evm: &mut ArcEvm<'_>,
        message: &Message<ArcEvmTypes>,
        gas: &mut GasTracker,
    ) -> Option<PrecompileResult> {
        self.0.execute(evm, message, gas)
    }
}

/// Returns an out-of-gas halt.
fn oog() -> PrecompileError {
    PrecompileHalt::OutOfGas.into()
}

/// Charges `cost`, halting out of gas when it cannot be paid.
fn charge(gas: &mut GasTracker, cost: u64) -> Result<(), PrecompileError> {
    gas.spend(cost).map_err(|_| oog())
}

/// Halts out of gas unless `cost` is left, without charging it.
fn require_gas(gas: &GasTracker, cost: u64) -> Result<(), PrecompileError> {
    if gas.remaining() < cost { Err(oog()) } else { Ok(()) }
}

/// Reverts with `reason`, keeping the gas charged so far.
fn revert(reason: &str) -> PrecompileError {
    PrecompileError::Revert(revert_reason(reason))
}

/// Reverts with `reason` after charging the early-revert penalty.
fn early_revert(gas: &mut GasTracker, reason: &str) -> PrecompileError {
    match charge(gas, EARLY_REVERT_GAS) {
        Ok(()) => revert(reason),
        Err(error) => error,
    }
}

/// Converts a host failure into a precompile failure.
fn host_error(error: HostError) -> PrecompileError {
    match error {
        HostError::Halt(stop) => stop.into(),
        HostError::Execution(ExecutionError::Database(error)) => PrecompileError::Database(error),
        HostError::Execution(ExecutionError::Fatal(error)) => PrecompileError::Fatal(error),
    }
}

/// Returns the input of `message` after its selector, or reverts if there is no selector.
fn split_selector<'a>(
    input: &'a [u8],
    gas: &mut GasTracker,
) -> Result<([u8; 4], &'a [u8]), PrecompileError> {
    match input.split_first_chunk::<4>() {
        Some((selector, args)) => Ok((*selector, args)),
        None => Err(early_revert(gas, "Input too short")),
    }
}

/// Decodes the arguments of `C`, reverting with the early-revert penalty on malformed input.
fn decode<C: SolCall>(args: &[u8], gas: &mut GasTracker) -> Result<C, PrecompileError> {
    C::abi_decode_raw_validate(args).map_err(|_| early_revert(gas, ERR_EXECUTION_REVERTED))
}

/// Returns `value` ABI-encoded as the precompile output.
fn output(value: impl alloy_sol_types::SolValue) -> PrecompileResult {
    Ok(PrecompileOutput::new(Bytes::from(value.abi_encode())))
}

/// Returns whether `message` runs in a static context.
fn is_static(message: &Message<ArcEvmTypes>) -> bool {
    message.caller_is_static || message.kind == MessageKind::StaticCall
}

/// Rejects a state change in a static context, consuming all gas.
fn check_static(
    message: &Message<ArcEvmTypes>,
    gas: &mut GasTracker,
) -> Result<(), PrecompileError> {
    if is_static(message) {
        gas.spend_all();
        return Err(revert(ERR_STATE_CHANGE_DURING_STATIC_CALL));
    }
    Ok(())
}

/// Rejects `DELEGATECALL` and `CALLCODE`, with the early-revert penalty from Zero8.
fn check_delegatecall(
    evm: &ArcEvm<'_>,
    message: &Message<ArcEvmTypes>,
    gas: &mut GasTracker,
    precompile: Address,
) -> Result<(), PrecompileError> {
    if message.destination == precompile && message.call_target == precompile {
        return Ok(());
    }
    Err(if evm.config_spec_id().is_active(ArcHardfork::Zero8) {
        early_revert(gas, ERR_DELEGATE_CALL_NOT_ALLOWED)
    } else {
        revert(ERR_DELEGATE_CALL_NOT_ALLOWED)
    })
}

/// Reads a storage slot, charging EIP-2929 gas before a cold load.
fn read(
    evm: &mut ArcEvm<'_>,
    gas: &mut GasTracker,
    address: Address,
    key: U256,
) -> Result<U256, PrecompileError> {
    let skip_cold_load = gas.remaining() < COLD_SLOAD_GAS;
    let load = evm.sload(&address, &key, skip_cold_load).map_err(host_error)?;
    charge(gas, if load.is_cold { COLD_SLOAD_GAS } else { WARM_READ_GAS })?;
    Ok(load.value)
}

/// Writes a storage slot with arc-node's EIP-2200 pricing and no refund.
fn write(
    evm: &mut ArcEvm<'_>,
    gas: &mut GasTracker,
    address: Address,
    key: U256,
    value: U256,
) -> Result<(), PrecompileError> {
    if gas.remaining() <= CALL_STIPEND {
        return Err(oog());
    }
    let skip_cold_load = gas.remaining() < COLD_SLOAD_GAS;
    // A failed charge halts the frame, which rolls the write back.
    let store = evm.sstore(&address, &key, &value, skip_cold_load).map_err(host_error)?;
    if store.is_cold {
        charge(gas, COLD_SLOAD_GAS)?;
    }
    let cost = if store.new_value == store.present_value {
        WARM_READ_GAS
    } else if store.original_value == store.present_value {
        if store.original_value.is_zero() { SSTORE_SET_GAS } else { SSTORE_RESET_GAS }
    } else {
        WARM_READ_GAS
    };
    charge(gas, cost)
}

/// Emits a log from `address`, charging the `LOG` opcode's gas.
fn emit(
    evm: &mut ArcEvm<'_>,
    gas: &mut GasTracker,
    address: Address,
    data: LogData,
) -> Result<(), PrecompileError> {
    let cost = 375 + 375 * data.topics().len() as u64 + 8 * data.data.len() as u64;
    charge(gas, cost)?;
    evm.log(Log { address, data });
    Ok(())
}

/// Emits `event` from `address`.
fn emit_event(
    evm: &mut ArcEvm<'_>,
    gas: &mut GasTracker,
    address: Address,
    event: &impl SolEvent,
) -> Result<(), PrecompileError> {
    emit(evm, gas, address, event.encode_log_data())
}

/// Account fields the native transfer helpers check.
struct LoadedAccount {
    balance: U256,
    nonce: u64,
    code_hash: alloy_primitives::B256,
    is_empty: bool,
    is_destructed: bool,
}

/// Loads `address`, warming it, and charges its EIP-2929 access.
fn load(
    evm: &mut ArcEvm<'_>,
    gas: &mut GasTracker,
    address: Address,
) -> Result<LoadedAccount, PrecompileError> {
    let account = evm.load_account(&address, false, false).map_err(host_error)?;
    let is_destructed = evm.state_mut().account(&address)?.is_destructed();
    charge(gas, if account.is_cold { COLD_ACCOUNT_GAS } else { WARM_READ_GAS })?;
    Ok(LoadedAccount {
        balance: account.balance,
        nonce: account.nonce,
        code_hash: account.code_hash,
        is_empty: account.is_empty,
        is_destructed,
    })
}

/// Checks `account` can pay `amount`; before Zero8 it must also not end up empty.
fn check_can_decrease(
    evm: &ArcEvm<'_>,
    gas: &mut GasTracker,
    account: &LoadedAccount,
    amount: U256,
) -> Result<(), PrecompileError> {
    let Some(balance) = account.balance.checked_sub(amount) else {
        return Err(revert(ERR_INSUFFICIENT_FUNDS));
    };
    if evm.config_spec_id().is_active(ArcHardfork::Zero8) {
        return Ok(());
    }
    let no_code = account.code_hash == KECCAK256_EMPTY || account.code_hash.is_zero();
    if balance.is_zero() && account.nonce == 0 && no_code {
        charge(gas, BALANCE_WRITE_GAS)?;
        return Err(revert(ERR_CLEAR_EMPTY));
    }
    Ok(())
}

/// Charges for crediting `amount` to an empty account.
fn charge_empty_credit(
    gas: &mut GasTracker,
    account: &LoadedAccount,
    amount: U256,
) -> Result<(), PrecompileError> {
    if !amount.is_zero() && account.is_empty {
        charge(gas, EMPTY_ACCOUNT_GAS)?;
    }
    Ok(())
}

/// Moves `amount` of native USDC from `from` to `to`.
fn transfer(
    evm: &mut ArcEvm<'_>,
    gas: &mut GasTracker,
    from: Address,
    to: Address,
    amount: U256,
) -> Result<(), PrecompileError> {
    let sender = load(evm, gas, from)?;
    check_can_decrease(evm, gas, &sender, amount)?;
    charge(gas, BALANCE_WRITE_GAS)?;
    let recipient = load(evm, gas, to)?;
    charge(gas, BALANCE_WRITE_GAS)?;
    if recipient.is_destructed {
        return Err(revert(crate::transfer::ERR_SELFDESTRUCTED_BALANCE_INCREASED));
    }
    charge_empty_credit(gas, &recipient, amount)?;
    if !evm.state_mut().transfer(&from, &to, &amount)? {
        return Err(revert(ERR_INSUFFICIENT_FUNDS));
    }
    Ok(())
}

/// Credits `amount` of native USDC to `to`.
fn increase_balance(
    evm: &mut ArcEvm<'_>,
    gas: &mut GasTracker,
    to: Address,
    amount: U256,
) -> Result<(), PrecompileError> {
    let account = load(evm, gas, to)?;
    if account.is_destructed {
        return Err(revert(crate::transfer::ERR_SELFDESTRUCTED_BALANCE_INCREASED));
    }
    if account.balance.checked_add(amount).is_none() {
        return Err(revert(ERR_OVERFLOW));
    }
    charge(gas, BALANCE_WRITE_GAS)?;
    charge_empty_credit(gas, &account, amount)?;
    evm.state_mut().account(&to)?.add_balance(amount);
    Ok(())
}

/// Debits `amount` of native USDC from `from`.
fn decrease_balance(
    evm: &mut ArcEvm<'_>,
    gas: &mut GasTracker,
    from: Address,
    amount: U256,
) -> Result<(), PrecompileError> {
    let account = load(evm, gas, from)?;
    check_can_decrease(evm, gas, &account, amount)?;
    charge(gas, BALANCE_WRITE_GAS)?;
    evm.state_mut().account(&from)?.set_balance(account.balance - amount);
    Ok(())
}

/// Reads the blocklist status of `account`, metered.
fn is_blocklisted(
    evm: &mut ArcEvm<'_>,
    gas: &mut GasTracker,
    account: Address,
) -> Result<bool, PrecompileError> {
    let status =
        read(evm, gas, NATIVE_COIN_CONTROL_ADDRESS, crate::transfer::blocklist_slot(account))?;
    Ok(!status.is_zero())
}

/// Returns the input of `message`.
fn input(evm: &ArcEvm<'_>, message: &Message<ArcEvmTypes>) -> Bytes {
    Bytes::copy_from_slice(evm.message_input(message))
}

/// Reverts with `reason` unless the caller is `expected`.
fn check_caller(
    message: &Message<ArcEvmTypes>,
    gas: &mut GasTracker,
    expected: Address,
    reason: &str,
) -> Result<(), PrecompileError> {
    if message.caller == expected { Ok(()) } else { Err(early_revert(gas, reason)) }
}
