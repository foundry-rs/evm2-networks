//! Monad opcode overlays.
//!
//! Port of `monad-revm` `instructions.rs`, `memory/opcodes.rs` and `page_opcode.rs`:
//!
//! - Every Monad hardfork replaces `CREATE`/`CREATE2` so a delegated (EIP-7702) account cannot
//!   create contracts, and the `CALL` family so a call through an EIP-7702 delegation dispatches to
//!   the precompile at the delegated address (`monad-revm` sets `bytecode_address` to the
//!   delegate).
//! - MonadNine and later replace every memory-expanding opcode with the [MIP-3] linear-cost,
//!   pooled-limit variant.
//! - MonadTen and later replace `SLOAD` and `SSTORE` with the [MIP-8] page-based variants.
//!
//! [MIP-3]: https://mips.monad.xyz/MIPs/MIP-3
//! [MIP-8]: https://mips.monad.xyz/MIPs/MIP-8

use crate::{
    MonadEvmTypes,
    memory::monad_resize_memory,
    page::{self, StoragePageKey},
};
use alloy_primitives::{B256, Bytes, KECCAK256_EMPTY, Log, LogData, keccak256};
use core::{cmp::min, ops::Range};
use evm2::{
    EvmFeatures,
    bytecode::Bytecode,
    constants::CALL_DEPTH_LIMIT,
    interpreter::{
        Gas, Host, InstrStop, InterpreterState, Message, MessageExt, MessageKind, Result, StackMut,
        Word, derive_create_destination,
    },
    utils::WordExt,
    version::GasId,
};
use evm2_macros::instruction;

type State<'s, 'f, 'h> = &'s mut InterpreterState<'f, 'h, MonadEvmTypes>;

/// Resizes memory with the MIP-3 model when `MIP3` is set, or the standard model otherwise.
#[inline]
fn resize<const MIP3: bool>(
    gas: &mut Gas,
    state: State<'_, '_, '_>,
    offset: usize,
    len: usize,
) -> Result {
    if MIP3 {
        monad_resize_memory(gas, state, offset, len)
    } else {
        state.resize_memory(gas, offset, len)
    }
}

#[inline]
const fn require_non_staticcall(state: &InterpreterState<'_, '_, MonadEvmTypes>) -> Result {
    if state.is_static() {
        return Err(InstrStop::StateChangeDuringStaticCall);
    }
    Ok(())
}

/// Copies `len` bytes of `data` into memory after charging copy cost and MIP-3 expansion.
fn mip3_copy(
    gas: &mut Gas,
    state: State<'_, '_, '_>,
    memory_offset: Word,
    data_offset: Word,
    len: usize,
    data: &[u8],
) -> Result {
    gas.spend(state.gas_params().copy_cost(len))?;
    if len == 0 {
        return Ok(());
    }
    let memory_offset = memory_offset.to_usize()?;
    monad_resize_memory(gas, state, memory_offset, len)?;
    state.memory().set_data(memory_offset, data_offset.to_usize_saturated(), len, data);
    Ok(())
}

/// MLOAD with MIP-3 linear memory cost.
#[instruction(EvmTypes = MonadEvmTypes, dynamic_gas)]
pub fn mload(cx: _, [offset]: [Word]) -> Result<out> {
    let offset = offset.to_usize()?;
    monad_resize_memory(cx.gas, cx.state, offset, 32)?;
    *out = cx.state.memory().get_word(offset);
}

/// MSTORE with MIP-3 linear memory cost.
#[instruction(EvmTypes = MonadEvmTypes, dynamic_gas)]
pub fn mstore(cx: _, [offset, value]: [Word]) -> Result {
    let offset = offset.to_usize()?;
    monad_resize_memory(cx.gas, cx.state, offset, 32)?;
    cx.state.memory().set(offset, &value.to_be_bytes::<32>());
}

/// MSTORE8 with MIP-3 linear memory cost.
#[instruction(EvmTypes = MonadEvmTypes, dynamic_gas)]
pub fn mstore8(cx: _, [offset, value]: [Word]) -> Result {
    let offset = offset.to_usize()?;
    monad_resize_memory(cx.gas, cx.state, offset, 1)?;
    cx.state.memory().set(offset, &[value.byte(0)]);
}

/// MCOPY with MIP-3 linear memory cost.
#[instruction(EvmTypes = MonadEvmTypes, dynamic_gas)]
pub fn mcopy(cx: _, [dst, src, len]: [Word]) -> Result {
    let len = len.to_usize()?;
    cx.gas.spend(cx.state.gas_params().mcopy_cost(len))?;
    if len != 0 {
        let dst = dst.to_usize()?;
        let src = src.to_usize()?;
        monad_resize_memory(cx.gas, cx.state, dst.max(src), len)?;
        cx.state.memory().copy(dst, src, len);
    };
}

/// KECCAK256 with MIP-3 linear memory cost.
#[instruction(EvmTypes = MonadEvmTypes, dynamic_gas)]
pub fn keccak256_mip3(cx: _, [offset, len]: [Word]) -> Result<out> {
    let len = len.to_usize()?;
    cx.gas.spend(cx.state.gas_params().keccak256_word_cost(len))?;
    let hash = if len == 0 {
        KECCAK256_EMPTY
    } else {
        let offset = offset.to_usize()?;
        monad_resize_memory(cx.gas, cx.state, offset, len)?;
        keccak256(cx.state.memory().slice(offset, len))
    };
    *out = Word::from_be_bytes(hash.0);
}

/// CALLDATACOPY with MIP-3 linear memory cost.
#[instruction(EvmTypes = MonadEvmTypes, dynamic_gas)]
pub fn calldatacopy(cx: _, [memory_offset, data_offset, len]: [Word]) -> Result {
    let len = len.to_usize()?;
    let input = cx.state.message().input.clone();
    mip3_copy(cx.gas, cx.state, *memory_offset, *data_offset, len, &input)
}

/// CODECOPY with MIP-3 linear memory cost.
#[instruction(EvmTypes = MonadEvmTypes, dynamic_gas)]
pub fn codecopy(cx: _, [memory_offset, code_offset, len]: [Word]) -> Result {
    let len = len.to_usize()?;
    let code = cx.state.message().code.clone();
    mip3_copy(cx.gas, cx.state, *memory_offset, *code_offset, len, code.original_byte_slice())
}

/// RETURNDATACOPY with MIP-3 linear memory cost.
#[instruction(EvmTypes = MonadEvmTypes, dynamic_gas)]
pub fn returndatacopy(cx: _, [memory_offset, data_offset, len]: [Word]) -> Result {
    let len = len.to_usize()?;
    let data_offset = data_offset.to_usize_saturated();
    if data_offset.saturating_add(len) > cx.state.return_data().len() {
        return Err(InstrStop::OutOfOffset);
    }
    let data = cx.state.return_data().clone();
    mip3_copy(cx.gas, cx.state, *memory_offset, Word::from(data_offset), len, &data)
}

/// EXTCODECOPY with MIP-3 linear memory cost.
#[instruction(EvmTypes = MonadEvmTypes, dynamic_gas)]
pub fn extcodecopy(cx: _, [address, memory_offset, code_offset, len]: [Word]) -> Result {
    let address = address.to_address();
    let len = len.to_usize()?;
    cx.gas.spend(cx.state.gas_params().extcodecopy_cost(len))?;
    let mut memory_offset_usize = 0;
    if len != 0 {
        memory_offset_usize = memory_offset.to_usize()?;
        monad_resize_memory(cx.gas, cx.state, memory_offset_usize, len)?;
    }
    let cold_load_gas = cx.state.gas_params().cold_account_additional_cost();
    let skip_cold_load = cx.gas.remaining() < cold_load_gas;
    let account = cx
        .state
        .host()
        .load_account(&address, true, skip_cold_load)
        .map_err(|error| cx.state.fail(error))?;
    if account.is_cold {
        cx.gas.spend(cold_load_gas)?;
    }
    let code = account.code.original_byte_slice();
    let code_offset = min(code_offset.to_usize_saturated(), code.len());
    cx.state.memory().set_data(memory_offset_usize, code_offset, len, code);
}

/// LOG0 to LOG4 with MIP-3 linear memory cost.
#[instruction(EvmTypes = MonadEvmTypes, no_stack_preamble, dynamic_gas)]
pub fn log<const N: usize>(cx: _) -> Result {
    require_non_staticcall(cx.state)?;
    let [offset, len] = stack.popn()?;
    let len = len.to_usize()?;
    cx.gas.spend(cx.state.gas_params().log_cost(N as u8, len))?;
    let data = if len == 0 {
        Bytes::new()
    } else {
        let offset = offset.to_usize()?;
        monad_resize_memory(cx.gas, cx.state, offset, len)?;
        Bytes::copy_from_slice(cx.state.memory().slice(offset, len))
    };
    let topics = stack.popn_dyn(N)?.map(|topic| B256::from(topic.to_be_bytes::<32>())).collect();
    let destination = cx.state.message().destination;
    let Some(data) = LogData::new(topics, data) else {
        return Err(InstrStop::StackUnderflow);
    };
    cx.state.host().log(Log { address: destination, data });
    Ok(())
}

#[inline]
fn return_inner(
    gas: &mut Gas,
    state: State<'_, '_, '_>,
    offset: &Word,
    len: &Word,
    result: InstrStop,
) -> Result {
    let len = len.to_usize()?;
    let output = if len != 0 {
        let offset = offset.to_usize()?;
        let Some(end) = offset.checked_add(len) else {
            return Err(InstrStop::MemoryOOG);
        };
        if end > u32::MAX as usize {
            return Err(InstrStop::MemoryLimitOOG);
        }
        monad_resize_memory(gas, state, offset, len)?;
        offset as u32..end as u32
    } else {
        0..0
    };
    state.set_output(output);
    Err(result)
}

/// RETURN with MIP-3 linear memory cost.
#[instruction(EvmTypes = MonadEvmTypes, dynamic_gas)]
pub fn ret(cx: _, [offset, len]: [Word]) -> Result {
    return_inner(cx.gas, cx.state, offset, len, InstrStop::Return)
}

/// REVERT with MIP-3 linear memory cost.
#[instruction(EvmTypes = MonadEvmTypes, dynamic_gas)]
pub fn revert(cx: _, [offset, len]: [Word]) -> Result {
    return_inner(cx.gas, cx.state, offset, len, InstrStop::Revert)
}

// ---------------------------------------------------------------------------
// CALL / CALLCODE / DELEGATECALL / STATICCALL
// ---------------------------------------------------------------------------

#[inline]
const fn should_charge_new_account_gas(
    eip161: bool,
    transfers_value: bool,
    target_is_empty_for_new_account_gas: bool,
) -> bool {
    target_is_empty_for_new_account_gas && (!eip161 || transfers_value)
}

fn resize_memory_range<const MIP3: bool>(
    gas: &mut Gas,
    state: State<'_, '_, '_>,
    offset: Word,
    len: Word,
) -> Result<Range<usize>> {
    let len = len.to_usize()?;
    let offset = if len != 0 {
        let offset = offset.to_usize()?;
        resize::<MIP3>(gas, state, offset, len)?;
        offset
    } else {
        usize::MAX
    };
    Ok(offset..offset + len)
}

fn memory_range_bytes(state: State<'_, '_, '_>, range: Range<usize>) -> Bytes {
    if range.is_empty() {
        return Bytes::new();
    }
    Bytes::copy_from_slice(state.memory().slice(range.start, range.len()))
}

/// Charges account access gas and returns `(gas_limit, state_gas, code, code_address)`.
///
/// Mirrors `load_acc_and_calc_gas_with_bytecode_address`: the resolved EIP-7702 delegate is
/// returned as the code address and precompile dispatch stays enabled.
fn load_acc_and_calc_gas(
    gas: &mut Gas,
    state: State<'_, '_, '_>,
    to: alloy_primitives::Address,
    transfers_value: bool,
    create_empty_account: bool,
    stack_gas_limit: u64,
) -> Result<(u64, u64, Bytecode, alloy_primitives::Address)> {
    if transfers_value {
        gas.spend(state.gas_params().get(GasId::TransferValueCost))?;
    }

    let additional_cold_cost = state.gas_params().cold_account_additional_cost();
    let remaining_gas = gas.remaining();
    let skip_cold_load = remaining_gas < additional_cold_cost;
    let account =
        state.host().load_account(&to, true, skip_cold_load).map_err(|error| state.fail(error))?;

    let mut cost = 0;
    if account.is_cold {
        cost += additional_cold_cost;
    }
    let mut code = account.code;
    let mut code_address = to;
    if state.feature(EvmFeatures::EIP7702)
        && let Some(delegated_address) = code.eip7702_address()
    {
        cost += state.gas_params().get(GasId::WarmStorageReadCost);
        if cost > remaining_gas {
            return Err(InstrStop::OutOfGas);
        }
        let skip_cold_load = remaining_gas < cost.saturating_add(additional_cold_cost);
        let delegated_account = state
            .host()
            .load_account(&delegated_address, true, skip_cold_load)
            .map_err(|error| state.fail(error))?;
        if delegated_account.is_cold {
            cost += additional_cold_cost;
        }
        code = delegated_account.code;
        code_address = delegated_address;
    }
    let features = state.version().features;
    let mut new_account_state_gas = 0;
    if create_empty_account
        && should_charge_new_account_gas(
            features.contains(EvmFeatures::EIP161),
            transfers_value,
            state
                .host()
                .target_is_empty_for_new_account_gas(&to, features)
                .map_err(|error| state.fail(error))?,
        )
    {
        cost += state.gas_params().get(GasId::NewAccountCost);
        if features.contains(EvmFeatures::EIP8037) && transfers_value {
            new_account_state_gas = state.gas_params().new_account_state_gas();
        }
    }
    gas.spend(cost)?;
    gas.spend_state(new_account_state_gas)?;

    let mut gas_limit = if state.feature(EvmFeatures::EIP150) {
        min(state.gas_params().call_stipend_reduction(gas.remaining()), stack_gas_limit)
    } else {
        stack_gas_limit
    };
    gas.spend(gas_limit)?;

    if transfers_value {
        gas_limit = gas_limit.saturating_add(state.gas_params().get(GasId::CallStipend));
    }

    Ok((gas_limit, new_account_state_gas, code, code_address))
}

/// Executes a child message while its memory counts against the pooled limit.
fn execute_child(
    state: State<'_, '_, '_>,
    message: &mut Message<MonadEvmTypes>,
) -> Result<evm2::interpreter::MessageResult<MonadEvmTypes>> {
    let frame_memory = state.memory().len() as u64;
    let host = state.host();
    host.ext_mut().memory_pool_offset += frame_memory;
    let result = host.execute_message(message);
    let host = state.host();
    host.ext_mut().memory_pool_offset -= frame_memory;
    let result = result.map_err(|error| state.fail(error))?;
    if result.stop.is_fatal() {
        return Err(result.stop);
    }
    Ok(result)
}

#[inline(never)]
fn call_inner<const MIP3: bool>(
    mut stack: StackMut<'_>,
    gas: &mut Gas,
    state: State<'_, '_, '_>,
    kind: MessageKind,
) -> Result {
    let has_value = matches!(kind, MessageKind::Call | MessageKind::CallCode);
    let [local_gas_limit, to] = stack.popn::<2>()?;
    let value = if has_value { stack.pop()? } else { Word::ZERO };
    let [input_offset, input_len, return_offset, return_len] = stack.popn::<4>()?;
    let to = to.to_address();
    let has_transfer = !value.is_zero();
    if state.is_static() && kind == MessageKind::Call && has_transfer {
        return Err(InstrStop::CallNotAllowedInsideStatic);
    }

    let local_gas_limit = u64::try_from(local_gas_limit).unwrap_or(u64::MAX);
    let input_range = resize_memory_range::<MIP3>(gas, state, input_offset, input_len)?;
    let return_memory_range = resize_memory_range::<MIP3>(gas, state, return_offset, return_len)?;
    let (gas_limit, new_account_state_gas, code, code_address) = load_acc_and_calc_gas(
        gas,
        state,
        to,
        has_transfer,
        kind == MessageKind::Call,
        local_gas_limit,
    )?;
    let input = memory_range_bytes(state, input_range);

    let current = state.message();
    let (destination, caller, call_value) = match kind {
        MessageKind::Call => (to, current.destination, value),
        MessageKind::CallCode => (current.destination, current.destination, value),
        MessageKind::DelegateCall => (current.destination, current.caller, current.value),
        _ => (to, current.destination, Word::ZERO),
    };
    let mut message = MessageExt {
        kind,
        depth: current.depth.saturating_add(1),
        gas_limit,
        reservoir: gas.reservoir(),
        destination,
        // Monad dispatches precompiles at the delegated address, while evm2 dispatches at the call
        // target.
        call_target: code_address,
        caller,
        input,
        value: call_value,
        code,
        code_address,
        caller_is_static: state.is_static(),
        salt: B256::ZERO,
        ext: (),
        _non_exhaustive: (),
    };

    let result = execute_child(state, &mut message)?;
    gas.merge_child_gas(result.gas, result.stop);
    if new_account_state_gas != 0 && !result.stop.is_success() {
        gas.refill_reservoir(new_account_state_gas);
    }
    let copy_len = min(return_memory_range.len(), result.output.len());
    if copy_len != 0 {
        state.memory().set(return_memory_range.start, &result.output[..copy_len]);
    }
    let success = result.stop.is_success();
    *state.return_data_mut() = result.output;
    stack.push(Word::from(success))
}

/// CALL with Monad delegation dispatch and spec-dependent memory expansion.
#[instruction(EvmTypes = MonadEvmTypes, no_stack_preamble, dynamic_gas)]
pub fn call<const MIP3: bool>(cx: _) -> Result {
    call_inner::<MIP3>(stack, cx.gas, cx.state, MessageKind::Call)
}

/// CALLCODE with Monad delegation dispatch and spec-dependent memory expansion.
#[instruction(EvmTypes = MonadEvmTypes, no_stack_preamble, dynamic_gas)]
pub fn callcode<const MIP3: bool>(cx: _) -> Result {
    call_inner::<MIP3>(stack, cx.gas, cx.state, MessageKind::CallCode)
}

/// DELEGATECALL with Monad delegation dispatch and spec-dependent memory expansion.
#[instruction(EvmTypes = MonadEvmTypes, no_stack_preamble, dynamic_gas)]
pub fn delegatecall<const MIP3: bool>(cx: _) -> Result {
    call_inner::<MIP3>(stack, cx.gas, cx.state, MessageKind::DelegateCall)
}

/// STATICCALL with Monad delegation dispatch and spec-dependent memory expansion.
#[instruction(EvmTypes = MonadEvmTypes, no_stack_preamble, dynamic_gas)]
pub fn staticcall<const MIP3: bool>(cx: _) -> Result {
    call_inner::<MIP3>(stack, cx.gas, cx.state, MessageKind::StaticCall)
}

// ---------------------------------------------------------------------------
// CREATE / CREATE2
// ---------------------------------------------------------------------------

/// CREATE/CREATE2 that rejects creation on behalf of a delegated account.
///
/// Monad matches the C++ client: contract creation is rejected when execution is happening on
/// behalf of an EIP-7702 delegated account.
#[instruction(EvmTypes = MonadEvmTypes, no_stack_preamble, dynamic_gas)]
pub fn create<const IS_CREATE2: bool, const MIP3: bool>(cx: _) -> Result {
    create_inner::<MIP3>(stack, cx.gas, cx.state, IS_CREATE2)
}

#[inline(never)]
fn create_inner<const MIP3: bool>(
    mut stack: StackMut<'_>,
    gas: &mut Gas,
    state: State<'_, '_, '_>,
    is_create2: bool,
) -> Result {
    require_non_staticcall(state)?;

    let target = state.message().destination;
    let target_account =
        state.host().load_account(&target, true, false).map_err(|error| state.fail(error))?;
    if target_account.code.is_eip7702() {
        return Err(InstrStop::NotActivated);
    }

    let [value, offset, len] = stack.popn::<3>()?;
    let salt = if is_create2 { Some(stack.pop()?) } else { None };

    let len = len.to_usize()?;
    if state.feature(EvmFeatures::EIP3860) {
        if len > state.version().max_initcode_size {
            return Err(InstrStop::CreateInitCodeSizeLimit);
        }
        gas.spend(state.gas_params().initcode_cost(len))?;
    }
    let code_range = resize_memory_range::<MIP3>(gas, state, offset, Word::from(len))?;
    let input = memory_range_bytes(state, code_range);
    let create_cost = if is_create2 {
        state.gas_params().create2_cost(len)
    } else {
        state.gas_params().get(GasId::Create)
    };
    gas.spend(create_cost)?;

    let kind = if is_create2 { MessageKind::Create2 } else { MessageKind::Create };
    let current = state.message();
    let caller = current.destination;
    let depth = current.depth.saturating_add(1);
    let salt = salt.map(|salt| B256::from(salt.to_be_bytes())).unwrap_or_default();

    let caller_info = if is_create2 && !state.feature(EvmFeatures::EIP8037) {
        None
    } else {
        Some(state.host().load_account(&caller, false, false).map_err(|error| state.fail(error))?)
    };
    let destination = derive_create_destination(
        kind,
        &caller,
        &salt,
        &input,
        caller_info.as_ref().map_or(0, |info| info.nonce),
    );

    let mut charged_create_state_gas = false;
    if state.feature(EvmFeatures::EIP8037) {
        if let Some(caller_info) = caller_info.as_ref()
            && (caller_info.balance < value
                || caller_info.nonce == u64::MAX
                || depth > CALL_DEPTH_LIMIT)
        {
            state.clear_return_data();
            stack.push(Word::ZERO)?;
            return Ok(());
        }
        let features = state.version().features;
        if state
            .host()
            .target_is_empty_for_new_account_gas(&destination, features)
            .map_err(|error| state.fail(error))?
        {
            gas.spend_state(state.gas_params().create_state_gas())?;
            charged_create_state_gas = true;
        }
    }
    let gas_limit = if state.feature(EvmFeatures::EIP150) {
        state.gas_params().call_stipend_reduction(gas.remaining())
    } else {
        gas.remaining()
    };
    gas.spend(gas_limit)?;

    let mut message = MessageExt {
        kind,
        depth,
        gas_limit,
        reservoir: gas.reservoir(),
        destination,
        call_target: destination,
        caller,
        code: Bytecode::new_legacy(input.clone()),
        input,
        value,
        code_address: caller,
        caller_is_static: false,
        salt,
        ext: (),
        _non_exhaustive: (),
    };
    let mut result = execute_child(state, &mut message)?;
    gas.merge_child_gas(result.gas, result.stop);

    let create_failed = result.created_address.is_none() || !result.stop.is_success();
    if charged_create_state_gas && create_failed {
        gas.refill_reservoir(state.gas_params().create_state_gas());
    }
    // EIP-211 exposes CREATE failure data only for REVERT; other failures clear returndata.
    if result.stop == InstrStop::Revert {
        *state.return_data_mut() = core::mem::take(&mut result.output);
    } else {
        state.clear_return_data();
    }
    stack.push(result.created_address_for_parent())
}

// ---------------------------------------------------------------------------
// MIP-8 SLOAD / SSTORE
// ---------------------------------------------------------------------------

/// SLOAD with MIP-8 page-based warmth.
#[instruction(EvmTypes = MonadEvmTypes, dynamic_gas)]
pub fn sload(cx: _, [key]: [Word]) -> Result<out> {
    let additional_cold_cost: u64 = cx.state.gas_params().get(GasId::ColdStorageAdditionalCost);
    let skip_cold_load = cx.gas.remaining() < additional_cold_cost;
    let destination = cx.state.message().destination;
    let page_key = StoragePageKey::from_slot(destination, *key);
    let is_cold = !page::is_read_accessed(cx.state.host(), page_key);
    if is_cold && skip_cold_load {
        return Err(InstrStop::OutOfGas);
    }
    let load =
        cx.state.host().sload(&destination, key, false).map_err(|error| cx.state.fail(error))?;
    if is_cold {
        page::mark_read_accessed(cx.state.host(), page_key);
        cx.gas.spend(additional_cold_cost)?;
    }
    *out = load.value;
}

/// SSTORE with MIP-8 page-based gas accounting.
#[instruction(EvmTypes = MonadEvmTypes, dynamic_gas)]
pub fn sstore(cx: _, [key, value]: [Word]) -> Result {
    require_non_staticcall(cx.state)?;
    if cx.state.feature(EvmFeatures::EIP2200)
        && cx.gas.remaining() <= cx.state.gas_params().get(GasId::CallStipend)
    {
        return Err(InstrStop::ReentrancySentryOOG);
    }

    let skip_cold_load = cx.gas.remaining() < cx.state.gas_params().get(GasId::ColdStorageCost);
    let destination = cx.state.message().destination;
    let page_key = StoragePageKey::from_slot(destination, *key);
    let is_cold = !page::is_read_accessed(cx.state.host(), page_key);
    if is_cold && skip_cold_load {
        return Err(InstrStop::OutOfGas);
    }
    let state_load = cx
        .state
        .host()
        .sstore(&destination, key, value, false)
        .map_err(|error| cx.state.fail(error))?;
    if is_cold {
        page::mark_read_accessed(cx.state.host(), page_key);
    }

    let mut gas = page::sstore_gas(cx.state.host(), page_key, &state_load);
    if is_cold {
        gas += cx.state.gas_params().get(GasId::ColdStorageAdditionalCost);
    }
    cx.gas.spend(gas)?;
    Ok(())
}
