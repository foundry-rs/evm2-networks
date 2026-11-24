//! Arc opcode overlays: value-moving opcodes reject the transfers arc-node rejects.

use crate::{
    ArcEvmTypes, ArcHardfork,
    transfer::{self, ERR_BLOCKED_ADDRESS, ERR_SELFDESTRUCTED_BALANCE_INCREASED, ERR_ZERO_ADDRESS},
};
use alloy_primitives::{Address, B256, Bytes};
use core::{cmp::min, ops::Range};
use evm2::{
    EvmFeatures,
    bytecode::Bytecode,
    interpreter::{
        Gas, Host, InstrStop, InterpreterState, Message, MessageExt, MessageKind, MessageResult,
        Pc, Result, StackMut, Word, create_preaccess_failure, derive_create_destination,
        instructions,
        private::{Instruction, InstructionFlags},
    },
    utils::WordExt,
    version::GasId,
};
use evm2_macros::instruction;

type State<'s, 'f, 'h> = &'s mut InterpreterState<'f, 'h, ArcEvmTypes>;

const fn should_charge_new_account_gas(
    eip161: bool,
    transfers_value: bool,
    target_is_empty_for_new_account_gas: bool,
) -> bool {
    target_is_empty_for_new_account_gas && (!eip161 || transfers_value)
}

fn resize_memory_range(
    gas: &mut Gas,
    state: State<'_, '_, '_>,
    offset: Word,
    len: Word,
) -> Result<Range<usize>> {
    let len = len.to_usize()?;
    let offset = if len != 0 {
        let offset = offset.to_usize()?;
        state.resize_memory(gas, offset, len)?;
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

/// Charges `CALL`'s value transfer, account access and new account, and takes the gas it forwards.
fn load_acc_and_calc_gas(
    gas: &mut Gas,
    state: State<'_, '_, '_>,
    to: Address,
    transfers_value: bool,
    stack_gas_limit: u64,
) -> Result<(u64, u64, Bytecode, Address)> {
    let params = state.gas_params();
    let transfer_value_cost = params.get(GasId::TransferValueCost);
    let additional_cold_cost = params.cold_account_additional_cost();
    let warm_cost = params.get(GasId::WarmStorageReadCost);
    let new_account_cost = params.get(GasId::NewAccountCost);
    let new_account_state_gas = params.new_account_state_gas();
    let call_stipend = params.get(GasId::CallStipend);

    if transfers_value {
        gas.spend(transfer_value_cost)?;
    }

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
        cost += warm_cost;
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
    let mut state_gas = 0;
    if should_charge_new_account_gas(
        state.feature(EvmFeatures::EIP161),
        transfers_value,
        account.is_empty_for_new_account_gas,
    ) {
        cost += new_account_cost;
        if state.feature(EvmFeatures::EIP8037) && transfers_value {
            state_gas = new_account_state_gas;
        }
    }
    gas.spend(cost)?;
    gas.spend_state(state_gas)?;

    let mut gas_limit = if state.feature(EvmFeatures::EIP150) {
        min(state.gas_params().call_stipend_reduction(gas.remaining()), stack_gas_limit)
    } else {
        stack_gas_limit
    };
    gas.spend(gas_limit)?;

    if transfers_value {
        gas_limit = gas_limit.saturating_add(call_stipend);
    }

    Ok((gas_limit, state_gas, code, code_address))
}

/// Runs a child message under arc-node's transfer rules.
fn execute_child(
    state: State<'_, '_, '_>,
    message: &mut Message<ArcEvmTypes>,
) -> Result<MessageResult<ArcEvmTypes>> {
    let result = transfer::execute_message(state.host(), message);
    let result = result.map_err(|error| state.fail(error))?;
    if result.stop.is_fatal() {
        return Err(result.stop);
    }
    Ok(result)
}

/// `CALL` rejecting the value transfers arc-node rejects.
#[instruction(EvmTypes = ArcEvmTypes, no_stack_preamble, hooked)]
pub fn call(cx: _) -> Result {
    call_inner(stack, cx.gas, cx.state)
}

#[inline(never)]
fn call_inner(mut stack: StackMut<'_>, gas: &mut Gas, state: State<'_, '_, '_>) -> Result {
    let [local_gas_limit, to, value] = stack.popn::<3>()?;
    let [input_offset, input_len, return_offset, return_len] = stack.popn::<4>()?;
    let to = to.to_address();
    let has_transfer = !value.is_zero();
    if state.is_static() && has_transfer {
        return Err(InstrStop::CallNotAllowedInsideStatic);
    }

    let local_gas_limit = local_gas_limit.saturating_to::<u64>();
    let input_range = resize_memory_range(gas, state, input_offset, input_len)?;
    let return_memory_range = resize_memory_range(gas, state, return_offset, return_len)?;
    let (gas_limit, new_account_state_gas, code, code_address) =
        load_acc_and_calc_gas(gas, state, to, has_transfer, local_gas_limit)?;
    let input = memory_range_bytes(state, input_range);

    let current = state.message();
    let mut message = MessageExt {
        kind: MessageKind::Call,
        depth: current.depth.saturating_add(1),
        gas_limit,
        reservoir: gas.reservoir(),
        destination: to,
        call_target: to,
        caller: current.destination,
        input: input.into(),
        value,
        code,
        code_address,
        caller_is_static: state.is_static(),
        salt: B256::ZERO,
        ext: (),
        _non_exhaustive: (),
    };

    let result = execute_child(state, &mut message)?;
    gas.merge_child_gas(result.gas, result.stop);
    if new_account_state_gas != 0 && !result.is_success() {
        gas.refill_reservoir(new_account_state_gas);
    }
    let copy_len = min(return_memory_range.len(), result.output.len());
    if copy_len != 0 {
        state.memory().set(return_memory_range.start, &result.output[..copy_len]);
    }
    let success = result.is_success();
    *state.return_data_mut() = result.output;
    stack.push_u64(success as u64)
}

/// `CREATE` and `CREATE2` rejecting the value transfers arc-node rejects.
#[instruction(EvmTypes = ArcEvmTypes, no_stack_preamble, hooked)]
pub fn create<const IS_CREATE2: bool>(cx: _) -> Result {
    create_inner(stack, cx.gas, cx.state, IS_CREATE2)
}

#[inline(never)]
fn create_inner(
    mut stack: StackMut<'_>,
    gas: &mut Gas,
    state: State<'_, '_, '_>,
    is_create2: bool,
) -> Result {
    if state.is_static() {
        return Err(InstrStop::StateChangeDuringStaticCall);
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
    let code_range = resize_memory_range(gas, state, offset, Word::from(len))?;
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
    let salt = salt.map(B256::from).unwrap_or_default();

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
        if let Some(caller_info) = caller_info.as_ref() {
            let initial_call_depth = state.host().initial_call_depth();
            if create_preaccess_failure(
                caller_info.balance,
                caller_info.nonce,
                value,
                depth,
                initial_call_depth,
            )
            .is_some()
            {
                state.clear_return_data();
                return stack.push_u64(0);
            }
        }
        if state
            .host()
            .load_account(&destination, false, false)
            .map_err(|error| state.fail(error))?
            .is_empty_for_new_account_gas
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
        input: input.into(),
        value,
        code_address: destination,
        caller_is_static: false,
        salt,
        ext: (),
        _non_exhaustive: (),
    };
    let mut result = execute_child(state, &mut message)?;
    gas.merge_child_gas(result.gas, result.stop);

    let create_failed = result.created_address.is_none() || !result.is_success();
    if charged_create_state_gas && create_failed {
        gas.refill_reservoir(state.gas_params().create_state_gas());
    }
    // EIP-211 exposes CREATE failure data only for REVERT; other failures clear returndata.
    if result.stop.is_revert() {
        *state.return_data_mut() = core::mem::take(&mut result.output);
    } else {
        state.clear_return_data();
    }
    stack.push(result.created_address_for_parent())
}

/// `SELFDESTRUCT` with arc-node's checks on the beneficiary of a non-zero balance.
#[derive(Debug)]
pub struct ArcSelfDestruct(());

impl Instruction<ArcEvmTypes> for ArcSelfDestruct {
    const FLAGS: InstructionFlags = InstructionFlags::DYNAMIC_GAS;

    fn execute(pc: &mut Pc, stack: StackMut<'_>, state: State<'_, '_, '_>) -> Result {
        if let Some(target) = stack.peek(0) {
            check_selfdestruct(state, target.to_address())?;
        }
        instructions::selfdestruct::<ArcEvmTypes>::execute(pc, stack, state)
    }
}

/// Ends the frame with a revert carrying `reason`, keeping its gas, as arc-node does.
fn revert_frame(state: State<'_, '_, '_>, reason: &str) -> Result {
    let output = transfer::revert_reason(reason);
    let memory = state.memory();
    let offset = memory.len();
    memory.resize(offset, output.len())?;
    memory.set(offset, &output);
    state.set_output(offset as u32..(offset + output.len()) as u32);
    Err(InstrStop::Revert)
}

/// Applies arc-node's `SELFDESTRUCT` checks before evm2 moves the balance to `target`.
fn check_selfdestruct(state: State<'_, '_, '_>, target: Address) -> Result {
    if state.is_static() {
        return Ok(());
    }
    let contract = state.message().destination;
    let balance = state.host().state_mut().account(&contract).map(|account| account.balance());
    let balance = balance.map_err(|error| state.fail(error))?;
    if balance.is_zero() {
        return Ok(());
    }
    if target.is_zero() {
        return revert_frame(state, ERR_ZERO_ADDRESS);
    }
    if target == contract {
        return Err(InstrStop::Revert);
    }
    let fail_closed = state.host().config_spec_id().is_active(ArcHardfork::Zero7);
    for account in [target, contract] {
        match transfer::is_blocklisted(state.host(), account) {
            Ok(true) => return revert_frame(state, ERR_BLOCKED_ADDRESS),
            Ok(false) => {}
            Err(error) if fail_closed => return Err(state.fail(error)),
            Err(_) => {}
        }
    }
    // A self-destructed account was touched in this transaction, so probing it leaves warmth as is.
    let destructed =
        state.host().state_mut().account(&target).map(|account| account.is_destructed());
    let destructed = destructed.map_err(|error| state.fail(error))?;
    if destructed {
        return revert_frame(state, ERR_SELFDESTRUCTED_BALANCE_INCREASED);
    }
    Ok(())
}
