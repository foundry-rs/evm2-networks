//! `CallFrom` (Zero7): lets `Memo` and `Multicall3From` call a target as their own sender.

use super::{charge, host_error, input, is_static, oog};
use crate::{ArcEvm, ArcEvmTypes, MEMO_ADDRESS, MULTICALL3_FROM_ADDRESS, transfer::revert_reason};
use alloy_primitives::{B256, U256};
use alloy_sol_types::{SolCall, sol};
use evm2::{
    evm::precompile::PrecompileOutput,
    interpreter::{GasTracker, Host, Message, MessageExt, MessageKind},
    precompiles::{PrecompileError, PrecompileHalt, PrecompileResult},
};

sol! {
    /// `CallFrom` precompile interface.
    interface ICallFrom {
        /// Calls `target` with `data` as `sender`.
        function callFrom(address sender, address target, bytes calldata data) external returns (bool success, bytes memory returnData);
    }
}

/// Gas charged for a rejected dispatch, so that probing is never free.
const DISPATCH_GAS: u64 = 100;
/// Base gas of decoding the call or encoding its result.
const ABI_BASE_GAS: u64 = 100;
/// `COPY` gas per 32-byte word.
const COPY_WORD_GAS: u64 = 3;

/// Gas of decoding or encoding `len` bytes of call data.
const fn abi_gas(len: usize) -> u64 {
    ABI_BASE_GAS.saturating_add((len as u64).div_ceil(32).saturating_mul(COPY_WORD_GAS))
}

/// Reverts with `reason` after charging the dispatch gas, or all gas if it is not left.
fn reject(gas: &mut GasTracker, reason: &str) -> PrecompileError {
    if gas.spend(DISPATCH_GAS).is_err() {
        gas.spend_all();
    }
    PrecompileError::Revert(revert_reason(reason))
}

pub(super) fn run(
    evm: &mut ArcEvm<'_>,
    message: &Message<ArcEvmTypes>,
    gas: &mut GasTracker,
) -> PrecompileResult {
    // arc-node only intercepts calls targeting the precompile; delegated ones run its `0xef` code.
    if matches!(message.kind, MessageKind::DelegateCall | MessageKind::CallCode) {
        gas.spend_all();
        return Err(PrecompileHalt::Other("undefined opcode 0xef".into()).into());
    }
    if message.caller != MEMO_ADDRESS && message.caller != MULTICALL3_FROM_ADDRESS {
        return Err(reject(gas, "unauthorized caller"));
    }
    if message.kind != MessageKind::Call {
        return Err(reject(gas, "subcall precompiles only support CALL scheme"));
    }
    if is_static(message) {
        gas.spend_all();
        return Err(PrecompileError::Revert(revert_reason(
            "subcall precompiles cannot be invoked in static context",
        )));
    }
    if !message.value.is_zero() {
        return Err(reject(gas, "subcall precompiles do not support value transfers"));
    }
    let input = input(evm, message);
    let call = match ICallFrom::callFromCall::abi_decode_validate(&input) {
        Ok(call) => call,
        Err(error) => {
            return Err(reject(gas, &format!("ABI decode error: callFrom: {error}")));
        }
    };
    let overhead = abi_gas(call.data.len());
    if gas.remaining() < overhead {
        return Err(reject(gas, "insufficient gas: gas limit below ABI decode overhead"));
    }
    if call.sender != message.caller && call.sender != evm.tx_env().origin {
        return Err(reject(gas, "sender spoofing requires tx.origin as sender"));
    }
    charge(gas, overhead)?;

    let mut child = MessageExt {
        kind: MessageKind::Call,
        depth: message.depth.saturating_add(1),
        gas_limit: u64::MAX,
        reservoir: 0,
        destination: call.target,
        call_target: call.target,
        caller: call.sender,
        input: call.data.into(),
        value: U256::ZERO,
        code: Default::default(),
        code_address: call.target,
        caller_is_static: false,
        salt: B256::ZERO,
        ext: (),
        _non_exhaustive: (),
    };
    // Charges the target access like `CALL` and forwards all but one 64th of the gas left.
    let result = evm.execute_call(gas, &mut child).map_err(host_error)?;
    let encode_gas = abi_gas(result.output.len());
    if !result.is_success() && !result.stop.is_revert() {
        // A halted child burns the gas kept back, as a halted `CALL` frame would.
        if gas.remaining() < encode_gas {
            return Err(oog());
        }
        gas.spend_all();
    } else {
        charge(gas, encode_gas)?;
    }
    let returns =
        ICallFrom::callFromReturn { success: result.is_success(), returnData: result.output };
    Ok(PrecompileOutput::new(ICallFrom::callFromCall::abi_encode_returns(&returns).into()))
}
