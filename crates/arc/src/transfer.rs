//! Arc's native USDC transfer rules: the blocklist, the zero address and self-destructed accounts.

use crate::{ArcEvm, ArcEvmTypes, ArcHardfork, NATIVE_COIN_CONTROL_ADDRESS};
use alloy_primitives::{Address, Bytes, keccak256};
use alloy_sol_types::{Revert, SolError};
use evm2::{
    HostError,
    interpreter::{GasTracker, Host, InstrStop, Message, MessageKind, MessageResult, Word},
};

/// Revert reason of a transfer from or to a blocklisted address.
pub const ERR_BLOCKED_ADDRESS: &str = "Blocked address";

/// Revert reason of a value transfer from or to the zero address.
pub const ERR_ZERO_ADDRESS: &str = "Zero address not allowed";

/// Revert reason of a transfer to an account self-destructed in the same transaction.
pub const ERR_SELFDESTRUCTED_BALANCE_INCREASED: &str =
    "Cannot increase the balance of selfdestructed account";

/// Solidity mapping slot of `NativeCoinControl`'s blocklist.
const BLOCKLIST_MAPPING_SLOT: u8 = 2;

/// Returns `reason` ABI-encoded as `Error(string)`.
pub fn revert_reason(reason: &str) -> Bytes {
    Revert::from(reason).abi_encode().into()
}

/// Returns the `NativeCoinControl` storage slot holding the blocklist status of `account`.
pub fn blocklist_slot(account: Address) -> Word {
    let mut preimage = [0u8; 64];
    preimage[12..32].copy_from_slice(account.as_slice());
    preimage[63] = BLOCKLIST_MAPPING_SLOT;
    Word::from_be_bytes(keccak256(preimage).0)
}

/// Reads the blocklist status of `account`, unmetered but warming the slot as arc-node does.
pub(crate) fn is_blocklisted(evm: &mut ArcEvm<'_>, account: Address) -> Result<bool, HostError> {
    let load = evm.sload(&NATIVE_COIN_CONTROL_ADDRESS, &blocklist_slot(account), false)?;
    Ok(!load.value.is_zero())
}

/// Returns why arc-node rejects a value transfer from `from` to `to`, if it does.
pub(crate) fn rejection(
    evm: &mut ArcEvm<'_>,
    from: Address,
    to: Address,
) -> Result<Option<&'static str>, HostError> {
    if from.is_zero() || to.is_zero() {
        return Ok(Some(ERR_ZERO_ADDRESS));
    }
    if is_blocklisted(evm, from)? || is_blocklisted(evm, to)? {
        return Ok(Some(ERR_BLOCKED_ADDRESS));
    }
    // arc-node warms the recipient here before Zero7, and probes it inside a checkpoint after.
    let warm = !evm.config_spec_id().is_active(ArcHardfork::Zero7);
    let mut recipient = evm.state_mut().account(&to)?;
    if warm {
        recipient.warm();
    }
    if recipient.is_destructed() {
        return Ok(Some(ERR_SELFDESTRUCTED_BALANCE_INCREASED));
    }
    Ok(None)
}

/// Returns why arc-node rejects the frame of `message` before running it, if it does.
pub(crate) fn message_rejection(
    evm: &mut ArcEvm<'_>,
    message: &Message<ArcEvmTypes>,
) -> Result<Option<&'static str>, HostError> {
    let moves_value =
        matches!(message.kind, MessageKind::Call | MessageKind::Create | MessageKind::Create2);
    if !moves_value || message.value.is_zero() {
        return Ok(None);
    }
    rejection(evm, message.caller, message.destination)
}

/// Returns the result of a frame arc-node rejects: a revert returning all its gas.
pub(crate) fn rejected_result(
    message: &Message<ArcEvmTypes>,
    reason: &str,
) -> MessageResult<ArcEvmTypes> {
    let mut gas =
        GasTracker::new_with_execution_gas_and_reservoir(message.gas_limit, message.reservoir);
    gas.settle_gas(InstrStop::Revert);
    MessageResult::<ArcEvmTypes> {
        stop: InstrStop::Revert,
        gas,
        output: revert_reason(reason),
        ..Default::default()
    }
}

/// Executes `message`, or reports it as reverted when arc-node rejects its value transfer.
pub(crate) fn execute_message(
    evm: &mut ArcEvm<'_>,
    message: &mut Message<ArcEvmTypes>,
) -> Result<MessageResult<ArcEvmTypes>, HostError> {
    match message_rejection(evm, message)? {
        Some(reason) => {
            let result = rejected_result(message, reason);
            Ok(evm.execute_halted_message(message, result)?)
        }
        None => Ok(evm.execute_message(message)?),
    }
}
