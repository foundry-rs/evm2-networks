//! Post-quantum signature verification: SLH-DSA-SHA2-128s.

use super::{charge, early_revert, input, output, revert, split_selector};
use crate::{ArcEvm, ArcEvmTypes};
use alloy_sol_types::{SolCall, sol};
use evm2::{
    interpreter::{GasTracker, Message},
    precompiles::PrecompileResult,
};
use slh_dsa::{Sha2_128s, Signature, VerifyingKey, signature::Verifier};

sol! {
    /// PQ signature verifier precompile interface.
    interface IPQ {
        /// Verifies an SLH-DSA-SHA2-128s signature of `message` under `vk`.
        function verifySlhDsaSha2128s(bytes calldata vk, bytes calldata message, bytes calldata sig) external returns (bool isValid);
    }
}

/// Base gas of a verification.
const VERIFY_BASE_GAS: u64 = 230_000;
/// Gas per 32-byte word of message, the `KECCAK256` word rate.
const MESSAGE_WORD_GAS: u64 = 6;
const VERIFYING_KEY_LEN: usize = 32;
const SIGNATURE_LEN: usize = 7_856;

pub(super) fn run(
    evm: &mut ArcEvm<'_>,
    message: &Message<ArcEvmTypes>,
    gas: &mut GasTracker,
) -> PrecompileResult {
    let input = input(evm, message);
    let (selector, args) = split_selector(&input, gas)?;
    if selector != IPQ::verifySlhDsaSha2128sCall::SELECTOR {
        return Err(early_revert(gas, "Invalid selector"));
    }
    let Ok(call) = IPQ::verifySlhDsaSha2128sCall::abi_decode_raw_validate(args) else {
        return Err(early_revert(gas, "Execution reverted"));
    };
    charge(gas, VERIFY_BASE_GAS)?;
    charge(gas, (call.message.len() as u64).div_ceil(32) * MESSAGE_WORD_GAS)?;
    if call.vk.len() != VERIFYING_KEY_LEN {
        return Err(revert("Invalid verifying key length"));
    }
    if call.sig.len() != SIGNATURE_LEN {
        return Err(revert("Invalid signature length"));
    }
    let Ok(key) = VerifyingKey::<Sha2_128s>::try_from(call.vk.as_ref()) else {
        return Err(revert("Failed to parse verifying key"));
    };
    let Ok(signature) = Signature::<Sha2_128s>::try_from(call.sig.as_ref()) else {
        return Err(revert("Failed to parse signature"));
    };
    output(key.verify(&call.message, &signature).is_ok())
}
