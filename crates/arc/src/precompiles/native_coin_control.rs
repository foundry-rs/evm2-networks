//! `NativeCoinControl`: the native USDC blocklist.

use super::{
    check_caller, check_delegatecall, check_static, decode, early_revert, emit_event, input,
    is_blocklisted, output, require_gas, split_selector, write,
};
use crate::{
    ArcEvm, ArcEvmTypes, ArcHardfork, NATIVE_COIN_CONTROL_ADDRESS, NATIVE_FIAT_TOKEN_ADDRESS,
    transfer::blocklist_slot,
};
use alloy_primitives::{Address, U256};
use alloy_sol_types::{SolCall, sol};
use evm2::{
    interpreter::{GasTracker, Message},
    precompiles::{PrecompileError, PrecompileResult},
};

sol! {
    /// `NativeCoinControl` precompile interface.
    interface INativeCoinControl {
        /// Adds `account` to the blocklist.
        function blocklist(address account) external returns (bool success);
        /// Returns whether `account` is blocklisted.
        function isBlocklisted(address account) external view returns (bool _isBlocklisted);
        /// Removes `account` from the blocklist.
        function unBlocklist(address account) external returns (bool success);
    }

    /// `account` was blocklisted.
    event Blocklisted(address indexed account);
    /// `account` was removed from the blocklist.
    event UnBlocklisted(address indexed account);
}

/// Gas `isBlocklisted` requires upfront.
const IS_BLOCKLISTED_GAS: u64 = 2_100;
/// Gas `blocklist` and `unBlocklist` require upfront: a slot write and a two-topic log.
const UPDATE_GAS: u64 = 2_900 + 375 + 2 * 375;

const ERR_CANNOT_BLOCKLIST: &str = "Not enabled for blocklisting";
const ERR_CANNOT_UNBLOCKLIST: &str = "Not enabled for unblocklisting";

pub(super) fn run(
    evm: &mut ArcEvm<'_>,
    message: &Message<ArcEvmTypes>,
    gas: &mut GasTracker,
) -> PrecompileResult {
    let input = input(evm, message);
    let (selector, args) = split_selector(&input, gas)?;
    match selector {
        INativeCoinControl::blocklistCall::SELECTOR => {
            let INativeCoinControl::blocklistCall { account } =
                decode_update::<INativeCoinControl::blocklistCall>(message, gas, args)?;
            update(evm, message, gas, account, true, ERR_CANNOT_BLOCKLIST)?;
            emit_event(evm, gas, NATIVE_COIN_CONTROL_ADDRESS, &Blocklisted { account })?;
            output(true)
        }
        INativeCoinControl::isBlocklistedCall::SELECTOR => {
            let INativeCoinControl::isBlocklistedCall { account } = decode(args, gas)?;
            require_gas(gas, IS_BLOCKLISTED_GAS)?;
            output(is_blocklisted(evm, gas, account)?)
        }
        INativeCoinControl::unBlocklistCall::SELECTOR => {
            let INativeCoinControl::unBlocklistCall { account } =
                decode_update::<INativeCoinControl::unBlocklistCall>(message, gas, args)?;
            update(evm, message, gas, account, false, ERR_CANNOT_UNBLOCKLIST)?;
            emit_event(evm, gas, NATIVE_COIN_CONTROL_ADDRESS, &UnBlocklisted { account })?;
            output(true)
        }
        _ => Err(early_revert(gas, "Invalid selector")),
    }
}

/// Rejects static calls, then decodes a blocklist update.
fn decode_update<C: SolCall>(
    message: &Message<ArcEvmTypes>,
    gas: &mut GasTracker,
    args: &[u8],
) -> Result<C, PrecompileError> {
    check_static(message, gas)?;
    decode(args, gas)
}

/// Writes the blocklist status of `account` after arc-node's caller and gas checks.
fn update(
    evm: &mut ArcEvm<'_>,
    message: &Message<ArcEvmTypes>,
    gas: &mut GasTracker,
    account: Address,
    blocklisted: bool,
    unauthorized: &str,
) -> Result<(), PrecompileError> {
    check_caller(message, gas, NATIVE_FIAT_TOKEN_ADDRESS, unauthorized)?;
    // Zero8 checks the delegatecall before the gas floor, so its penalty applies.
    let zero8 = evm.config_spec_id().is_active(ArcHardfork::Zero8);
    if zero8 {
        check_delegatecall(evm, message, gas, NATIVE_COIN_CONTROL_ADDRESS)?;
    }
    require_gas(gas, UPDATE_GAS)?;
    if !zero8 {
        check_delegatecall(evm, message, gas, NATIVE_COIN_CONTROL_ADDRESS)?;
    }
    write(evm, gas, NATIVE_COIN_CONTROL_ADDRESS, blocklist_slot(account), U256::from(blocklisted))
}
