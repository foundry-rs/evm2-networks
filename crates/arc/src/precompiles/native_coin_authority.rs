//! `NativeCoinAuthority`: native USDC mint, burn, transfer and total supply.

use super::{
    check_caller, check_delegatecall, check_static, decode, decrease_balance, early_revert,
    emit_event, increase_balance, input, is_blocklisted, output, read, require_gas, split_selector,
    transfer, write,
};
use crate::{
    ArcEvm, ArcEvmTypes, NATIVE_COIN_AUTHORITY_ADDRESS, NATIVE_FIAT_TOKEN_ADDRESS,
    transfer::{ERR_BLOCKED_ADDRESS, ERR_ZERO_ADDRESS},
};
use alloy_primitives::{Address, U256};
use alloy_sol_types::{SolCall, sol};
use evm2::{
    evm::SYSTEM_ADDRESS,
    interpreter::{GasTracker, Message},
    precompiles::{PrecompileError, PrecompileResult},
};

sol! {
    /// `NativeCoinAuthority` precompile interface.
    interface INativeCoinAuthority {
        /// Mints `amount` to `to`.
        function mint(address to, uint256 amount) external returns (bool);
        /// Burns `amount` from `from`.
        function burn(address from, uint256 amount) external returns (bool);
        /// Moves `amount` from `from` to `to`.
        function transfer(address from, address to, uint256 amount) external returns (bool);
        /// Returns the native USDC total supply.
        function totalSupply() external view returns (uint256 supply);
    }

    /// EIP-7708 native transfer log.
    event Transfer(address indexed from, address indexed to, uint256 value);
}

/// Storage slot of the total supply.
const TOTAL_SUPPLY_SLOT: U256 = U256::from_limbs([2, 0, 0, 0]);
/// Gas `totalSupply` requires upfront.
const TOTAL_SUPPLY_GAS: u64 = 2_100;

const ERR_CANNOT_MINT: &str = "Not enabled native coin minter";
const ERR_CANNOT_BURN: &str = "Not enabled native coin burner";
const ERR_CANNOT_TRANSFER: &str = "Not enabled for native coin transfers";
const ERR_OVERFLOW: &str = "Arithmetic overflow";
const ERR_ZERO_AMOUNT: &str = "Zero amount invalid";

pub(super) fn run(
    evm: &mut ArcEvm<'_>,
    message: &Message<ArcEvmTypes>,
    gas: &mut GasTracker,
) -> PrecompileResult {
    let input = input(evm, message);
    let (selector, args) = split_selector(&input, gas)?;
    match selector {
        INativeCoinAuthority::mintCall::SELECTOR => mint(evm, message, gas, args),
        INativeCoinAuthority::burnCall::SELECTOR => burn(evm, message, gas, args),
        INativeCoinAuthority::transferCall::SELECTOR => move_coins(evm, message, gas, args),
        INativeCoinAuthority::totalSupplyCall::SELECTOR => total_supply(evm, gas, args),
        _ => Err(early_revert(gas, "Invalid selector")),
    }
}

/// Emits the EIP-7708 `Transfer` log of a mint, burn or transfer.
fn log_transfer(
    evm: &mut ArcEvm<'_>,
    gas: &mut GasTracker,
    from: Address,
    to: Address,
    value: U256,
) -> Result<(), PrecompileError> {
    emit_event(evm, gas, SYSTEM_ADDRESS, &Transfer { from, to, value })
}

fn mint(
    evm: &mut ArcEvm<'_>,
    message: &Message<ArcEvmTypes>,
    gas: &mut GasTracker,
    args: &[u8],
) -> PrecompileResult {
    check_static(message, gas)?;
    let INativeCoinAuthority::mintCall { to, amount } = decode(args, gas)?;
    check_caller(message, gas, NATIVE_FIAT_TOKEN_ADDRESS, ERR_CANNOT_MINT)?;
    check_delegatecall(evm, message, gas, NATIVE_COIN_AUTHORITY_ADDRESS)?;
    if to.is_zero() {
        return Err(early_revert(gas, ERR_ZERO_ADDRESS));
    }
    if is_blocklisted(evm, gas, to)? {
        return Err(early_revert(gas, ERR_BLOCKED_ADDRESS));
    }
    if amount.is_zero() {
        return Err(early_revert(gas, ERR_ZERO_AMOUNT));
    }
    let supply = read(evm, gas, NATIVE_COIN_AUTHORITY_ADDRESS, TOTAL_SUPPLY_SLOT)?;
    let Some(supply) = supply.checked_add(amount) else {
        return Err(early_revert(gas, ERR_OVERFLOW));
    };
    write(evm, gas, NATIVE_COIN_AUTHORITY_ADDRESS, TOTAL_SUPPLY_SLOT, supply)?;
    increase_balance(evm, gas, to, amount)?;
    log_transfer(evm, gas, Address::ZERO, to, amount)?;
    output(true)
}

fn burn(
    evm: &mut ArcEvm<'_>,
    message: &Message<ArcEvmTypes>,
    gas: &mut GasTracker,
    args: &[u8],
) -> PrecompileResult {
    check_static(message, gas)?;
    let INativeCoinAuthority::burnCall { from, amount } = decode(args, gas)?;
    check_caller(message, gas, NATIVE_FIAT_TOKEN_ADDRESS, ERR_CANNOT_BURN)?;
    check_delegatecall(evm, message, gas, NATIVE_COIN_AUTHORITY_ADDRESS)?;
    if from.is_zero() {
        return Err(early_revert(gas, ERR_ZERO_ADDRESS));
    }
    if is_blocklisted(evm, gas, from)? {
        return Err(early_revert(gas, ERR_BLOCKED_ADDRESS));
    }
    if amount.is_zero() {
        return Err(early_revert(gas, ERR_ZERO_AMOUNT));
    }
    decrease_balance(evm, gas, from, amount)?;
    let supply = read(evm, gas, NATIVE_COIN_AUTHORITY_ADDRESS, TOTAL_SUPPLY_SLOT)?;
    write(
        evm,
        gas,
        NATIVE_COIN_AUTHORITY_ADDRESS,
        TOTAL_SUPPLY_SLOT,
        supply.saturating_sub(amount),
    )?;
    log_transfer(evm, gas, from, Address::ZERO, amount)?;
    output(true)
}

fn move_coins(
    evm: &mut ArcEvm<'_>,
    message: &Message<ArcEvmTypes>,
    gas: &mut GasTracker,
    args: &[u8],
) -> PrecompileResult {
    check_static(message, gas)?;
    let INativeCoinAuthority::transferCall { from, to, amount } = decode(args, gas)?;
    check_caller(message, gas, NATIVE_FIAT_TOKEN_ADDRESS, ERR_CANNOT_TRANSFER)?;
    check_delegatecall(evm, message, gas, NATIVE_COIN_AUTHORITY_ADDRESS)?;
    if from.is_zero() || to.is_zero() {
        return Err(early_revert(gas, ERR_ZERO_ADDRESS));
    }
    if is_blocklisted(evm, gas, from)? || is_blocklisted(evm, gas, to)? {
        return Err(early_revert(gas, ERR_BLOCKED_ADDRESS));
    }
    if !amount.is_zero() {
        transfer(evm, gas, from, to, amount)?;
        // EIP-7708: a self-transfer emits no log.
        if from != to {
            log_transfer(evm, gas, from, to, amount)?;
        }
    }
    output(true)
}

fn total_supply(evm: &mut ArcEvm<'_>, gas: &mut GasTracker, args: &[u8]) -> PrecompileResult {
    let INativeCoinAuthority::totalSupplyCall {} = decode(args, gas)?;
    require_gas(gas, TOTAL_SUPPLY_GAS)?;
    output(read(evm, gas, NATIVE_COIN_AUTHORITY_ADDRESS, TOTAL_SUPPLY_SLOT)?)
}
