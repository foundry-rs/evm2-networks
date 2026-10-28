//! CIP-64 fee currencies: the per-block context and the fee-currency contract calls.

use crate::{CeloEvm, fee_currency_directory};
use alloy_primitives::{Address, Bytes, U256, map::HashMap};
use alloy_sol_types::{SolCall, sol};
use evm2::{
    TxResult,
    evm::{JournalEntry, SystemTx},
    registry::HandlerResult,
};

sol! {
    interface IFeeCurrencyDirectory {
        struct CurrencyConfig {
            address oracle;
            uint256 intrinsicGas;
        }

        function getCurrencies() external view returns (address[] memory currencies);
        function getExchangeRate(address token) external view returns (uint256 numerator, uint256 denominator);
        function getCurrencyConfig(address token) external view returns (CurrencyConfig memory);
    }

    interface IFeeCurrency {
        function balanceOf(address account) external view returns (uint256);
        function debitGasFees(address from, uint256 value) external;
        function creditGasFees(
            address from,
            address feeRecipient,
            address gatewayFeeRecipient,
            address communityFund,
            uint256 refund,
            uint256 tipTxFee,
            uint256 gatewayFee,
            uint256 baseTxFee
        ) external;
    }
}

/// A registered fee currency.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct FeeCurrencyInfo {
    /// CELO to currency exchange rate as `(numerator, denominator)`, both non-zero.
    pub exchange_rate: (U256, U256),
    /// Extra intrinsic gas of transactions paying in this currency.
    pub intrinsic_gas: u64,
}

/// The fee currencies registered in the `FeeCurrencyDirectory` at the start of a block.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct FeeCurrencyContext {
    /// Block the context was loaded for.
    pub block: Option<U256>,
    /// Registered currencies.
    pub currencies: HashMap<Address, FeeCurrencyInfo>,
}

impl FeeCurrencyContext {
    /// Returns the registered currency `token`, if any.
    pub fn get(&self, token: &Address) -> Option<&FeeCurrencyInfo> {
        self.currencies.get(token)
    }
}

/// Loads the fee currency context for the current block, unless it is already loaded.
///
/// Like celo-revm, this runs before the first transaction of each block, so the context reflects
/// the state at the start of the block. The directory reads are read-only system calls: they
/// leave no state, warmth or logs behind. A currency whose exchange rate or configuration cannot
/// be read is left out.
pub(crate) fn ensure_fee_currency_context(host: &mut CeloEvm<'_>) -> HandlerResult<()> {
    let number = host.block().number;
    if host.ext().fee_currency_context.block == Some(number) {
        return Ok(());
    }
    let directory = fee_currency_directory(host.version().chain_id);
    let tokens = call_read_only(host, directory, IFeeCurrencyDirectory::getCurrenciesCall {})?
        .unwrap_or_default();
    let mut currencies = HashMap::default();
    for token in tokens {
        let rate = IFeeCurrencyDirectory::getExchangeRateCall { token };
        let Some(rate) = call_read_only(host, directory, rate)?
            .filter(|rate| !rate.numerator.is_zero() && !rate.denominator.is_zero())
        else {
            continue;
        };
        let config = IFeeCurrencyDirectory::getCurrencyConfigCall { token };
        let Some(config) = call_read_only(host, directory, config)? else {
            continue;
        };
        let info = FeeCurrencyInfo {
            exchange_rate: (rate.numerator, rate.denominator),
            intrinsic_gas: config.intrinsicGas.try_into().unwrap_or(u64::MAX),
        };
        currencies.insert(token, info);
    }
    host.ext_mut().fee_currency_context = FeeCurrencyContext { block: Some(number), currencies };
    Ok(())
}

/// Returns `balanceOf(account)` of `token`, read without side effects, or `None` if the call
/// fails.
pub(crate) fn balance_of(
    host: &mut CeloEvm<'_>,
    token: Address,
    account: Address,
) -> HandlerResult<Option<U256>> {
    call_read_only(host, token, IFeeCurrency::balanceOfCall { account })
}

/// Calls `debitGasFees(from, value)` on `token` and keeps its effects in the transaction.
///
/// Like celo-revm, transient storage written by the debit is cleared afterwards.
pub(crate) fn debit_gas_fees(
    host: &mut CeloEvm<'_>,
    token: Address,
    from: Address,
    value: U256,
    gas_limit: u64,
) -> HandlerResult<TxResult<crate::CeloEvmTypes>> {
    let checkpoint = host.state().checkpoint();
    let data = IFeeCurrency::debitGasFeesCall { from, value }.abi_encode();
    let result = system_call(host, token, data.into(), Some(gas_limit))?;
    let owners = host.state().journal()[checkpoint.journal_len()..]
        .iter()
        .filter_map(|entry| match entry {
            JournalEntry::TransientStorageChange { address, .. } => Some(*address),
            _ => None,
        })
        .collect::<Vec<_>>();
    for owner in owners {
        host.state_mut().take_transient_storage(&owner);
    }
    Ok(result)
}

/// Calls `creditGasFees` on `token` and keeps its effects in the transaction.
#[allow(clippy::too_many_arguments)]
pub(crate) fn credit_gas_fees(
    host: &mut CeloEvm<'_>,
    token: Address,
    from: Address,
    fee_recipient: Address,
    community_fund: Address,
    refund: U256,
    tip: U256,
    base_fee: U256,
    gas_limit: u64,
) -> HandlerResult<TxResult<crate::CeloEvmTypes>> {
    let data = IFeeCurrency::creditGasFeesCall {
        from,
        feeRecipient: fee_recipient,
        gatewayFeeRecipient: Address::ZERO,
        communityFund: community_fund,
        refund,
        tipTxFee: tip,
        gatewayFee: U256::ZERO,
        baseTxFee: base_fee,
    }
    .abi_encode();
    system_call(host, token, data.into(), Some(gas_limit))
}

/// Runs `call` on `to` and rolls back every effect, returning the decoded output, or `None` if the
/// call fails or its output does not decode.
///
/// The call runs from [`SYSTEM_ADDRESS`](evm2::evm::SYSTEM_ADDRESS) with the default system call
/// gas limit, like celo-revm's read-only core contract calls.
fn call_read_only<C: SolCall>(
    host: &mut CeloEvm<'_>,
    to: Address,
    call: C,
) -> HandlerResult<Option<C::Return>> {
    // Load the target first: `execute_system_call` prewarms it, and an account loaded while
    // prewarmed keeps its warmth after the prewarm set is restored.
    host.state_mut().account(&to)?;
    let checkpoint = host.state().checkpoint();
    let prewarm_set = host.state().prewarm_set().clone();
    let result = system_call(host, to, call.abi_encode().into(), None);
    let features = host.version().features;
    host.state_mut().rollback(checkpoint, features);
    host.state_mut().set_prewarm_set(prewarm_set);
    let result = result?;
    Ok(result.status.then(|| C::abi_decode_returns(&result.output).ok()).flatten())
}

/// Executes a fee-currency system call in the current transaction.
///
/// With a gas limit the caller is the zero address, as for celo-revm's debit and credit calls;
/// without one it is [`SYSTEM_ADDRESS`](evm2::evm::SYSTEM_ADDRESS) with the default gas limit.
/// Precompiles are warm, as they are in celo-revm, where they stay warm from the previous
/// transaction.
fn system_call(
    host: &mut CeloEvm<'_>,
    to: Address,
    data: Bytes,
    gas_limit: Option<u64>,
) -> HandlerResult<TxResult<crate::CeloEvmTypes>> {
    let mut tx = SystemTx::new(to, data);
    if let Some(gas_limit) = gas_limit {
        tx = tx.with_caller(Address::ZERO).with_gas_limit(gas_limit);
    }
    host.warm_precompiles();
    host.execute_system_call(tx)
}
