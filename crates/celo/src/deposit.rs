//! Deposit transaction execution.
//!
//! Port of op-revm's deposit handling for the post-Regolith hardforks Celo L2 runs.

use crate::{
    CeloEvm, CeloEvmTypes, CeloTxResultExt, fee_currency::ensure_fee_currency_context,
    handler::CeloTxError,
};
use alloy_primitives::U256;
use evm2::{
    EvmFeatures, TxResult,
    env::TxEnvExt,
    ethereum::{
        execute_initial_frame, finalize_gas, initial_gas_and_reservoir, intrinsic_and_floor_gas,
        prepare_initial_frame, validate_floor_gas, validate_intrinsic_gas, warm_base_accounts,
    },
    handler::GasSettlement,
    interpreter::{GasTracker, InstrStop},
    registry::{HandlerError, HandlerResult, TxRequest},
};
use op_evm2::TxDeposit;

/// Deposit state after preparation.
#[derive(Debug)]
pub(crate) enum PreparedDeposit {
    /// The deposit passed validation; mint and nonce bump are applied.
    Ready { intrinsic: u64, floor_gas: u64, nonce: u64 },
    /// The deposit failed validation and will be included as a failed deposit.
    Failed(HandlerError),
}

/// Prepares a deposit: deposits skip the environment checks (chain ID, gas limit caps, initcode
/// size), but not the intrinsic and floor gas checks, then mint and bump the sender nonce without
/// charging fees.
///
/// A deposit that fails validation is included as a failed deposit. Database and fatal errors
/// propagate.
pub(crate) fn prepare_deposit(
    req: &mut TxRequest<'_, '_, CeloEvmTypes, TxDeposit>,
) -> HandlerResult<PreparedDeposit> {
    // The first transaction of every block is a deposit, so this loads the context from the state
    // at the start of the block.
    ensure_fee_currency_context(req.host)?;
    match try_prepare_deposit(req) {
        Ok(prepared) => Ok(prepared),
        Err(error @ (HandlerError::Database(_) | HandlerError::Fatal(_))) => Err(error),
        Err(error) => Ok(PreparedDeposit::Failed(error)),
    }
}

fn try_prepare_deposit(
    req: &mut TxRequest<'_, '_, CeloEvmTypes, TxDeposit>,
) -> HandlerResult<PreparedDeposit> {
    let tx = req.tx.inner();
    let host = &mut *req.host;
    if tx.is_system_transaction {
        return Err(HandlerError::external(CeloTxError::DepositSystemTxPostRegolith));
    }

    let (intrinsic, floor_gas) =
        intrinsic_and_floor_gas(host.version(), tx.from, tx.to, &tx.input, 0, 0, tx.value);
    validate_intrinsic_gas(tx.gas_limit, intrinsic, 0)?;
    validate_floor_gas(tx.gas_limit, floor_gas)?;

    host.state_mut().prewarm(&tx.from);
    warm_base_accounts(host, tx.to);

    let balance_check = host.feature(EvmFeatures::BALANCE_CHECK);
    let balance_top_up = host.feature(EvmFeatures::BALANCE_TOP_UP);
    let mut caller = host.state_mut().account(&tx.from)?;
    let mut balance = caller.balance().saturating_add(U256::from(tx.mint));
    if !balance_check && balance_top_up {
        // Not consensus critical: used in testing so the value transfer cannot fail.
        balance = balance.max(tx.value);
    }
    caller.set_balance(balance);
    let nonce = caller.nonce();
    caller.bump_nonce();

    Ok(PreparedDeposit::Ready { intrinsic, floor_gas, nonce })
}

/// Executes a prepared deposit.
///
/// Deposits are funded on L1: no gas is charged or refunded, the coinbase earns nothing, and no
/// fee recipient is credited. A deposit whose execution stops with anything but success or
/// `REVERT` becomes a failed deposit, like op-revm, which classifies every other stop (including
/// an unaffordable value transfer) as a halt.
pub(crate) fn execute_deposit(
    req: TxRequest<'_, '_, CeloEvmTypes, TxDeposit>,
    prepared: PreparedDeposit,
) -> HandlerResult<TxResult<CeloEvmTypes>> {
    let tx = req.tx.inner();
    let host = req.host;
    let (intrinsic, floor_gas, nonce) = match prepared {
        PreparedDeposit::Ready { intrinsic, floor_gas, nonce } => (intrinsic, floor_gas, nonce),
        PreparedDeposit::Failed(error) => {
            return failed_deposit(host, tx, InstrStop::OutOfGas, Some(error));
        }
    };

    let (execution_gas_limit, reservoir) =
        initial_gas_and_reservoir(host.version(), tx.gas_limit, intrinsic, 0);
    let tx_env = TxEnvExt {
        origin: tx.from,
        gas_price: U256::ZERO,
        chain_id: U256::from(host.version().chain_id),
        ..TxEnvExt::default()
    };
    let mut tx_gas =
        GasTracker::new_with_execution_gas_and_reservoir(execution_gas_limit, reservoir);
    let frame =
        prepare_initial_frame(host, tx.from, nonce, tx.to, &tx.input, tx.value, &mut tx_gas)?;
    let result =
        execute_initial_frame(host, &tx_env, frame, &mut tx_gas, execution_gas_limit, reservoir)?;
    if !result.stop.is_success() && result.stop != InstrStop::Revert {
        return failed_deposit(host, tx, result.stop, None);
    }

    finalize_gas(
        host,
        GasSettlement {
            caller: tx.from,
            gas_price: U256::ZERO,
            gas_limit: tx.gas_limit,
            floor_gas,
            initial_state_gas: 0,
            state_refund: 0,
            result,
        },
    )
}

/// Discards all changes of a deposit except the sender nonce bump and the mint, and reports it as
/// a failed deposit that consumes its full gas limit.
fn failed_deposit(
    host: &mut CeloEvm<'_>,
    tx: &TxDeposit,
    stop: InstrStop,
    deposit_error: Option<HandlerError>,
) -> HandlerResult<TxResult<CeloEvmTypes>> {
    host.state_mut().clear_transaction_state();
    let mut caller = host.state_mut().account(&tx.from)?;
    caller.bump_nonce();
    caller.add_balance(U256::from(tx.mint));
    Ok(TxResult::<CeloEvmTypes> {
        status: false,
        total_gas_spent: tx.gas_limit,
        stop,
        ext: CeloTxResultExt { failed_deposit: true, deposit_error, ..Default::default() },
        ..Default::default()
    })
}
