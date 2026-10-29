//! Deposit transaction execution.

use alloy_primitives::U256;
use base_common_consensus::TxDeposit;
use base_common_genesis::BaseUpgrade;
use evm2::{
    EvmFeatures, TxResult,
    env::TxEnvExt,
    ethereum::{
        execute_initial_frame, finalize_gas, initial_gas_and_reservoir, intrinsic_and_floor_gas,
        prepare_initial_frame, warm_base_accounts,
    },
    evm::StateCheckpoint,
    handler::GasSettlement,
    interpreter::{GasTracker, InstrStop},
    registry::{HandlerResult, TxRequest},
};

use crate::{BaseEvm, BaseEvmTypes, BaseTxResultExt};

/// A deposit after its pre-execution state changes.
#[derive(Debug)]
pub enum PreparedDeposit {
    /// The deposit executes its call or create frame.
    Execute {
        /// Checkpoint taken before any deposit state change, for the failed-deposit rollback.
        checkpoint: StateCheckpoint,
        /// The sender nonce before the deposit.
        nonce: u64,
        /// Intrinsic gas.
        intrinsic: u64,
        /// EIP-7623 calldata floor gas.
        floor_gas: u64,
    },
    /// The deposit fails without executing (a post-Regolith system transaction, or a gas limit
    /// below the intrinsic or floor gas).
    Failed {
        /// Checkpoint taken before any deposit state change, for the failed-deposit rollback.
        checkpoint: StateCheckpoint,
        /// The sender nonce before the deposit.
        nonce: u64,
    },
}

/// Applies a deposit's pre-execution state changes and decides whether it executes.
///
/// Mirrors the deposit branches of `base_common_evm::BaseHandler`:
///
/// - `validate_env`: deposits skip all environment validation (chain id, fee caps, block and
///   per-transaction gas-limit caps, initcode size), except that system transactions are rejected
///   from Regolith on.
/// - `validate_initial_tx_gas`: the gas limit must cover the intrinsic gas and, from Prague, the
///   EIP-7623 floor.
/// - `validate_against_state_and_deduct_caller`: the mint is credited to the sender, no fee is
///   deducted, and with [`EvmFeatures::BALANCE_CHECK`] disabled the balance is raised to at least
///   the value. There are no nonce or EIP-3607 checks.
///
/// A deposit never fails validation: a deposit that cannot execute is prepared as
/// [`PreparedDeposit::Failed`] and becomes a failed deposit at execution.
pub fn prepare_deposit(
    req: &mut TxRequest<'_, '_, BaseEvmTypes, TxDeposit>,
) -> HandlerResult<PreparedDeposit> {
    let tx = *req.tx.inner();
    let host = &mut *req.host;
    let checkpoint = host.state().checkpoint();
    let balance_check = host.feature(EvmFeatures::BALANCE_CHECK);

    let nonce = {
        host.ext_mut().tx_origin = tx.from;
        let mut sender = host.state_mut().account(&tx.from)?;
        let nonce = sender.nonce();
        let mut balance = sender.balance().saturating_add(U256::from(tx.mint));
        if !balance_check {
            balance = balance.max(tx.value);
        }
        sender.set_balance(balance);
        // The reference bumps a call's nonce here and a create's in its create frame. evm2
        // creates the top-level frame from the pre-bump nonce, so it is bumped here for both.
        sender.bump_nonce();
        nonce
    };

    if tx.is_system_transaction && host.config_spec_id().is_enabled_in(BaseUpgrade::Regolith) {
        return Ok(PreparedDeposit::Failed { checkpoint, nonce });
    }

    let version = host.version();
    let (intrinsic, floor_gas) =
        intrinsic_and_floor_gas(version, tx.from, tx.to, &tx.input, 0, 0, tx.value);
    if tx.gas_limit < intrinsic || tx.gas_limit < floor_gas {
        return Ok(PreparedDeposit::Failed { checkpoint, nonce });
    }

    // Pre-warm the sender, destination, coinbase, and precompiles like every transaction.
    host.state_mut().prewarm(&tx.from);
    warm_base_accounts(host, tx.to);

    Ok(PreparedDeposit::Execute { checkpoint, nonce, intrinsic, floor_gas })
}

/// Executes a prepared deposit.
///
/// Deposits are funded on L1: no gas is charged or refunded, the coinbase earns nothing, and no
/// fee vault is credited. A successful or reverted deposit reports its metered gas. A halted
/// deposit becomes a failed deposit ([`failed_deposit`]).
pub fn execute_deposit(
    req: TxRequest<'_, '_, BaseEvmTypes, TxDeposit>,
    prepared: PreparedDeposit,
) -> HandlerResult<TxResult<BaseEvmTypes>> {
    let tx = *req.tx.inner();
    let host = req.host;
    let (checkpoint, nonce, intrinsic, floor_gas) = match prepared {
        PreparedDeposit::Failed { checkpoint, nonce } => {
            return failed_deposit(host, tx, checkpoint, nonce);
        }
        PreparedDeposit::Execute { checkpoint, nonce, intrinsic, floor_gas } => {
            (checkpoint, nonce, intrinsic, floor_gas)
        }
    };

    let (execution_gas_limit, reservoir) =
        initial_gas_and_reservoir(host.version(), tx.gas_limit, intrinsic, 0);
    *host.tx_env_mut() = TxEnvExt {
        origin: tx.from,
        gas_price: U256::ZERO,
        chain_id: U256::from(host.version().chain_id),
        ..TxEnvExt::default()
    };
    let mut tx_gas =
        GasTracker::new_with_execution_gas_and_reservoir(execution_gas_limit, reservoir);
    let frame =
        prepare_initial_frame(host, tx.from, nonce, tx.to, &tx.input, tx.value, &mut tx_gas)?;
    let result = execute_initial_frame(host, frame, &mut tx_gas, execution_gas_limit, reservoir)?;

    // The reference turns a halted deposit into `HaltedDepositPostRegolith`, which its
    // `catch_error` settles as a failed deposit. Its execution result classifies every stop other
    // than success and `REVERT` as a halt, including the revert-class `OutOfFunds` of a value
    // transfer the sender cannot afford.
    if !result.stop.is_success() && result.stop != InstrStop::Revert {
        return failed_deposit(host, tx, checkpoint, nonce);
    }

    let mut result = finalize_gas(
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
    )?;
    result.ext.deposit_nonce = Some(nonce);
    Ok(result)
}

/// Settles a failed deposit.
///
/// Ports `base_common_evm::BaseHandler::catch_error` for deposits: every state change of the
/// transaction is reverted, then the mint is credited and the sender nonce bumped. The result
/// fails, consumes the full gas limit, carries no output or logs, and sets
/// [`BaseTxResultExt::failed_deposit`]. The stop reason is [`InstrStop::OutOfGas`], since the full
/// gas limit is consumed.
pub fn failed_deposit(
    host: &mut BaseEvm<'_>,
    tx: &TxDeposit,
    checkpoint: StateCheckpoint,
    nonce: u64,
) -> HandlerResult<TxResult<BaseEvmTypes>> {
    let features = host.version().features;
    host.state_mut().rollback(checkpoint, features);
    let mut sender = host.state_mut().account(&tx.from)?;
    sender.add_balance(U256::from(tx.mint));
    sender.bump_nonce();
    Ok(TxResult::<BaseEvmTypes> {
        status: false,
        total_gas_spent: tx.gas_limit,
        stop: InstrStop::OutOfGas,
        ext: BaseTxResultExt {
            failed_deposit: true,
            deposit_nonce: Some(nonce),
            ..Default::default()
        },
        ..Default::default()
    })
}
