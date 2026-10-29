//! Native EIP-8130 preparation, phased calls, and settlement.
//!
//! Authentication and account-configuration rules are shared with Base's reference executor.
//! All state access, checkpoints, and call execution use evm2; the reference engine is never run.

use alloy_eips::eip2718::Encodable2718;
use alloy_primitives::{Address, B256, Bytes, TxKind, U256};
use alloy_sol_types::{SolError, sol};
use base_common_consensus::{
    AccountChange, Delegation, Eip8130Constants, Eip8130Contracts, Eip8130Signed, Predeploys,
};
use base_common_eip8130::{IntrinsicGas, IntrinsicGasInput};
use base_common_precompiles::{NonceManagerStorage, TxContextStorage};
use base_execution_eip8130::{
    AccountChangeApplier, AccountConfigurationEvents, AccountConfigurationStorage, ApplyError,
    DelegationEffect, FeeCheck, NonceMode, NonceValidator, TransactionAuthorizer,
};
use base_precompile_storage::{BasePrecompileError, StorageCtx};
use evm2::{
    AnyError, EvmFeatures, TxResult,
    bytecode::Bytecode,
    env::TxEnvExt,
    ethereum::{execute_initial_frame, prepare_initial_frame},
    evm::{
        AccountInfo, DbResult, DynDatabase, EmptyDB, StateCheckpoint, precompile::PrecompileOutput,
    },
    interpreter::{GasTracker, Host, InstrStop, Message, MessageExt, MessageKind},
    precompiles::{PrecompileError, PrecompileResult},
    registry::{HandlerError, HandlerResult, TxRequest},
};
use std::error::Error;

use crate::{
    BaseEvm, BaseEvmFactory, BaseEvmTypes, BasePrecompiles, BaseTxEnvelope, BaseTxHandlerHooks,
    BaseTxResultExt,
    precompiles::{EIP8130_ROOT_ADDRESS, activation_admin_address_for_upgrade_by_chain_id},
    storage::BaseStorageProvider,
};

sol! {
    /// Reverted when a policy-gated actor dispatches to any other target.
    error ActorPolicyViolation(bytes32 actorId, address target);
}

/// Resolved transaction context and metered pre-call work.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct PreparedEip8130 {
    checkpoint: StateCheckpoint,
    encoded: Bytes,
    sender: Address,
    payer: Address,
    actor: B256,
    policy_gated: bool,
    policy_target: Address,
    intrinsic: u64,
    payer_auth: u64,
    pool: u64,
    effective: u128,
    base_fee: u128,
    bump_nonce: bool,
    simulated: bool,
    prepay: U256,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct CallsResult {
    spent: u64,
    refund: i64,
    reverted: bool,
    output: Bytes,
    phases: Vec<u8>,
}

/// Hand-off between an inspected EIP-8130 transaction and its synthetic trace root, see
/// [`EIP8130_ROOT_ADDRESS`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Eip8130Root(RootState);

#[derive(Clone, Debug, PartialEq, Eq)]
enum RootState {
    /// The calls to run under the root, with their call gas pool.
    Pending(Box<(Eip8130Signed, PreparedEip8130, u64)>),
    /// The calls' outcome.
    Done(Box<CallsResult>),
}

fn invalid(error: impl std::fmt::Display) -> HandlerError {
    HandlerError::External(format!("EIP-8130: {error}").into())
}

/// Preserve fatal storage errors through the shared authorization error wrappers.
fn validation_error(error: impl Error + Send + Sync + 'static) -> HandlerError {
    let mut source: &(dyn Error + 'static) = &error;
    loop {
        if matches!(
            source.downcast_ref::<BasePrecompileError>(),
            Some(BasePrecompileError::Fatal(_))
        ) {
            return HandlerError::Fatal(AnyError::new(error));
        }
        let Some(next) = source.source() else { break };
        source = next;
    }
    HandlerError::external(error)
}

/// Applies the pre-call pipeline. The registry's validation entry point runs the same pipeline
/// and discards its writes, without dispatching any calls.
pub(crate) fn prepare_eip8130(
    req: &mut TxRequest<'_, '_, BaseEvmTypes, Eip8130Signed>,
) -> HandlerResult<PreparedEip8130> {
    let signed = *req.tx.inner();
    let tx = signed.tx();
    let host = &mut *req.host;
    let checkpoint = host.state().checkpoint();
    let simulation = match req.envelope {
        BaseTxEnvelope::Eip8130Simulation { sender_actor_id, .. } => Some(*sender_actor_id),
        _ => None,
    };
    let chain_id = host.version().chain_id;
    if simulation.is_none() && tx.chain_id != chain_id {
        return Err(HandlerError::InvalidChainId { expected: chain_id, got: tx.chain_id });
    }
    let now = u64::try_from(host.block().timestamp)
        .map_err(|_| invalid("block timestamp exceeds u64"))?;
    let base_fee =
        u128::try_from(host.block().basefee).map_err(|_| invalid("block base fee exceeds u128"))?;
    let encoded = Bytes::from(signed.encoded_2718());
    let origin = req.tx.signer();
    let mut provider = BaseStorageProvider::unmetered(host, Address::ZERO, origin);
    let prepared = StorageCtx::enter(&mut provider, |ctx| {
        let mut acc = AccountConfigurationStorage::new(ctx);
        let mut nonces = NonceManagerStorage::new(ctx);
        let (sender, payer, actor, policy_gated, policy_target, bump_nonce, input) =
            if let Some(hint) = simulation {
                apply_simulated_changes(ctx, signed, origin, now)?;
                let actor =
                    hint.unwrap_or_else(|| AccountConfigurationStorage::self_actor_id(origin));
                let scope =
                    acc.resolve_actor_config(origin, actor).map_err(validation_error)?.scope;
                let gated = Eip8130Constants::sender_is_policy_gated(scope);
                let target = if gated {
                    acc.get_policy_manager(origin, actor).map_err(validation_error)?
                } else {
                    Address::ZERO
                };
                let nonce = ctx
                    .with_account_info(origin, |info| Ok(info.nonce))
                    .map_err(validation_error)?;
                let first = if tx.nonce_key == Eip8130Constants::NONCE_KEY_MAX {
                    false
                } else if tx.nonce_key.is_zero() {
                    nonce == 0
                } else {
                    nonces.get_nonce(origin, tx.nonce_key).map_err(validation_error)? == 0
                };
                if !tx
                    .account_changes
                    .iter()
                    .any(|change| matches!(change, AccountChange::Delegation(_)))
                {
                    auto_delegate(ctx, origin)?;
                }
                (
                    origin,
                    tx.payer.unwrap_or(origin),
                    actor,
                    gated,
                    target,
                    false,
                    IntrinsicGasInput::worst_case(
                        first,
                        IntrinsicGasInput::sender_auto_delegated(&tx.account_changes),
                        tx.payer.is_some(),
                    ),
                )
            } else {
                let now_ms = now.saturating_mul(1_000);
                if tx.valid_after != 0 && now_ms < tx.valid_after {
                    return Err(invalid("transaction is not yet valid"));
                }
                if tx.valid_before != 0 && now_ms > tx.valid_before {
                    return Err(invalid("transaction validity window has expired"));
                }
                let applied =
                    TransactionAuthorizer::authorize_and_apply(signed, &mut acc, chain_id, now)
                        .map_err(validation_error)?;
                let sender = applied.actors.sender.account;
                let actor = applied.actors.sender.resolved;
                let payer = applied.actors.payer.as_ref().map_or(sender, |p| p.account);
                if !actor.can_use_nonce_key(tx.nonce_key) {
                    return Err(invalid("sender actor scope does not authorize sequenced nonces"));
                }
                if let Some(created) = &applied.applied.created {
                    install_created_code(ctx, created.address, &created.code)?;
                }
                if let Some(delegation) = &applied.applied.delegation {
                    delegation.install(ctx).map_err(validation_error)?;
                }
                let protocol_nonce = ctx
                    .with_account_info(sender, |info| Ok(info.nonce))
                    .map_err(validation_error)?;
                let (first, bump) = if tx.nonce_key == Eip8130Constants::NONCE_KEY_MAX {
                    NonceValidator::validate(
                        tx,
                        sender,
                        protocol_nonce,
                        &nonces,
                        NonceMode::Inclusion,
                        now_ms,
                    )
                    .map_err(validation_error)?;
                    nonces
                        .check_and_mark_expiring_nonce(
                            NonceValidator::replay_hash(tx, sender),
                            tx.valid_before,
                        )
                        .map_err(validation_error)?;
                    (false, false)
                } else if tx.nonce_key.is_zero() {
                    NonceValidator::validate(
                        tx,
                        sender,
                        protocol_nonce,
                        &nonces,
                        NonceMode::Inclusion,
                        now_ms,
                    )
                    .map_err(validation_error)?;
                    (protocol_nonce == 0, true)
                } else {
                    let current =
                        nonces.get_nonce(sender, tx.nonce_key).map_err(validation_error)?;
                    NonceValidator::validate_sequence(tx, current, NonceMode::Inclusion)
                        .map_err(validation_error)?;
                    nonces.increment_nonce(sender, tx.nonce_key).map_err(validation_error)?;
                    (current == 0, false)
                };
                let auto =
                    if applied.applied.delegation.is_some() || applied.applied.created.is_some() {
                        false
                    } else {
                        auto_delegate(ctx, sender)?
                    };
                let payer_gated = applied
                    .actors
                    .payer
                    .as_ref()
                    .is_some_and(|actor| actor.resolved.is_policy_gated());
                (
                    sender,
                    payer,
                    actor.actor_id,
                    actor.is_policy_gated(),
                    actor.policy_target,
                    bump,
                    IntrinsicGasInput::new(first, auto)
                        .with_policy_gates(actor.is_policy_gated(), payer_gated)
                        .with_revoke_discount_slots(applied.revoke_discount_slots),
                )
            };
        let intrinsic =
            IntrinsicGas::compute(signed, &encoded, &input).map_err(validation_error)?;
        let pool = intrinsic
            .execution_gas_available(tx.gas_limit)
            .ok_or_else(|| invalid("EIP-8130 sender-intrinsic gas exceeds the gas limit"))?;
        if simulation.is_none() {
            FeeCheck::validate_fees(tx.max_fee_per_gas, tx.max_priority_fee_per_gas, base_fee)
                .map_err(validation_error)?;
            let balance =
                ctx.with_account_info(payer, |info| Ok(info.balance)).map_err(validation_error)?;
            FeeCheck::validate_balance(
                balance,
                tx.gas_limit,
                intrinsic.payer_auth,
                tx.max_fee_per_gas,
            )
            .map_err(validation_error)?;
        }
        TxContextStorage::new(ctx).set_context(sender, payer, actor).map_err(validation_error)?;
        Ok(PreparedEip8130 {
            checkpoint,
            encoded: encoded.clone(),
            sender,
            payer,
            actor,
            policy_gated,
            policy_target,
            intrinsic: intrinsic.sender_intrinsic(),
            payer_auth: intrinsic.payer_auth,
            pool,
            effective: FeeCheck::effective_gas_price(
                tx.max_fee_per_gas,
                tx.max_priority_fee_per_gas,
                base_fee,
            ),
            base_fee,
            bump_nonce,
            simulated: simulation.is_some(),
            prepay: U256::ZERO,
        })
    });
    if let Some(error) = provider.take_host_error() {
        return Err(error.into());
    }
    let mut prepared = prepared?;
    if !prepared.simulated {
        BaseTxHandlerHooks::load_l1_block_info(host)?;
        host.ext_mut().clear_tx_l1_cost();
        if prepared.bump_nonce && !host.state_mut().account(&prepared.sender)?.bump_nonce() {
            return Err(HandlerError::NonceOverflow);
        }
        prepared.prepay = prepay(host, signed, &prepared)?;
    }
    // The AA protocol does not prewarm the sender or call targets: its pre-call storage work
    // already loads the accounts it needs. Only the precompile set and coinbase are prewarmed.
    host.warm_precompiles();
    if host.feature(EvmFeatures::EIP3651) {
        let beneficiary = host.block().beneficiary;
        host.state_mut().prewarm(&beneficiary);
    }
    Ok(prepared)
}

/// Executes the calls, retaining earlier committed phases after a later phase reverts.
pub(crate) fn execute_eip8130(
    req: TxRequest<'_, '_, BaseEvmTypes, Eip8130Signed>,
    prepared: PreparedEip8130,
) -> HandlerResult<TxResult<BaseEvmTypes>> {
    let signed = *req.tx.inner();
    let host = req.host;
    host.ext_mut().tx_origin = prepared.sender;
    // Inspectors see the transaction's calls under one root frame, and do not see estimation.
    let inspected = host.inspector().is_some();
    let pool = match (prepared.simulated, inspected) {
        (false, _) => prepared.pool,
        (true, false) => estimate_pool(host, signed, &prepared)?,
        (true, true) => estimate_pool(&mut uninspected_evm(host), signed, &prepared)?,
    };
    let calls = if inspected {
        execute_root(host, signed, &prepared, pool)?
    } else {
        execute_calls(host, signed, &prepared, pool, false)?
    };
    let gas_used = billable_gas(&prepared, &calls, pool);
    let stop = if calls.reverted { InstrStop::Revert } else { InstrStop::Return };
    let output = calls.output.clone();
    let phases = calls.phases;
    let (l1_fee, operator_fee) = if prepared.simulated {
        // Even an accidental `commit` of a simulated envelope must not publish its changes.
        // Logs remain execution output and are retained without firing inspector hooks again.
        let logs = host.logs().to_vec();
        let features = host.version().features;
        host.state_mut().rollback(prepared.checkpoint, features);
        *host.state_mut().logs_mut() = logs;
        (U256::ZERO, U256::ZERO)
    } else {
        settle(host, &prepared, gas_used)?
    };
    host.ext_mut().clear_tx_l1_cost();
    Ok(TxResult::<BaseEvmTypes> {
        status: stop.is_success(),
        total_gas_spent: gas_used,
        stop,
        output,
        ext: BaseTxResultExt {
            l1_fee,
            operator_fee,
            eip8130_phase_statuses: (!prepared.simulated).then_some(phases),
            ..Default::default()
        },
        ..Default::default()
    })
}

fn billable_gas(prepared: &PreparedEip8130, calls: &CallsResult, pool: u64) -> u64 {
    let gross = prepared.intrinsic.saturating_add(calls.spent);
    let refunded = (calls.refund.max(0) as u64).min(gross / 5);
    if prepared.simulated {
        let execution = if calls.reverted { calls.spent } else { pool };
        prepared.intrinsic.saturating_add(execution).saturating_add(prepared.payer_auth)
    } else {
        gross.saturating_sub(refunded).saturating_add(prepared.payer_auth)
    }
}

fn execute_calls(
    host: &mut BaseEvm<'_>,
    signed: &Eip8130Signed,
    prepared: &PreparedEip8130,
    pool: u64,
    under_root: bool,
) -> HandlerResult<CallsResult> {
    let mut remaining = pool;
    let mut refund = 0i64;
    let mut phases = Vec::with_capacity(signed.tx().calls.len());
    *host.tx_env_mut() = TxEnvExt {
        origin: prepared.sender,
        gas_price: U256::from(prepared.effective),
        chain_id: U256::from(host.version().chain_id),
        ..TxEnvExt::default()
    };
    for phase in &signed.tx().calls {
        let checkpoint = host.state().checkpoint();
        let mut phase_refund = 0i64;
        let mut failure = None;
        for call in phase {
            if prepared.policy_gated && call.to != prepared.policy_target {
                failure = Some(
                    ActorPolicyViolation { actorId: prepared.actor, target: call.to }
                        .abi_encode()
                        .into(),
                );
                break;
            }
            // Base's run_call loads and warms the target before opening its EVM frame.
            // Keep that access inside the phase checkpoint, not the transaction prewarm set.
            host.state_mut().account(&call.to)?.warm();
            let mut gas = GasTracker::new(remaining);
            let mut frame = prepare_initial_frame(
                host,
                prepared.sender,
                0,
                TxKind::Call(call.to),
                &call.data,
                U256::ZERO,
                &mut gas,
            )?;
            // Calls under the synthetic root are its children.
            if under_root && let Some(frame) = &mut frame {
                frame.message.depth += 1;
            }
            let result = execute_initial_frame(host, frame, &mut gas, remaining, 0)?;
            remaining = remaining
                .checked_sub(result.gas.spent())
                .ok_or_else(|| invalid("call consumed more gas than the phase pool contained"))?;
            if result.stop.is_success() {
                phase_refund = phase_refund.saturating_add(result.gas.refunded());
            } else {
                failure = Some(result.output);
                break;
            }
        }
        if let Some(output) = failure {
            let features = host.version().features;
            host.state_mut().rollback(checkpoint, features);
            phases.resize(signed.tx().calls.len(), 0);
            return Ok(CallsResult {
                spent: pool - remaining,
                refund,
                reverted: true,
                output,
                phases,
            });
        }
        phases.push(1);
        refund = refund.saturating_add(phase_refund);
    }
    Ok(CallsResult {
        spent: pool - remaining,
        refund,
        reverted: false,
        output: Bytes::new(),
        phases,
    })
}

fn probe(
    host: &mut BaseEvm<'_>,
    signed: &Eip8130Signed,
    prepared: &PreparedEip8130,
    pool: u64,
) -> HandlerResult<CallsResult> {
    let checkpoint = host.state().checkpoint();
    let result = execute_calls(host, signed, prepared, pool, false);
    let features = host.version().features;
    host.state_mut().rollback(checkpoint, features);
    result
}

/// Runs the calls under a synthetic root message, so that inspectors trace them as its children.
fn execute_root(
    host: &mut BaseEvm<'_>,
    signed: &Eip8130Signed,
    prepared: &PreparedEip8130,
    pool: u64,
) -> HandlerResult<CallsResult> {
    *host.tx_env_mut() = TxEnvExt {
        origin: prepared.sender,
        gas_price: U256::from(prepared.effective),
        chain_id: U256::from(host.version().chain_id),
        ..TxEnvExt::default()
    };
    let mut root = MessageExt {
        kind: MessageKind::Call,
        depth: host.version().initial_call_depth,
        caller: prepared.sender,
        destination: EIP8130_ROOT_ADDRESS,
        call_target: EIP8130_ROOT_ADDRESS,
        code_address: EIP8130_ROOT_ADDRESS,
        input: prepared.encoded.clone(),
        gas_limit: signed.tx().gas_limit,
        ..MessageExt::default()
    };
    let pending = Box::new((signed.clone(), prepared.clone(), pool));
    host.ext_mut().eip8130_root = Some(Eip8130Root(RootState::Pending(pending)));
    let result = Host::execute_message(host, &mut root);
    let root = host.ext_mut().eip8130_root.take();
    result?;
    match root {
        Some(Eip8130Root(RootState::Done(calls))) => Ok(*calls),
        // An inspector override skipped the root; the calls still execute.
        _ => execute_calls(host, signed, prepared, pool, false),
    }
}

/// Runs the synthetic EIP-8130 root: the calls of the pending transaction, if any.
pub(crate) fn run_root(
    evm: &mut BaseEvm<'_>,
    message: &Message<BaseEvmTypes>,
    gas: &mut GasTracker,
) -> PrecompileResult {
    let Some(Eip8130Root(RootState::Pending(pending))) = evm.ext_mut().eip8130_root.take() else {
        return Ok(PrecompileOutput::new(Bytes::new()));
    };
    let (signed, prepared, pool) = *pending;
    let calls =
        execute_calls(evm, &signed, &prepared, pool, true).map_err(|error| match error {
            HandlerError::Database(error) => PrecompileError::Database(error),
            HandlerError::Fatal(error) => PrecompileError::Fatal(error),
            error => PrecompileError::Fatal(AnyError::new(error)),
        })?;
    gas.spend(billable_gas(&prepared, &calls, pool).min(message.gas_limit))?;
    let output = calls.output.clone();
    // A revert of the root rolls back its frame; earlier phases that committed must survive it.
    let revert = calls.reverted && calls.phases.iter().all(|status| *status == 0);
    evm.ext_mut().eip8130_root = Some(Eip8130Root(RootState::Done(Box::new(calls))));
    if revert { Err(PrecompileError::Revert(output)) } else { Ok(PrecompileOutput::new(output)) }
}

/// Builds an EVM over `host`'s running state without its inspector, for estimation probes that
/// inspectors must not see. Base's precompiles stand in for the host's.
fn uninspected_evm<'h>(host: &'h mut BaseEvm<'_>) -> BaseEvm<'h> {
    let spec = host.config_spec_id();
    let version = *host.version();
    let block = *host.block();
    let ext = host.ext().clone();
    let snapshot = host.state().snapshot();
    let admin = activation_admin_address_for_upgrade_by_chain_id(version.chain_id, spec.upgrade());
    let factory = BaseEvmFactory::default();
    let mut evm = BaseEvm::new_with_execution_config_and_ext(
        factory.execution_config(spec, version),
        spec,
        block,
        factory.tx_registry(spec),
        EmptyDB::default(),
        BasePrecompiles::new(spec).with_activation_admin_address(admin),
        ext,
    );
    *evm.state_mut() = snapshot.into_state(HostDb(host.database_mut()));
    evm
}

/// Reads through to a host EVM's backing database.
struct HostDb<'h, 'a>(&'h mut (dyn DynDatabase + 'a));

impl DynDatabase for HostDb<'_, '_> {
    fn get_account(&mut self, address: &Address) -> DbResult<Option<AccountInfo>> {
        self.0.get_account(address)
    }

    fn get_code_by_hash(&mut self, code_hash: &B256) -> DbResult<Bytecode> {
        self.0.get_code_by_hash(code_hash)
    }

    fn get_storage(&mut self, address: &Address, key: &U256) -> DbResult<U256> {
        self.0.get_storage(address, key)
    }

    fn get_block_hash(&mut self, number: &U256) -> DbResult<B256> {
        self.0.get_block_hash(number)
    }
}

/// Searches only verified-feasible pools, including the gas retained by nested EIP-150 calls.
fn estimate_pool(
    host: &mut BaseEvm<'_>,
    signed: &Eip8130Signed,
    prepared: &PreparedEip8130,
) -> HandlerResult<u64> {
    let ceiling = probe(host, signed, prepared, prepared.pool)?;
    if ceiling.reverted {
        return Ok(prepared.pool);
    }
    let mut low = ceiling.spent.min(prepared.pool);
    if low >= prepared.pool || !probe(host, signed, prepared, low)?.reverted {
        return Ok(low);
    }
    let mut high = prepared.pool;
    let seed = low.saturating_mul(64) / 63;
    if seed > low && seed < high {
        if probe(host, signed, prepared, seed)?.reverted {
            low = seed;
        } else {
            high = seed;
        }
    }
    for _ in 0..16 {
        if low + 1 >= high || (high - low).saturating_mul(1_000) <= high.saturating_mul(15) {
            break;
        }
        let mid = low + (high - low) / 2;
        if probe(host, signed, prepared, mid)?.reverted {
            low = mid;
        } else {
            high = mid;
        }
    }
    Ok(high)
}

fn prepay(
    host: &mut BaseEvm<'_>,
    signed: &Eip8130Signed,
    prepared: &PreparedEip8130,
) -> HandlerResult<U256> {
    let spec = host.config_spec_id();
    let max_gas = FeeCheck::max_chargeable_gas(signed.tx().gas_limit, prepared.payer_auth);
    let gas = U256::from(max_gas)
        .checked_mul(U256::from(prepared.effective))
        .ok_or_else(|| invalid("gas pre-charge overflow"))?;
    let l1 = host.ext_mut().l1_block_info.calculate_tx_l1_cost(&prepared.encoded, spec);
    let operator =
        host.ext().l1_block_info.operator_fee_charge(&prepared.encoded, U256::from(max_gas), spec);
    let prepay = gas
        .checked_add(l1)
        .and_then(|fee| fee.checked_add(operator))
        .ok_or_else(|| invalid("pre-charge overflow"))?;
    let mut payer = host.state_mut().account(&prepared.payer)?;
    let balance = payer
        .balance()
        .checked_sub(prepay)
        .ok_or_else(|| invalid("payer balance is below the worst-case fee"))?;
    payer.set_balance(balance);
    Ok(prepay)
}

fn settle(
    host: &mut BaseEvm<'_>,
    prepared: &PreparedEip8130,
    gas_used: u64,
) -> HandlerResult<(U256, U256)> {
    let spec = host.config_spec_id();
    let fee = U256::from(gas_used)
        .checked_mul(U256::from(prepared.effective))
        .ok_or_else(|| invalid("fee overflow"))?;
    let base = U256::from(gas_used)
        .checked_mul(U256::from(prepared.base_fee))
        .ok_or_else(|| invalid("base-fee amount overflow"))?;
    let priority = fee.checked_sub(base).ok_or_else(|| invalid("priority amount underflow"))?;
    let l1 = host.ext_mut().l1_block_info.calculate_tx_l1_cost(&prepared.encoded, spec);
    let operator =
        host.ext().l1_block_info.operator_fee_charge(&prepared.encoded, U256::from(gas_used), spec);
    let cost = fee
        .checked_add(l1)
        .and_then(|cost| cost.checked_add(operator))
        .ok_or_else(|| invalid("settled cost overflow"))?;
    let refund = prepared
        .prepay
        .checked_sub(cost)
        .ok_or_else(|| invalid("settled fee exceeds the worst-case pre-charge"))?;
    let beneficiary = host.block().beneficiary;
    for (recipient, amount) in [
        (prepared.payer, refund),
        (Predeploys::BASE_FEE_VAULT, base),
        (beneficiary, priority),
        (Predeploys::L1_FEE_VAULT, l1),
        (Predeploys::OPERATOR_FEE_VAULT, operator),
    ] {
        let mut account = host.state_mut().account(&recipient)?;
        let balance = account
            .balance()
            .checked_add(amount)
            .ok_or_else(|| invalid("fee recipient balance overflow"))?;
        account.set_balance(balance);
    }
    Ok((l1, operator))
}

fn install_created_code(ctx: StorageCtx<'_>, address: Address, code: &Bytes) -> HandlerResult<()> {
    let occupied = ctx
        .with_account_info(address, |info| Ok(!info.is_empty_code_hash() || info.nonce != 0))
        .map_err(validation_error)?;
    if occupied {
        return Err(invalid("create destination already has code or a non-zero nonce"));
    }
    let bytecode =
        revm::state::Bytecode::new_raw_checked(code.clone()).map_err(validation_error)?;
    ctx.set_code(address, bytecode).map_err(validation_error)
}

fn auto_delegate(ctx: StorageCtx<'_>, sender: Address) -> HandlerResult<bool> {
    let codeless = ctx
        .with_account_info(sender, |info| Ok(info.is_empty_code_hash()))
        .map_err(validation_error)?;
    if codeless {
        ctx.set_code(sender, revm::state::Bytecode::new_eip7702(Eip8130Contracts::DEFAULT_ACCOUNT))
            .map_err(validation_error)?;
        AccountConfigurationEvents::emit_delegation_applied(
            ctx,
            sender,
            Eip8130Contracts::DEFAULT_ACCOUNT,
        )
        .map_err(validation_error)?;
    }
    Ok(codeless)
}

fn apply_simulated_changes(
    ctx: StorageCtx<'_>,
    signed: &Eip8130Signed,
    sender: Address,
    now: u64,
) -> HandlerResult<()> {
    let mut acc = AccountConfigurationStorage::new(ctx);
    let mut created = None;
    let mut delegation = None;
    for (index, change) in signed.tx().account_changes.iter().enumerate() {
        match change {
            AccountChange::Create(entry) => {
                if delegation.is_some() {
                    return Err(validation_error(ApplyError::CreateAndDelegation));
                }
                if index != 0 || created.is_some() {
                    return Err(validation_error(ApplyError::InvalidCreatePosition));
                }
                let effect = AccountChangeApplier::apply_create(&mut acc, entry)
                    .map_err(validation_error)?;
                created = Some(effect);
            }
            AccountChange::ConfigChange(change) => {
                AccountChangeApplier::apply_config_change(
                    &mut acc,
                    sender,
                    &change.changes,
                    change.channel,
                    change.sequence,
                    now,
                )
                .map_err(validation_error)?;
            }
            AccountChange::Delegation(Delegation { target }) => {
                if delegation.is_some() {
                    return Err(validation_error(ApplyError::MultipleDelegations));
                }
                if created.is_some() {
                    return Err(validation_error(ApplyError::CreateAndDelegation));
                }
                delegation = Some(DelegationEffect::new(sender, *target));
            }
        }
    }
    if let Some(created) = created {
        install_created_code(ctx, created.address, &created.code)?;
    }
    if let Some(delegation) = delegation {
        delegation.install(ctx).map_err(validation_error)?;
    }
    Ok(())
}
