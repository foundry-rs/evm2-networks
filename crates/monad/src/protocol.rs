//! Replay of canonical Monad protocol system transactions.
//!
//! Monad blocks contain staking syscalls (`syscallReward`, `syscallSnapshot` and
//! `syscallOnEpochChange`) encoded as legacy transactions sent by the reserved
//! [`SYSTEM_ADDRESS`]. Replaying a historical block therefore needs to execute those envelopes as
//! system calls rather than as ordinary user transactions.
//!
//! Replay is opt-in through [`MonadEvmExt::protocol_replay`](crate::MonadEvmExt). When it is
//! enabled, the legacy transaction handler routes envelopes from [`SYSTEM_ADDRESS`] through
//! [`protocol_system_call`] and executes them as follows:
//!
//! 1. The envelope must be canonical: legacy type, a call to [`STAKING_ADDRESS`], zero gas limit
//!    and gas price, and exactly one of the staking syscall ABI encodings with its strict calldata
//!    length. Only `syscallReward` may carry value, which is the block reward.
//! 2. The optional EIP-155 chain ID must match the active chain, and the envelope nonce must match
//!    the system sender's state nonce.
//! 3. The system sender nonce is bumped and, for `syscallReward`, the reward is minted to
//!    [`STAKING_ADDRESS`]. The reward is also appended to the calldata, as
//!    [`syscall_reward_calldata`] does.
//! 4. The call runs through the handler-level [`Evm::execute_system_call`], so an installed
//!    inspector observes it. The result reports zero gas.
//! 5. A reverted or halted syscall is rejected with [`ProtocolSystemCallError::ExecutionFailed`].
//!    Like every rejected transaction, [`Evm::transact`] then discards the whole transaction state,
//!    including the nonce bump and the reward mint.
//!
//! Envelopes from [`SYSTEM_ADDRESS`] of any other transaction type are rejected while replay is
//! enabled. With replay disabled, the default, every transaction keeps the ordinary handler
//! behavior.
//!
//! # Non-goals
//!
//! - Signature or sender trust: the envelope signer is taken as already recovered and trusted. The
//!   caller decides which envelopes may be attributed to [`SYSTEM_ADDRESS`] and owns the signed
//!   bytes and transaction hash.
//! - Block consensus rules: the position, count and ordering of protocol transactions within a
//!   block, epoch boundaries and reward amounts are not validated.
//! - Pool admission: protocol envelopes are not meant for transaction pools, and replay must stay
//!   disabled for ordinary transaction execution and validation.
//! - A custom EIP-2718 transaction type: protocol envelopes are ordinary legacy envelopes.

use crate::{
    MonadEvmTypes, MonadTxEnvelope,
    staking::{STAKING_ADDRESS, constants::SYSTEM_ADDRESS, interface::IMonadStaking::*},
    staking_system_tx, syscall_on_epoch_change_calldata, syscall_reward_calldata,
    syscall_snapshot_calldata,
};
use alloy_consensus::{TxLegacy, transaction::Recovered};
use alloy_eips::eip2718::Typed2718;
use alloy_primitives::{Address, Bytes, TxKind, U256};
use alloy_sol_types::SolCall;
use core::fmt;
use evm2::{
    Evm, TxResult,
    evm::SystemTx,
    interpreter::InstrStop,
    registry::{HandlerError, HandlerResult},
};

/// A canonical Monad protocol system transaction, decoded from its legacy envelope.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProtocolSystemCall {
    /// Reserved protocol caller, [`SYSTEM_ADDRESS`].
    pub caller: Address,
    /// System contract being called, [`STAKING_ADDRESS`].
    pub contract: Address,
    /// Calldata passed to the system call.
    ///
    /// For `syscallReward` the block reward is appended as a 32-byte extension.
    pub data: Bytes,
    /// Sender nonce encoded by the envelope.
    pub nonce: u64,
    /// Optional EIP-155 chain ID encoded by the envelope.
    pub chain_id: Option<u64>,
    /// Protocol mint applied before the system call executes: `(recipient, amount)`.
    pub balance_increment: Option<(Address, U256)>,
}

impl ProtocolSystemCall {
    /// Returns the system call executed for this protocol transaction.
    pub fn system_tx(&self) -> SystemTx {
        staking_system_tx(self.data.clone())
    }

    /// Validates the envelope chain ID, if any, against `chain_id`.
    pub const fn validate_chain_id(&self, chain_id: u64) -> Result<(), ProtocolSystemCallError> {
        if let Some(got) = self.chain_id
            && got != chain_id
        {
            return Err(ProtocolSystemCallError::ChainIdMismatch { expected: chain_id, got });
        }
        Ok(())
    }
}

/// Errors for Monad protocol system transactions.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ProtocolSystemCallError {
    /// The envelope is not a legacy transaction.
    NotLegacy {
        /// EIP-2718 transaction type.
        tx_type: u8,
    },
    /// The envelope does not call the staking contract.
    InvalidTarget(TxKind),
    /// The envelope gas limit is not zero.
    NonZeroGasLimit(u64),
    /// The envelope gas price is not zero.
    NonZeroGasPrice(u128),
    /// The calldata is shorter than a selector.
    MissingSelector,
    /// The selector is not a staking syscall.
    UnknownSelector([u8; 4]),
    /// The calldata length does not match the syscall ABI encoding.
    InvalidCalldataLength {
        /// Syscall selector.
        selector: [u8; 4],
        /// Required calldata length.
        expected: usize,
        /// Envelope calldata length.
        got: usize,
    },
    /// The calldata is not the canonical ABI encoding of the syscall.
    NonCanonicalCalldata {
        /// Syscall selector.
        selector: [u8; 4],
    },
    /// A non-payable syscall carries value.
    NonZeroValue {
        /// Syscall selector.
        selector: [u8; 4],
    },
    /// The envelope chain ID does not match the active chain.
    ChainIdMismatch {
        /// Active chain ID.
        expected: u64,
        /// Envelope chain ID.
        got: u64,
    },
    /// The envelope nonce does not match the system sender's state nonce.
    NonceMismatch {
        /// State nonce.
        expected: u64,
        /// Envelope nonce.
        got: u64,
    },
    /// The system sender nonce cannot be incremented.
    NonceOverflow,
    /// The reward mint overflows the recipient balance.
    BalanceOverflow,
    /// The system call reverted or halted.
    ExecutionFailed {
        /// Interpreter stop reason.
        stop: InstrStop,
        /// Revert output.
        output: Bytes,
    },
}

impl fmt::Display for ProtocolSystemCallError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("invalid Monad protocol system transaction: ")?;
        match self {
            Self::NotLegacy { tx_type } => {
                write!(f, "transaction type must be legacy, got 0x{tx_type:02x}")
            }
            Self::InvalidTarget(_) => f.write_str("target must be the staking contract"),
            Self::NonZeroGasLimit(gas_limit) => {
                write!(f, "gas limit must be zero, got {gas_limit}")
            }
            Self::NonZeroGasPrice(gas_price) => {
                write!(f, "gas price must be zero, got {gas_price}")
            }
            Self::MissingSelector => f.write_str("calldata is shorter than a selector"),
            Self::UnknownSelector(selector) => {
                write!(f, "unknown staking syscall selector {}", Bytes::copy_from_slice(selector))
            }
            Self::InvalidCalldataLength { selector, expected, got } => write!(
                f,
                "calldata for {} must be {expected} bytes, got {got}",
                Bytes::copy_from_slice(selector)
            ),
            Self::NonCanonicalCalldata { selector } => {
                write!(f, "non-canonical calldata for {}", Bytes::copy_from_slice(selector))
            }
            Self::NonZeroValue { selector } => {
                write!(f, "value must be zero for {}", Bytes::copy_from_slice(selector))
            }
            Self::ChainIdMismatch { expected, got } => {
                write!(f, "chain ID mismatch: envelope {got}, environment {expected}")
            }
            Self::NonceMismatch { expected, got } => {
                write!(f, "nonce mismatch: envelope {got}, state {expected}")
            }
            Self::NonceOverflow => f.write_str("nonce overflow"),
            Self::BalanceOverflow => f.write_str("reward mint overflows balance"),
            Self::ExecutionFailed { stop, output } => {
                write!(f, "system call failed with {stop:?}: {output}")
            }
        }
    }
}

impl core::error::Error for ProtocolSystemCallError {}

impl From<ProtocolSystemCallError> for HandlerError {
    fn from(error: ProtocolSystemCallError) -> Self {
        Self::external(error)
    }
}

/// Classifies a recovered Monad envelope as a protocol system transaction.
///
/// Returns `Ok(None)` when the signer is not [`SYSTEM_ADDRESS`], the decoded system call when the
/// envelope is canonical, and an error when an envelope from [`SYSTEM_ADDRESS`] is not canonical.
/// The signer is trusted as given; see the [module documentation](self).
///
/// State-dependent checks (chain ID, nonce and reward mint) are applied at execution.
pub fn protocol_system_call(
    tx: &Recovered<MonadTxEnvelope>,
) -> Result<Option<ProtocolSystemCall>, ProtocolSystemCallError> {
    if tx.signer() != SYSTEM_ADDRESS {
        return Ok(None);
    }
    match tx.inner().as_legacy() {
        Some(legacy) => legacy_protocol_system_call(tx.signer(), legacy),
        None => Err(ProtocolSystemCallError::NotLegacy { tx_type: tx.inner().ty() }),
    }
}

/// Classifies a legacy transaction from `caller` as a protocol system transaction.
pub(crate) fn legacy_protocol_system_call(
    caller: Address,
    tx: &TxLegacy,
) -> Result<Option<ProtocolSystemCall>, ProtocolSystemCallError> {
    if caller != SYSTEM_ADDRESS {
        return Ok(None);
    }
    if tx.to != TxKind::Call(STAKING_ADDRESS) {
        return Err(ProtocolSystemCallError::InvalidTarget(tx.to));
    }
    if tx.gas_limit != 0 {
        return Err(ProtocolSystemCallError::NonZeroGasLimit(tx.gas_limit));
    }
    if tx.gas_price != 0 {
        return Err(ProtocolSystemCallError::NonZeroGasPrice(tx.gas_price));
    }

    let input = &tx.input[..];
    let selector: [u8; 4] = input
        .get(..4)
        .and_then(|selector| selector.try_into().ok())
        .ok_or(ProtocolSystemCallError::MissingSelector)?;
    let check_len = |expected: usize| {
        if input.len() == expected {
            Ok(())
        } else {
            Err(ProtocolSystemCallError::InvalidCalldataLength {
                selector,
                expected,
                got: input.len(),
            })
        }
    };
    let check_no_value = || {
        if tx.value.is_zero() {
            Ok(())
        } else {
            Err(ProtocolSystemCallError::NonZeroValue { selector })
        }
    };
    let non_canonical = || ProtocolSystemCallError::NonCanonicalCalldata { selector };

    let (data, balance_increment) = match selector {
        syscallRewardCall::SELECTOR => {
            check_len(36)?;
            let call =
                syscallRewardCall::abi_decode_raw(&input[4..]).map_err(|_| non_canonical())?;
            if call.abi_encode() != input {
                return Err(non_canonical());
            }
            (syscall_reward_calldata(call.blockAuthor, tx.value), Some((STAKING_ADDRESS, tx.value)))
        }
        syscallSnapshotCall::SELECTOR => {
            check_len(4)?;
            check_no_value()?;
            (syscall_snapshot_calldata(), None)
        }
        syscallOnEpochChangeCall::SELECTOR => {
            check_len(36)?;
            check_no_value()?;
            let call = syscallOnEpochChangeCall::abi_decode_raw(&input[4..])
                .map_err(|_| non_canonical())?;
            if call.abi_encode() != input {
                return Err(non_canonical());
            }
            (syscall_on_epoch_change_calldata(call.epoch), None)
        }
        _ => return Err(ProtocolSystemCallError::UnknownSelector(selector)),
    };

    Ok(Some(ProtocolSystemCall {
        caller: SYSTEM_ADDRESS,
        contract: STAKING_ADDRESS,
        data,
        nonce: tx.nonce,
        chain_id: tx.chain_id,
        balance_increment,
    }))
}

/// Validates the state-dependent fields of a protocol call and applies its pre-execution writes:
/// the system sender nonce bump and the reward mint.
pub(crate) fn prepare_protocol_system_call(
    host: &mut Evm<'_, MonadEvmTypes>,
    call: &ProtocolSystemCall,
) -> HandlerResult<()> {
    call.validate_chain_id(host.version().chain_id)?;
    let next_nonce = call.nonce.checked_add(1).ok_or(ProtocolSystemCallError::NonceOverflow)?;
    let state_nonce = host.state_mut().account(&call.caller)?.nonce();
    if state_nonce != call.nonce {
        return Err(ProtocolSystemCallError::NonceMismatch {
            expected: state_nonce,
            got: call.nonce,
        }
        .into());
    }
    let minted = match call.balance_increment {
        Some((address, amount)) => {
            let balance = host
                .state_mut()
                .account(&address)?
                .balance()
                .checked_add(amount)
                .ok_or(ProtocolSystemCallError::BalanceOverflow)?;
            Some((address, balance))
        }
        None => None,
    };

    host.state_mut().account(&call.caller)?.set_nonce(next_nonce);
    if let Some((address, balance)) = minted {
        host.state_mut().account(&address)?.set_balance(balance);
    }
    Ok(())
}

/// Executes a prepared protocol call as an inspected system call.
///
/// Rejects reverted and halted calls so the outer transaction lifecycle discards the prestate.
pub(crate) fn execute_protocol_system_call(
    host: &mut Evm<'_, MonadEvmTypes>,
    call: &ProtocolSystemCall,
) -> HandlerResult<TxResult<MonadEvmTypes>> {
    host.ext_mut().memory_pool_offset = 0;
    let mut result = host.execute_system_call(call.system_tx())?;
    if !result.status {
        return Err(ProtocolSystemCallError::ExecutionFailed {
            stop: result.stop,
            output: result.output,
        }
        .into());
    }
    // Protocol transactions consume no block gas.
    result.total_gas_spent = 0;
    result.state_gas_spent = 0;
    result.refunded = 0;
    result.floor_gas = 0;
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        MonadEvm, MonadEvmFactory, MonadHardfork, monad_version,
        staking::{
            constants::MON,
            storage::{consensus_view_key, val_id_secp_key, validator_key, validator_offsets},
        },
    };
    use alloy_consensus::TxEip1559;
    use alloy_primitives::address;
    use evm2::{
        Inspector,
        evm::{AccountInfo, InMemoryDB},
        interpreter::{Interpreter, Message, MessageResult},
    };

    const CHAIN_ID: u64 = 143;
    const AUTHOR: Address = address!("0x5555555555555555555555555555555555555555");
    const UNKNOWN_AUTHOR: Address = address!("0x7777777777777777777777777777777777777777");
    const USER: Address = address!("0x1111111111111111111111111111111111111111");

    fn staking_balance() -> U256 {
        U256::from(3) * MON
    }

    /// Staking pre-state with one active validator for [`AUTHOR`].
    fn db() -> InMemoryDB {
        let validator_id = 7u64;
        let auth = Address::repeat_byte(0x66);
        let mut db = InMemoryDB::default();
        db.insert_account_info(
            &STAKING_ADDRESS,
            AccountInfo::default().with_balance(staking_balance()),
        );
        for (key, value) in [
            (val_id_secp_key(&AUTHOR), U256::from(validator_id) << 192),
            (consensus_view_key(validator_id, 0), U256::from(100) * MON),
            (
                validator_key(validator_id, validator_offsets::ADDRESS_FLAGS),
                U256::from_be_slice(auth.as_slice()) << 96,
            ),
            (validator_key(validator_id, validator_offsets::STAKE), U256::from(100) * MON),
        ] {
            db.insert_account_storage(&STAKING_ADDRESS, &key, &value);
        }
        db.insert_account_info(&SYSTEM_ADDRESS, AccountInfo::default());
        db.insert_account_info(&USER, AccountInfo::default().with_balance(MON));
        db
    }

    fn evm<'a>(protocol_replay: bool) -> MonadEvm<'a> {
        let spec = MonadHardfork::MonadNine;
        let mut evm = MonadEvmFactory.create_evm(
            spec,
            monad_version(spec, CHAIN_ID),
            Default::default(),
            db(),
        );
        evm.ext_mut().set_protocol_replay(protocol_replay);
        evm
    }

    fn legacy(nonce: u64, value: U256, input: Vec<u8>) -> TxLegacy {
        TxLegacy {
            chain_id: Some(CHAIN_ID),
            nonce,
            gas_price: 0,
            gas_limit: 0,
            to: TxKind::Call(STAKING_ADDRESS),
            value,
            input: input.into(),
        }
    }

    fn reward(nonce: u64, author: Address, amount: U256) -> TxLegacy {
        legacy(nonce, amount, syscallRewardCall { blockAuthor: author }.abi_encode())
    }

    fn recovered(tx: TxLegacy) -> Recovered<MonadTxEnvelope> {
        Recovered::new_unchecked(MonadTxEnvelope::Legacy(tx), SYSTEM_ADDRESS)
    }

    fn protocol_error(error: &HandlerError) -> &ProtocolSystemCallError {
        error.external_ref().unwrap_or_else(|| panic!("unexpected error: {error:?}"))
    }

    fn nonce_and_staking_balance(evm: &mut MonadEvm<'_>) -> (u64, U256) {
        let nonce = evm.read_account_info(&SYSTEM_ADDRESS).unwrap().unwrap().nonce;
        let balance = evm.read_account_info(&STAKING_ADDRESS).unwrap().unwrap().balance;
        (nonce, balance)
    }

    #[derive(Default)]
    struct CallRecorder {
        calls: Vec<(Address, Address, Bytes)>,
    }

    impl Inspector<MonadEvmTypes> for CallRecorder {
        fn call(
            &mut self,
            _interp: &mut Interpreter<'_, '_, MonadEvmTypes>,
            message: &mut Message<MonadEvmTypes>,
        ) -> Option<MessageResult<MonadEvmTypes>> {
            self.calls.push((message.caller, message.call_target, message.input.clone()));
            None
        }
    }

    #[test]
    fn protocol_syscalls_replay_with_nonce_logs_and_zero_gas() {
        let amount = U256::from(25) * MON;
        let mut recorder = CallRecorder::default();
        {
            let mut evm = evm(true);
            evm.set_inspector(&mut recorder);

            let result = evm.transact(&recovered(reward(0, AUTHOR, amount))).unwrap().commit();
            assert!(result.status);
            assert_eq!(result.logs.len(), 1);
            assert_eq!(result.logs[0].address, STAKING_ADDRESS);
            assert_eq!(
                (result.total_gas_spent, result.state_gas_spent, result.refunded, result.floor_gas),
                (0, 0, 0, 0)
            );
            assert_eq!(result.tx_gas_used(), 0);
            assert_eq!(nonce_and_staking_balance(&mut evm), (1, staking_balance() + amount));

            let snapshot = legacy(1, U256::ZERO, syscall_snapshot_calldata().to_vec());
            let result = evm.transact(&recovered(snapshot)).unwrap().commit();
            assert!(result.status);
            assert_eq!(result.tx_gas_used(), 0);

            let epoch = legacy(2, U256::ZERO, syscall_on_epoch_change_calldata(1).to_vec());
            let result = evm.transact(&recovered(epoch)).unwrap().commit();
            assert!(result.status);
            assert_eq!(result.tx_gas_used(), 0);
            assert_eq!(nonce_and_staking_balance(&mut evm), (3, staking_balance() + amount));
        }

        // The syscalls are inspected, and the reward is encoded into the calldata.
        assert_eq!(
            recorder.calls,
            vec![
                (SYSTEM_ADDRESS, STAKING_ADDRESS, syscall_reward_calldata(AUTHOR, amount)),
                (SYSTEM_ADDRESS, STAKING_ADDRESS, syscall_snapshot_calldata()),
                (SYSTEM_ADDRESS, STAKING_ADDRESS, syscall_on_epoch_change_calldata(1)),
            ]
        );
    }

    #[test]
    fn classifier_decodes_canonical_envelopes() {
        let amount = U256::from(5);
        assert_eq!(
            protocol_system_call(&recovered(reward(4, AUTHOR, amount))).unwrap(),
            Some(ProtocolSystemCall {
                caller: SYSTEM_ADDRESS,
                contract: STAKING_ADDRESS,
                data: syscall_reward_calldata(AUTHOR, amount),
                nonce: 4,
                chain_id: Some(CHAIN_ID),
                balance_increment: Some((STAKING_ADDRESS, amount)),
            })
        );
        let epoch = legacy(0, U256::ZERO, syscall_on_epoch_change_calldata(9).to_vec());
        let call = protocol_system_call(&recovered(TxLegacy { chain_id: None, ..epoch }))
            .unwrap()
            .unwrap();
        assert_eq!(call.data, syscall_on_epoch_change_calldata(9));
        assert_eq!(call.chain_id, None);
        assert_eq!(call.balance_increment, None);

        // Other senders are not protocol transactions, whatever their contents.
        let user =
            Recovered::new_unchecked(MonadTxEnvelope::Legacy(reward(0, AUTHOR, amount)), USER);
        assert_eq!(protocol_system_call(&user).unwrap(), None);
    }

    #[test]
    fn noncanonical_protocol_envelopes_are_rejected() {
        let reward_selector = syscallRewardCall::SELECTOR;
        let snapshot_selector = syscallSnapshotCall::SELECTOR;
        let epoch_selector = syscallOnEpochChangeCall::SELECTOR;
        let base = reward(0, AUTHOR, U256::ZERO);
        let mut dirty_author = base.input.to_vec();
        dirty_author[4] = 1;
        let mut dirty_epoch = syscall_on_epoch_change_calldata(1).to_vec();
        dirty_epoch[4] = 1;
        let cases = [
            (
                TxLegacy { to: TxKind::Call(USER), ..base.clone() },
                ProtocolSystemCallError::InvalidTarget(TxKind::Call(USER)),
            ),
            (
                TxLegacy { to: TxKind::Create, ..base.clone() },
                ProtocolSystemCallError::InvalidTarget(TxKind::Create),
            ),
            (
                TxLegacy { gas_limit: 1, ..base.clone() },
                ProtocolSystemCallError::NonZeroGasLimit(1),
            ),
            (TxLegacy { gas_price: 1, ..base }, ProtocolSystemCallError::NonZeroGasPrice(1)),
            (legacy(0, U256::ZERO, vec![1, 2, 3]), ProtocolSystemCallError::MissingSelector),
            (
                legacy(0, U256::ZERO, vec![1, 2, 3, 4]),
                ProtocolSystemCallError::UnknownSelector([1, 2, 3, 4]),
            ),
            (
                legacy(0, U256::ZERO, syscall_reward_calldata(AUTHOR, U256::ZERO).to_vec()),
                ProtocolSystemCallError::InvalidCalldataLength {
                    selector: reward_selector,
                    expected: 36,
                    got: 68,
                },
            ),
            (
                legacy(0, U256::ZERO, dirty_author),
                ProtocolSystemCallError::NonCanonicalCalldata { selector: reward_selector },
            ),
            (
                legacy(0, U256::ZERO, [&snapshot_selector[..], &[0]].concat()),
                ProtocolSystemCallError::InvalidCalldataLength {
                    selector: snapshot_selector,
                    expected: 4,
                    got: 5,
                },
            ),
            (
                legacy(0, U256::from(1), syscall_snapshot_calldata().to_vec()),
                ProtocolSystemCallError::NonZeroValue { selector: snapshot_selector },
            ),
            (
                legacy(0, U256::from(1), syscall_on_epoch_change_calldata(1).to_vec()),
                ProtocolSystemCallError::NonZeroValue { selector: epoch_selector },
            ),
            (
                legacy(0, U256::ZERO, dirty_epoch),
                ProtocolSystemCallError::NonCanonicalCalldata { selector: epoch_selector },
            ),
        ];

        let mut evm = evm(true);
        for (tx, expected) in cases {
            let tx = recovered(tx);
            assert_eq!(protocol_system_call(&tx).unwrap_err(), expected);
            let error = evm.transact(&tx).unwrap_err();
            assert_eq!(protocol_error(&error), &expected);
        }

        // Typed envelopes from the system sender are rejected while replay is enabled.
        let typed = Recovered::new_unchecked(
            MonadTxEnvelope::Eip1559(TxEip1559 {
                chain_id: CHAIN_ID,
                to: TxKind::Call(STAKING_ADDRESS),
                input: syscall_snapshot_calldata(),
                ..Default::default()
            }),
            SYSTEM_ADDRESS,
        );
        let expected = ProtocolSystemCallError::NotLegacy { tx_type: 2 };
        assert_eq!(protocol_system_call(&typed).unwrap_err(), expected);
        assert_eq!(protocol_error(&evm.transact(&typed).unwrap_err()), &expected);

        // State-dependent checks run at execution.
        let wrong_chain = TxLegacy { chain_id: Some(1), ..reward(0, AUTHOR, U256::ZERO) };
        assert_eq!(
            protocol_error(&evm.transact(&recovered(wrong_chain)).unwrap_err()),
            &ProtocolSystemCallError::ChainIdMismatch { expected: CHAIN_ID, got: 1 }
        );
        assert_eq!(
            protocol_error(&evm.transact(&recovered(reward(1, AUTHOR, U256::ZERO))).unwrap_err()),
            &ProtocolSystemCallError::NonceMismatch { expected: 0, got: 1 }
        );
        assert_eq!(nonce_and_staking_balance(&mut evm), (0, staking_balance()));
    }

    #[test]
    fn failed_protocol_reward_rolls_back_and_allows_same_nonce_retry() {
        let amount = U256::from(25) * MON;
        let mut evm = evm(true);

        // An unknown block author makes the staking precompile reject the reward.
        let error = evm.transact(&recovered(reward(0, UNKNOWN_AUTHOR, amount))).unwrap_err();
        assert!(matches!(
            protocol_error(&error),
            ProtocolSystemCallError::ExecutionFailed { stop, .. } if !stop.is_success()
        ));
        // The nonce bump and the reward mint are discarded.
        assert_eq!(nonce_and_staking_balance(&mut evm), (0, staking_balance()));

        let result = evm.transact(&recovered(reward(0, AUTHOR, amount))).unwrap().commit();
        assert!(result.status);
        assert_eq!(nonce_and_staking_balance(&mut evm), (1, staking_balance() + amount));
    }

    #[test]
    fn protocol_envelopes_require_replay_opt_in() {
        let tx = recovered(reward(0, AUTHOR, U256::from(25) * MON));

        // With replay disabled the envelope is an ordinary transaction, for execution and pool
        // validation alike: its zero gas limit cannot cover intrinsic gas.
        let mut evm = evm(false);
        assert!(matches!(evm.validate_tx(&tx), Err(HandlerError::IntrinsicGasTooLow { .. })));
        assert!(matches!(evm.transact(&tx), Err(HandlerError::IntrinsicGasTooLow { .. })));
        let typed = Recovered::new_unchecked(
            MonadTxEnvelope::Eip1559(TxEip1559 {
                chain_id: CHAIN_ID,
                gas_limit: 0,
                to: TxKind::Call(STAKING_ADDRESS),
                input: syscall_snapshot_calldata(),
                ..Default::default()
            }),
            SYSTEM_ADDRESS,
        );
        assert!(matches!(evm.transact(&typed), Err(HandlerError::IntrinsicGasTooLow { .. })));
        assert_eq!(nonce_and_staking_balance(&mut evm), (0, staking_balance()));

        // With replay enabled ordinary senders keep the ordinary handler behavior.
        let mut evm = self::evm(true);
        let user = Recovered::new_unchecked(
            MonadTxEnvelope::Legacy(tx.inner().as_legacy().unwrap().clone()),
            USER,
        );
        assert!(matches!(evm.validate_tx(&user), Err(HandlerError::IntrinsicGasTooLow { .. })));
        assert!(matches!(evm.transact(&user), Err(HandlerError::IntrinsicGasTooLow { .. })));
        let user_tx = TxLegacy {
            chain_id: Some(CHAIN_ID),
            gas_limit: 100_000,
            to: TxKind::Call(USER),
            ..Default::default()
        };
        let user_tx = Recovered::new_unchecked(MonadTxEnvelope::Legacy(user_tx), USER);
        let result = evm.transact(&user_tx).unwrap().commit();
        assert!(result.status);
        assert_eq!(result.tx_gas_used(), 21_000);
    }
}
