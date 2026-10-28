//! Monad reserve-balance tracking and precompile (0x1001).
//!
//! Port of `monad-revm` `reserve_balance/*` and the reserve-balance parts of `journal.rs`.
//!
//! `monad-revm` wraps the journal and feeds the tracker from every transfer, balance increment,
//! code change and checkpoint revert. evm2 has no journal hooks, so [`sync_reserve_balance`]
//! derives the same events from the evm2 revert journal: each journaled account session is
//! classified as a debit, credit or code change, and entries removed by a rollback are replayed as
//! checkpoint reverts. The tracker is synced before every `dippedIntoReserve()` query and at the
//! end of every transaction.

pub mod tracker;

use crate::{MonadEvmTypes, MonadHardfork, page::PAGE_TRACKER_ADDRESS};
use alloy_primitives::{Address, B256, Bytes, KECCAK256_EMPTY, U256, address};
use evm2::{
    DatabaseError, Evm,
    evm::{AccountFlags, AccountInfo, DynDatabase, JournalEntry, precompile::PrecompileOutput},
    interpreter::{GasTracker, Message, MessageKind},
    precompiles::{PrecompileError, PrecompileHalt, PrecompileResult},
};
use tracker::{ReserveAccount, ReserveBalanceInit};

/// Reserve-balance precompile address.
pub const RESERVE_BALANCE_ADDRESS: Address = address!("0x0000000000000000000000000000000000001001");

/// `dippedIntoReserve()` selector.
pub const DIPPED_INTO_RESERVE_SELECTOR: [u8; 4] = [0x3a, 0x61, 0x58, 0x4e];

/// Gas cost for `dippedIntoReserve()`.
pub const DIPPED_INTO_RESERVE_GAS: u64 = 100;

/// Fallback dispatch cost for invalid selectors.
pub const FALLBACK_GAS: u64 = 100;

/// Default reserve balance threshold: 10 MON.
pub const DEFAULT_RESERVE_BALANCE: U256 =
    U256::from_limbs([10_000_000_000_000_000_000u64, 0, 0, 0]);

alloy_sol_types::sol! {
    /// Monad reserve-balance precompile interface at address 0x1001.
    interface IReserveBalance {
        function dippedIntoReserve() external returns (bool);
    }
}

/// Reserve-balance precompile errors.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReserveBalanceError {
    /// Unknown or short selector.
    MethodNotSupported,
    /// Nonzero value supplied to a non-payable method.
    ValueNonZero,
    /// Extra calldata past the selector.
    InvalidInput,
}

impl ReserveBalanceError {
    /// Returns the revert message emitted by the precompile.
    pub const fn message(self) -> &'static str {
        match self {
            Self::MethodNotSupported => "method not supported",
            Self::ValueNonZero => "value is nonzero",
            Self::InvalidInput => "input is invalid",
        }
    }
}

impl core::fmt::Display for ReserveBalanceError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.message())
    }
}

impl core::error::Error for ReserveBalanceError {}

/// Cursor over the evm2 revert journal that turns journal entries into tracker events.
///
/// The cursor remembers the account-affecting entries it already processed for the current
/// transaction, so a later sync can tell new entries apart from entries removed by a rollback.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ReserveBalanceSync {
    /// Journal length when tracking started for this transaction.
    base: usize,
    /// Entries processed so far, starting at `base`.
    processed: Vec<JournalEntry>,
}

impl ReserveBalanceSync {
    /// Starts a new transaction at the current journal position.
    pub fn begin(&mut self, journal_len: usize) {
        self.base = journal_len;
        self.processed.clear();
    }
}

/// Builds the tracker view of `address` from the current evm2 state.
pub fn reserve_account(
    evm: &mut Evm<'_, MonadEvmTypes>,
    address: Address,
) -> Result<ReserveAccount, DatabaseError> {
    let original = evm.overlay_db_mut().get_account(&address)?;
    let mut account = evm.state_mut().account(&address)?;
    let present = account.get().cloned();
    // `monad-revm` reads the loaded current code, which evm2 loads on demand.
    let is_delegated = account.load_code()?.is_eip7702();
    let selfdestructed_created_locally = account.is_destructed() && account.is_created();
    Ok(ReserveAccount {
        balance: present.as_ref().map_or(U256::ZERO, |info| info.balance),
        original_balance: original.as_ref().map_or(U256::ZERO, |info| info.balance),
        code_hash: present.as_ref().map_or(KECCAK256_EMPTY, |info| info.code_hash),
        original_code_hash: original.as_ref().map_or(KECCAK256_EMPTY, |info| info.code_hash),
        is_delegated,
        selfdestructed_created_locally,
    })
}

/// Initializes the reserve-balance tracker for the transaction sent by `sender`.
///
/// Mirrors `MonadHandler::first_frame_input`: it runs after fees, nonces and EIP-7702
/// authorizations are applied and before the first frame executes. When
/// [`MonadEvmExt::preserve_reserve_balance_tracker`](crate::MonadEvmExt) is set the tracker is
/// kept and only the journal cursor moves to the new transaction.
pub fn begin_reserve_balance_tx(
    evm: &mut Evm<'_, MonadEvmTypes>,
    sender: Address,
    effective_gas_price: u128,
    gas_limit: u64,
) -> Result<(), DatabaseError> {
    let journal_len = evm.state().journal().len();
    evm.ext_mut().reserve_balance_sync.begin(journal_len);
    if evm.ext().preserve_reserve_balance_tracker {
        return Ok(());
    }
    let spec = evm.config_spec_id();
    let sender_account = reserve_account(evm, sender)?;
    let sender_is_delegated = sender_account.is_delegated;
    let ext = evm.ext_mut();
    let chain = ext.chain.clone();
    ext.reserve_balance.init(ReserveBalanceInit {
        chain: &chain,
        spec,
        sender,
        effective_gas_price,
        gas_limit,
        sender_is_delegated,
        sender_account: Some(&sender_account),
    });
    Ok(())
}

/// Clears transaction-scoped reserve-balance state at the end of a transaction.
///
/// Mirrors `MonadJournal::commit_tx`: the tracker is cleared unless it is preserved.
pub fn end_reserve_balance_tx(evm: &mut Evm<'_, MonadEvmTypes>) {
    let ext = evm.ext_mut();
    ext.reserve_balance_sync.begin(0);
    if !ext.preserve_reserve_balance_tracker {
        ext.reserve_balance.clear();
    }
}

/// Returns the address an entry reverts, if it affects one.
fn entry_address(entry: &JournalEntry) -> Option<Address> {
    match entry {
        JournalEntry::AccountChange { address, .. }
        | JournalEntry::StorageChange { address, .. }
        | JournalEntry::TransientStorageChange { address, .. }
        | JournalEntry::StorageWarmed { address, .. } => Some(*address),
        _ => None,
    }
}

/// Account fields captured at a journal session boundary.
#[derive(Clone, Copy, Debug)]
struct SessionState {
    balance: U256,
    code_hash: B256,
    destroyed: bool,
}

impl SessionState {
    fn from_info(info: Option<&AccountInfo>, destroyed: bool) -> Self {
        Self {
            balance: info.map_or(U256::ZERO, |info| info.balance),
            code_hash: info.map_or(KECCAK256_EMPTY, |info| info.code_hash),
            destroyed,
        }
    }
}

/// A tracker event derived from one journaled account session.
#[derive(Clone, Copy, Debug)]
enum Event {
    Debit(Address),
    Credit(Address),
    SetCode(Address),
}

/// Feeds every journal change since the last sync into the reserve-balance tracker.
///
/// Rolled-back entries are replayed as checkpoint reverts, and new account sessions become
/// debits, credits and code changes in journal order. Events are evaluated against the current
/// account state, which yields the same violation set as evaluating each event at the time it
/// occurred because thresholds only depend on transaction-start balances and current code.
pub fn sync_reserve_balance(evm: &mut Evm<'_, MonadEvmTypes>) -> Result<(), DatabaseError> {
    if !evm.ext().reserve_balance.tracking_enabled() {
        return Ok(());
    }
    let (common, reverted, events) = {
        let sync = &evm.ext().reserve_balance_sync;
        let journal = evm.state().journal();
        let base = sync.base.min(journal.len());
        let current = &journal[base..];
        let common =
            sync.processed.iter().zip(current).take_while(|(left, right)| left == right).count();
        let reverted: Vec<Address> =
            sync.processed[common..].iter().filter_map(entry_address).collect();
        let new_entries = current[common..].to_vec();
        (common, reverted, new_entries)
    };

    // Replay rolled-back entries as a checkpoint revert.
    if !reverted.is_empty() {
        let mut views = Vec::with_capacity(reverted.len());
        for address in reverted {
            if address == PAGE_TRACKER_ADDRESS {
                continue;
            }
            views.push((address, reserve_account(evm, address)?));
        }
        evm.ext_mut()
            .reserve_balance
            .on_checkpoint_revert(views.iter().map(|(address, view)| (*address, Some(view))));
    }

    // Classify new account sessions.
    let mut derived = Vec::new();
    for (index, entry) in events.iter().enumerate() {
        let JournalEntry::AccountChange { address, previous, previous_flags } = entry else {
            continue;
        };
        let before = SessionState::from_info(
            previous.as_ref(),
            previous_flags.contains(AccountFlags::DESTROYED),
        );
        let next = events[index + 1..].iter().find_map(|later| match later {
            JournalEntry::AccountChange { address: later_address, previous, previous_flags }
                if later_address == address =>
            {
                Some(SessionState::from_info(
                    previous.as_ref(),
                    previous_flags.contains(AccountFlags::DESTROYED),
                ))
            }
            _ => None,
        });
        let after = match next {
            Some(after) => after,
            None => {
                let account = evm.state_mut().account(address)?;
                let destroyed = account.is_destructed();
                SessionState::from_info(account.get(), destroyed)
            }
        };
        if after.balance < before.balance || (!before.destroyed && after.destroyed) {
            derived.push(Event::Debit(*address));
        } else if after.balance > before.balance {
            derived.push(Event::Credit(*address));
        }
        if after.code_hash != before.code_hash {
            derived.push(Event::SetCode(*address));
        }
    }
    for event in derived {
        match event {
            Event::Debit(address) => {
                let view = reserve_account(evm, address)?;
                evm.ext_mut().reserve_balance.on_debit(Some(&view), address);
            }
            Event::Credit(address) => {
                let view = reserve_account(evm, address)?;
                evm.ext_mut().reserve_balance.on_credit(Some(&view), address);
            }
            Event::SetCode(address) => {
                let view = reserve_account(evm, address)?;
                let code = evm.state_mut().account(&address)?.load_code()?;
                let is_smart_contract =
                    !code.original_byte_slice().is_empty() && !code.is_eip7702();
                evm.ext_mut().reserve_balance.on_set_code(Some(&view), address, is_smart_contract);
            }
        }
    }

    let sync = &mut evm.ext_mut().reserve_balance_sync;
    sync.processed.truncate(common);
    sync.processed.extend(events);
    Ok(())
}

/// Returns whether the current transaction dipped into reserve, syncing the tracker first.
pub fn dipped_into_reserve(evm: &mut Evm<'_, MonadEvmTypes>) -> Result<bool, DatabaseError> {
    sync_reserve_balance(evm)?;
    Ok(evm.ext().reserve_balance.has_violation())
}

/// Rebases the live reserve-balance tracker onto the EVM's current chain context and state.
///
/// Port of the `refresh_journal` flow Foundry uses when the chain position changes mid-execution.
pub fn rebase_reserve_balance(evm: &mut Evm<'_, MonadEvmTypes>) -> Result<(), DatabaseError> {
    sync_reserve_balance(evm)?;
    let tracked: Vec<Address> = evm.ext().reserve_balance.tracked_addresses().copied().collect();
    let mut views = Vec::with_capacity(tracked.len());
    for address in tracked {
        views.push((address, reserve_account(evm, address)?));
    }
    let ext = evm.ext_mut();
    let chain = ext.chain.clone();
    ext.reserve_balance.rebase(&chain, |address| {
        views.iter().find(|(tracked, _)| *tracked == address).map(|(_, view)| *view)
    });
    Ok(())
}

/// Runs the reserve-balance precompile.
///
/// The caller must only dispatch messages whose code address is [`RESERVE_BALANCE_ADDRESS`] while
/// MonadNine or later is active.
pub fn run_reserve_balance_precompile(
    evm: &mut Evm<'_, MonadEvmTypes>,
    message: &Message<MonadEvmTypes>,
    gas: &mut GasTracker,
) -> PrecompileResult {
    debug_assert!(MonadHardfork::MonadNine.is_enabled_in(evm.config_spec_id()));
    let is_delegated_call =
        message.kind == MessageKind::Call && message.destination != message.code_address;
    let is_static = message.kind == MessageKind::StaticCall || message.caller_is_static;

    if message.kind != MessageKind::Call || is_static || is_delegated_call {
        return revert(gas, Bytes::new());
    }

    if message.gas_limit < DIPPED_INTO_RESERVE_GAS {
        return Err(PrecompileHalt::OutOfGas.into());
    }

    let input = &message.input;
    if input.get(..4) != Some(&DIPPED_INTO_RESERVE_SELECTOR[..]) {
        return revert_error(gas, ReserveBalanceError::MethodNotSupported);
    }

    if !message.value.is_zero() {
        return revert_error(gas, ReserveBalanceError::ValueNonZero);
    }

    if input.len() > 4 {
        return revert_error(gas, ReserveBalanceError::InvalidInput);
    }

    let has_violation = dipped_into_reserve(evm).map_err(PrecompileError::Database)?;
    gas.spend(DIPPED_INTO_RESERVE_GAS)?;
    let mut output = [0u8; 32];
    output[31] = u8::from(has_violation);
    Ok(PrecompileOutput::new(Bytes::copy_from_slice(&output)))
}

fn revert_error(gas: &mut GasTracker, error: ReserveBalanceError) -> PrecompileResult {
    revert(gas, Bytes::from_static(error.message().as_bytes()))
}

fn revert(gas: &mut GasTracker, output: Bytes) -> PrecompileResult {
    gas.spend_all();
    Err(PrecompileError::Revert(output))
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_sol_types::SolCall;

    #[test]
    fn constants_match_monad_revm() {
        use monad_revm::reserve_balance::abi;
        assert_eq!(RESERVE_BALANCE_ADDRESS, abi::RESERVE_BALANCE_ADDRESS);
        assert_eq!(DIPPED_INTO_RESERVE_SELECTOR, abi::DIPPED_INTO_RESERVE_SELECTOR);
        assert_eq!(DIPPED_INTO_RESERVE_SELECTOR, IReserveBalance::dippedIntoReserveCall::SELECTOR);
        assert_eq!(DIPPED_INTO_RESERVE_GAS, abi::DIPPED_INTO_RESERVE_GAS);
        assert_eq!(FALLBACK_GAS, abi::FALLBACK_GAS);
        assert_eq!(DEFAULT_RESERVE_BALANCE, abi::DEFAULT_RESERVE_BALANCE);
        for (ours, theirs) in [
            (ReserveBalanceError::MethodNotSupported, "method not supported"),
            (ReserveBalanceError::ValueNonZero, "value is nonzero"),
            (ReserveBalanceError::InvalidInput, "input is invalid"),
        ] {
            assert_eq!(ours.message(), theirs);
        }
    }
}
