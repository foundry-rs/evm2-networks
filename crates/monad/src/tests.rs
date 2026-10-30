//! Differential parity tests against `monad-revm`.
//!
//! Each scenario runs the same pre-state and transaction through `monad-revm` (the source of
//! truth) and through this evm2 port, then compares the outcome, gas used, output, logs, balances
//! and storage.

use crate::{
    MonadChainContext, MonadEvmFactory, MonadHardfork, MonadInvalidTransaction, monad_version,
    reserve_balance::{DIPPED_INTO_RESERVE_SELECTOR, RESERVE_BALANCE_ADDRESS},
    staking::{STAKING_ADDRESS, constants::SYSTEM_ADDRESS},
};
use alloy_consensus::{TxEip1559, TxEip7702, TxLegacy, transaction::Recovered};
use alloy_eips::eip7702::{Authorization, RecoveredAuthority, RecoveredAuthorization};
use alloy_primitives::{Address, Bytes, Log, TxKind, U256};
use core::str::FromStr;
use evm2::{
    Inspector, InspectorConfig, OpcodeSet,
    ethereum::{LazyAuthorization, LazyTxEip7702, TxEnvelope},
    evm::{AccountInfo as Evm2AccountInfo, InMemoryDB as Evm2Db},
    interpreter::{Interpreter, Message, MessageResult},
    registry::HandlerError,
};
use monad_revm::api::builder::MonadBuilder;
use revm::{
    ExecuteEvm,
    context::TxEnv,
    context_interface::{
        either::Either,
        result::ExecutionResult,
        transaction::{
            Authorization as RevmAuthorization, RecoveredAuthority as RevmRecoveredAuthority,
            RecoveredAuthorization as RevmRecoveredAuthorization,
        },
    },
    database::InMemoryDB as RevmDb,
    state::{AccountInfo as RevmAccountInfo, Bytecode as RevmBytecode},
};

/// Opcode bytes used by the test contracts.
mod op {
    pub(super) const STOP: u8 = 0x00;
    pub(super) const SUB: u8 = 0x03;
    pub(super) const BALANCE: u8 = 0x31;
    pub(super) const CALLDATASIZE: u8 = 0x36;
    pub(super) const CALLDATACOPY: u8 = 0x37;
    pub(super) const EXTCODESIZE: u8 = 0x3b;
    pub(super) const POP: u8 = 0x50;
    pub(super) const MLOAD: u8 = 0x51;
    pub(super) const MSTORE: u8 = 0x52;
    pub(super) const SLOAD: u8 = 0x54;
    pub(super) const SSTORE: u8 = 0x55;
    pub(super) const GAS: u8 = 0x5a;
    pub(super) const PUSH0: u8 = 0x5f;
    pub(super) const PUSH1: u8 = 0x60;
    pub(super) const PUSH2: u8 = 0x61;
    pub(super) const PUSH4: u8 = 0x63;
    pub(super) const PUSH20: u8 = 0x73;
    pub(super) const SWAP1: u8 = 0x90;
    pub(super) const LOG1: u8 = 0xa1;
    pub(super) const KECCAK256: u8 = 0x20;
    pub(super) const CREATE: u8 = 0xf0;
    pub(super) const CREATE2: u8 = 0xf5;
    pub(super) const CALL: u8 = 0xf1;
    pub(super) const CALLCODE: u8 = 0xf2;
    pub(super) const RETURN: u8 = 0xf3;
    pub(super) const DELEGATECALL: u8 = 0xf4;
    pub(super) const STATICCALL: u8 = 0xfa;
    pub(super) const REVERT: u8 = 0xfd;
    pub(super) const SELFDESTRUCT: u8 = 0xff;
}

#[derive(Clone, Debug, Default)]
struct TestAccount {
    address: Address,
    balance: U256,
    nonce: u64,
    code: Vec<u8>,
    storage: Vec<(U256, U256)>,
    delegate: Option<Address>,
}

impl TestAccount {
    fn new(address: Address) -> Self {
        Self { address, ..Default::default() }
    }

    fn balance(mut self, balance: u128) -> Self {
        self.balance = U256::from(balance);
        self
    }

    fn code(mut self, code: Vec<u8>) -> Self {
        self.code = code;
        self
    }

    fn storage(mut self, key: U256, value: U256) -> Self {
        self.storage.push((key, value));
        self
    }

    fn delegate(mut self, delegate: Address) -> Self {
        self.delegate = Some(delegate);
        self
    }
}

#[derive(Clone, Debug)]
struct TestTx {
    caller: Address,
    to: TxKind,
    value: U256,
    data: Bytes,
    gas_limit: u64,
    gas_price: u128,
    priority_fee: Option<u128>,
    nonce: u64,
    /// `(authority, delegate, nonce)` authorizations.
    authorizations: Vec<(Address, Address, u64)>,
}

impl TestTx {
    fn call(caller: Address, to: Address) -> Self {
        Self {
            caller,
            to: TxKind::Call(to),
            value: U256::ZERO,
            data: Bytes::new(),
            gas_limit: 1_000_000,
            gas_price: 0,
            priority_fee: None,
            nonce: 0,
            authorizations: Vec::new(),
        }
    }
}

#[derive(Clone, Debug)]
struct Scenario {
    spec: MonadHardfork,
    accounts: Vec<TestAccount>,
    chain: MonadChainContext,
    basefee: u64,
    beneficiary: Address,
    tx: TestTx,
    /// Addresses whose balances are compared.
    watch: Vec<Address>,
    /// Storage slots compared after execution.
    watch_storage: Vec<(Address, U256)>,
}

impl Scenario {
    fn new(spec: MonadHardfork, accounts: Vec<TestAccount>, tx: TestTx) -> Self {
        let mut watch: Vec<_> = accounts.iter().map(|account| account.address).collect();
        watch.push(Address::with_last_byte(0xbe));
        let watch_storage = accounts
            .iter()
            .flat_map(|account| account.storage.iter().map(|(key, _)| (account.address, *key)))
            .collect();
        Self {
            spec,
            accounts,
            chain: MonadChainContext::default(),
            basefee: 0,
            beneficiary: Address::with_last_byte(0xbe),
            tx,
            watch,
            watch_storage,
        }
    }
}

/// Comparable execution outcome.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Outcome {
    Success { gas_used: u64, output: Bytes, logs: Vec<Log> },
    Revert { gas_used: u64, output: Bytes },
    Halt { gas_used: u64 },
    Invalid,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct Observed {
    outcome: Outcome,
    balances: Vec<(Address, U256)>,
    storage: Vec<(Address, U256, U256)>,
}

fn their_spec(spec: MonadHardfork) -> monad_revm::MonadHardfork {
    monad_revm::MonadHardfork::from_str(spec.into()).expect("known spec")
}

fn their_chain(chain: &MonadChainContext) -> monad_revm::MonadChainContext {
    monad_revm::MonadChainContext {
        parent_senders_and_authorities: chain
            .parent_senders_and_authorities
            .iter()
            .copied()
            .collect(),
        grandparent_senders_and_authorities: chain
            .grandparent_senders_and_authorities
            .iter()
            .copied()
            .collect(),
        current_block_senders: chain.current_block_senders.clone(),
        current_block_authorities: chain.current_block_authorities.clone(),
        current_tx_index: chain.current_tx_index,
        max_reserve_balance: chain.max_reserve_balance,
    }
}

fn run_revm(scenario: &Scenario) -> Observed {
    let mut db = RevmDb::default();
    for account in &scenario.accounts {
        let code = match account.delegate {
            Some(delegate) => RevmBytecode::new_eip7702(delegate),
            None => RevmBytecode::new_raw(account.code.clone().into()),
        };
        let mut info = RevmAccountInfo::default().with_code(code);
        info.balance = account.balance;
        info.nonce = account.nonce;
        db.insert_account_info(account.address, info);
        for (key, value) in &account.storage {
            db.insert_account_storage(account.address, *key, *value).unwrap();
        }
    }
    let mut ctx = monad_revm::monad_context_with_db(db)
        .with_cfg(monad_revm::MonadCfgEnv::new_with_spec(their_spec(scenario.spec)));
    ctx.chain = their_chain(&scenario.chain);
    ctx.block.basefee = scenario.basefee;
    ctx.block.beneficiary = scenario.beneficiary;
    let mut evm = ctx.build_monad();

    let tx = &scenario.tx;
    let mut builder = TxEnv::builder()
        .caller(tx.caller)
        .kind(tx.to)
        .value(tx.value)
        .data(tx.data.clone())
        .gas_limit(tx.gas_limit)
        .gas_price(tx.gas_price)
        .nonce(tx.nonce)
        .chain_id(Some(1))
        .gas_priority_fee(tx.priority_fee);
    if !tx.authorizations.is_empty() {
        builder = builder.authorization_list(
            tx.authorizations
                .iter()
                .map(|(authority, delegate, nonce)| {
                    Either::Right(RevmRecoveredAuthorization::new_unchecked(
                        RevmAuthorization {
                            chain_id: U256::from(1),
                            address: *delegate,
                            nonce: *nonce,
                        },
                        RevmRecoveredAuthority::Valid(*authority),
                    ))
                })
                .collect(),
        );
    }
    let tx_env = builder.build_fill();
    let result = match evm.transact(tx_env) {
        Ok(result) => result,
        Err(_) => {
            return Observed {
                outcome: Outcome::Invalid,
                balances: Vec::new(),
                storage: Vec::new(),
            };
        }
    };
    let outcome = match &result.result {
        ExecutionResult::Success { output, logs, .. } => Outcome::Success {
            gas_used: result.result.tx_gas_used(),
            output: output.data().clone(),
            logs: logs.clone(),
        },
        ExecutionResult::Revert { output, .. } => {
            Outcome::Revert { gas_used: result.result.tx_gas_used(), output: output.clone() }
        }
        ExecutionResult::Halt { .. } => Outcome::Halt { gas_used: result.result.tx_gas_used() },
    };
    let balances = scenario
        .watch
        .iter()
        .map(|address| {
            let balance =
                result.state.get(address).map(|account| account.info.balance).unwrap_or_else(
                    || {
                        scenario
                            .accounts
                            .iter()
                            .find(|account| account.address == *address)
                            .map_or(U256::ZERO, |account| account.balance)
                    },
                );
            (*address, balance)
        })
        .collect();
    let storage = scenario
        .watch_storage
        .iter()
        .map(|(address, key)| {
            let value = result
                .state
                .get(address)
                .and_then(|account| account.storage.get(key))
                .map(|slot| slot.present_value)
                .unwrap_or_else(|| {
                    scenario
                        .accounts
                        .iter()
                        .find(|account| account.address == *address)
                        .and_then(|account| {
                            account.storage.iter().find(|(k, _)| k == key).map(|(_, v)| *v)
                        })
                        .unwrap_or_default()
                });
            (*address, *key, value)
        })
        .collect();
    Observed { outcome, balances, storage }
}

fn evm2_envelope(tx: &TestTx) -> TxEnvelope {
    if !tx.authorizations.is_empty() {
        let TxKind::Call(to) = tx.to else { panic!("7702 must be a call") };
        let inner = TxEip7702 {
            chain_id: 1,
            nonce: tx.nonce,
            gas_limit: tx.gas_limit,
            max_fee_per_gas: tx.gas_price,
            max_priority_fee_per_gas: tx.priority_fee.unwrap_or_default(),
            to,
            value: tx.value,
            input: tx.data.clone(),
            ..Default::default()
        };
        let authorizations = tx
            .authorizations
            .iter()
            .map(|(authority, delegate, nonce)| {
                LazyAuthorization::from(RecoveredAuthorization::new_unchecked(
                    Authorization { chain_id: U256::from(1), address: *delegate, nonce: *nonce },
                    RecoveredAuthority::Valid(*authority),
                ))
            })
            .collect();
        return TxEnvelope::Eip7702(LazyTxEip7702::from_authorizations(inner, authorizations));
    }
    match tx.priority_fee {
        Some(priority_fee) => TxEnvelope::Eip1559(TxEip1559 {
            chain_id: 1,
            nonce: tx.nonce,
            gas_limit: tx.gas_limit,
            max_fee_per_gas: tx.gas_price,
            max_priority_fee_per_gas: priority_fee,
            to: tx.to,
            value: tx.value,
            input: tx.data.clone(),
            ..Default::default()
        }),
        None => TxEnvelope::Legacy(TxLegacy {
            chain_id: Some(1),
            nonce: tx.nonce,
            gas_price: tx.gas_price,
            gas_limit: tx.gas_limit,
            to: tx.to,
            value: tx.value,
            input: tx.data.clone(),
        }),
    }
}

fn evm2_db(scenario: &Scenario) -> Evm2Db {
    let mut db = Evm2Db::default();
    for account in &scenario.accounts {
        let code = match account.delegate {
            Some(delegate) => evm2::bytecode::Bytecode::new_eip7702(delegate),
            None => evm2::bytecode::Bytecode::new_raw(account.code.clone().into()),
        };
        let info = Evm2AccountInfo::default()
            .with_code(code)
            .with_balance(account.balance)
            .with_nonce(account.nonce);
        db.insert_account_info(&account.address, info);
        for (key, value) in &account.storage {
            db.insert_account_storage(&account.address, key, value);
        }
    }
    db
}

fn run_evm2_with(
    scenario: &Scenario,
    configure: impl FnOnce(&mut crate::MonadEvm<'_>),
) -> (Observed, Option<Result<crate::MonadTxResultExt, HandlerError>>) {
    let factory = MonadEvmFactory;
    let block = crate::MonadBlockEnv {
        basefee: U256::from(scenario.basefee),
        beneficiary: scenario.beneficiary,
        ..Default::default()
    };
    let mut evm = factory.create_evm(
        scenario.spec,
        monad_version(scenario.spec, 1),
        block,
        evm2_db(scenario),
    );
    evm.ext_mut().chain = scenario.chain.clone();
    configure(&mut evm);
    let tx = Recovered::new_unchecked(evm2_envelope(&scenario.tx), scenario.tx.caller);
    let result = match evm.transact(&tx) {
        Ok(executed) => executed.commit(),
        Err(error) => {
            return (
                Observed { outcome: Outcome::Invalid, balances: Vec::new(), storage: Vec::new() },
                Some(Err(error)),
            );
        }
    };
    let outcome = if result.status {
        Outcome::Success {
            gas_used: result.tx_gas_used(),
            output: result.output.clone(),
            logs: result.logs.clone(),
        }
    } else if result.stop == evm2::interpreter::InstrStop::Revert {
        Outcome::Revert { gas_used: result.tx_gas_used(), output: result.output.clone() }
    } else {
        Outcome::Halt { gas_used: result.tx_gas_used() }
    };
    let balances = scenario
        .watch
        .iter()
        .map(|address| {
            let balance =
                evm.read_account_info(address).unwrap().map_or(U256::ZERO, |info| info.balance);
            (*address, balance)
        })
        .collect();
    let storage = scenario
        .watch_storage
        .iter()
        .map(|(address, key)| {
            (*address, *key, evm.state_mut().read_committed_storage(address, key).unwrap())
        })
        .collect();
    (Observed { outcome, balances, storage }, Some(Ok(result.ext)))
}

fn run_evm2(scenario: &Scenario) -> Observed {
    run_evm2_with(scenario, |_| {}).0
}

/// Runs `scenario` on both implementations and asserts identical observations.
#[track_caller]
fn assert_parity(scenario: &Scenario) -> Observed {
    let expected = run_revm(scenario);
    let actual = run_evm2(scenario);
    assert_eq!(actual, expected, "spec {}", scenario.spec);
    actual
}

/// Like [`assert_parity`], and also asserts that the transaction was valid.
#[track_caller]
fn assert_valid_parity(scenario: &Scenario) -> Observed {
    let observed = assert_parity(scenario);
    assert_ne!(observed.outcome, Outcome::Invalid, "spec {}", scenario.spec);
    observed
}

/// Returns the gas word a [`measure`] contract returned.
fn measured_gas(observed: &Observed) -> u64 {
    match &observed.outcome {
        Outcome::Success { output, .. } => U256::from_be_slice(&output[..32]).to::<u64>(),
        outcome => panic!("expected success, got {outcome:?}"),
    }
}

const CALLER: Address = Address::new([0x11; 20]);
const TARGET: Address = Address::new([0x22; 20]);
const OTHER: Address = Address::new([0x33; 20]);
const THIRD: Address = Address::new([0x44; 20]);

fn funded_caller() -> TestAccount {
    TestAccount::new(CALLER).balance(1_000_000_000_000_000_000_000)
}

fn push_u32(code: &mut Vec<u8>, value: u32) {
    code.push(op::PUSH4);
    code.extend_from_slice(&value.to_be_bytes());
}

fn push_address(code: &mut Vec<u8>, address: Address) {
    code.push(op::PUSH20);
    code.extend_from_slice(address.as_slice());
}

/// Code that measures the gas of running `body` and returns it.
fn measure(body: &[u8]) -> Vec<u8> {
    let mut code = vec![op::GAS];
    code.extend_from_slice(body);
    code.extend_from_slice(&[
        op::GAS,
        op::SWAP1,
        op::SUB,
        op::PUSH0,
        op::MSTORE,
        op::PUSH1,
        0x20,
        op::PUSH0,
        op::RETURN,
    ]);
    code
}

fn call_code(opcode: u8, target: Address, value: u32, input_len: u32, output_len: u32) -> Vec<u8> {
    let mut code = Vec::new();
    push_u32(&mut code, output_len);
    push_u32(&mut code, 0x2000);
    push_u32(&mut code, input_len);
    push_u32(&mut code, 0x1000);
    if matches!(opcode, op::CALL | op::CALLCODE) {
        push_u32(&mut code, value);
    }
    push_address(&mut code, target);
    code.push(op::GAS);
    code.push(opcode);
    code
}

fn storage_ops(op: u8, slots: &[u32]) -> Vec<u8> {
    let mut code = Vec::new();
    for slot in slots {
        if op == op::SSTORE {
            code.extend_from_slice(&[op::PUSH1, 1]);
            push_u32(&mut code, *slot);
            code.push(op::SSTORE);
        } else {
            push_u32(&mut code, *slot);
            code.extend_from_slice(&[op::SLOAD, op::POP]);
        }
    }
    code
}

#[test]
fn storage_access_pricing_matches() {
    for spec in MonadHardfork::ALL {
        for slots in [vec![0, 127], vec![0, 128], vec![5, 5], vec![0, 1, 200, 129, 300]] {
            for opcode in [op::SLOAD, op::SSTORE] {
                let mut target =
                    TestAccount::new(TARGET).code(measure(&storage_ops(opcode, &slots)));
                // Existing non-zero slots exercise the reset and clearing paths.
                target = target.storage(U256::from(1), U256::from(7));
                target = target.storage(U256::from(129), U256::from(9));
                let scenario = Scenario::new(
                    spec,
                    vec![funded_caller(), target],
                    TestTx::call(CALLER, TARGET),
                );
                assert_valid_parity(&scenario);
            }
        }
    }
}

#[test]
fn sstore_clearing_and_nested_revert_page_state_match() {
    // Child writes three slots on one page and reverts, then the parent writes the same page.
    let child = {
        let mut code = vec![op::PUSH1, 1, op::PUSH0, op::SSTORE];
        code.extend_from_slice(&[op::PUSH1, 1, op::PUSH1, 1, op::SSTORE]);
        code.extend_from_slice(&[
            op::PUSH0,
            op::PUSH0,
            op::SSTORE,
            op::PUSH0,
            op::PUSH0,
            op::REVERT,
        ]);
        code
    };
    let mut parent = call_code(op::DELEGATECALL, OTHER, 0, 0, 0);
    parent.push(op::POP);
    parent.extend_from_slice(&measure(&[op::PUSH1, 1, op::PUSH1, 2, op::SSTORE]));
    for spec in MonadHardfork::ALL {
        let scenario = Scenario::new(
            spec,
            vec![
                funded_caller(),
                TestAccount::new(TARGET).code(parent.clone()).storage(U256::from(3), U256::from(1)),
                TestAccount::new(OTHER).code(child.clone()),
            ],
            TestTx::call(CALLER, TARGET),
        );
        assert_valid_parity(&scenario);
    }
}

#[test]
fn cold_account_access_pricing_matches() {
    for spec in MonadHardfork::ALL {
        for opcode in [op::BALANCE, op::EXTCODESIZE] {
            let mut body = Vec::new();
            push_address(&mut body, OTHER);
            body.extend_from_slice(&[opcode, op::POP]);
            push_address(&mut body, OTHER);
            body.extend_from_slice(&[opcode, op::POP]);
            let scenario = Scenario::new(
                spec,
                vec![
                    funded_caller(),
                    TestAccount::new(TARGET).code(measure(&body)),
                    TestAccount::new(OTHER).code(vec![op::STOP]),
                ],
                TestTx::call(CALLER, TARGET),
            );
            assert_valid_parity(&scenario);
        }
    }
}

#[test]
fn memory_expansion_pricing_matches() {
    for spec in MonadHardfork::ALL {
        for offset in [0u32, 0x20, 0x2000, 0x10000, 0x7fffe0] {
            // MSTORE, MLOAD and KECCAK256 at growing offsets.
            let mut body = vec![op::PUSH0];
            push_u32(&mut body, offset);
            body.push(op::MSTORE);
            push_u32(&mut body, offset);
            body.extend_from_slice(&[op::MLOAD, op::POP]);
            push_u32(&mut body, 0x40);
            push_u32(&mut body, offset);
            body.extend_from_slice(&[op::KECCAK256, op::POP]);
            let scenario = Scenario::new(
                spec,
                vec![funded_caller(), TestAccount::new(TARGET).code(measure(&body))],
                TestTx { gas_limit: 30_000_000, ..TestTx::call(CALLER, TARGET) },
            );
            assert_valid_parity(&scenario);
        }
    }
}

#[test]
fn memory_limit_matches() {
    // MonadNine and later cap memory at 8 MiB: the last in-limit word succeeds, the next one
    // halts with a memory-limit error.
    for spec in MonadHardfork::ALL {
        for offset in [0x7fffe0u32, 0x800000] {
            let mut code = vec![op::PUSH0];
            push_u32(&mut code, offset);
            code.extend_from_slice(&[op::MSTORE, op::STOP]);
            let scenario = Scenario::new(
                spec,
                vec![funded_caller(), TestAccount::new(TARGET).code(code)],
                TestTx { gas_limit: 30_000_000, ..TestTx::call(CALLER, TARGET) },
            );
            assert_valid_parity(&scenario);
        }
    }
}

#[test]
fn pooled_memory_limit_matches() {
    // The parent holds 4 MiB, so a child that grows past the remaining 4 MiB fails while the
    // parent continues.
    let child = |offset: u32| {
        let mut code = vec![op::PUSH0];
        push_u32(&mut code, offset);
        code.extend_from_slice(&[op::MSTORE, op::STOP]);
        code
    };
    for spec in MonadHardfork::ALL {
        for child_offset in [0x3fffe0u32, 0x400000] {
            let mut parent = vec![op::PUSH0];
            push_u32(&mut parent, 0x3fffe0);
            parent.push(op::MSTORE);
            parent.extend_from_slice(&[op::PUSH0, op::PUSH0, op::PUSH0, op::PUSH0, op::PUSH0]);
            push_address(&mut parent, OTHER);
            parent.extend_from_slice(&[op::GAS, op::CALL, op::PUSH0, op::MSTORE]);
            parent.extend_from_slice(&[op::PUSH1, 0x20, op::PUSH0, op::RETURN]);
            let scenario = Scenario::new(
                spec,
                vec![
                    funded_caller(),
                    TestAccount::new(TARGET).code(parent),
                    TestAccount::new(OTHER).code(child(child_offset)),
                ],
                TestTx { gas_limit: 30_000_000, ..TestTx::call(CALLER, TARGET) },
            );
            assert_valid_parity(&scenario);
        }
    }
}

#[test]
fn copy_log_and_return_memory_pricing_matches() {
    for spec in MonadHardfork::ALL {
        let mut body = Vec::new();
        // CALLDATACOPY into a high offset.
        body.push(op::CALLDATASIZE);
        body.push(op::PUSH0);
        push_u32(&mut body, 0x3000);
        body.push(op::CALLDATACOPY);
        // LOG1 from a higher offset.
        push_u32(&mut body, 0xabcd);
        push_u32(&mut body, 0x40);
        push_u32(&mut body, 0x4000);
        body.push(op::LOG1);
        let mut code = measure(&body);
        // Replace the trailing RETURN with a return of a large range.
        code.truncate(code.len() - 4);
        code.extend_from_slice(&[op::PUSH2, 0x50, 0x00, op::PUSH0, op::RETURN]);
        let scenario = Scenario::new(
            spec,
            vec![funded_caller(), TestAccount::new(TARGET).code(code)],
            TestTx { data: Bytes::from(vec![0xaa; 100]), ..TestTx::call(CALLER, TARGET) },
        );
        assert_valid_parity(&scenario);
    }
}

#[test]
fn call_family_memory_and_value_pricing_matches() {
    for spec in MonadHardfork::ALL {
        for opcode in [op::CALL, op::CALLCODE, op::DELEGATECALL, op::STATICCALL] {
            for (value, input_len, output_len) in [(0, 0, 0), (0, 0x20, 0x20), (5, 0x40, 0x100)] {
                if value != 0 && !matches!(opcode, op::CALL | op::CALLCODE) {
                    continue;
                }
                let body = call_code(opcode, OTHER, value, input_len, output_len);
                let mut code = measure(&body);
                code.insert(0, op::POP);
                code.insert(0, op::GAS);
                let scenario = Scenario::new(
                    spec,
                    vec![
                        funded_caller(),
                        TestAccount::new(TARGET).code(measure(&body)).balance(100),
                        TestAccount::new(OTHER).code(vec![op::PUSH1, 0x20, op::PUSH0, op::RETURN]),
                    ],
                    TestTx::call(CALLER, TARGET),
                );
                assert_valid_parity(&scenario);
            }
        }
    }
}

#[test]
fn value_transfer_to_new_account_and_selfdestruct_match() {
    for spec in MonadHardfork::ALL {
        let mut code = call_code(op::CALL, THIRD, 7, 0, 0);
        code.push(op::POP);
        push_address(&mut code, OTHER);
        code.push(op::SELFDESTRUCT);
        let scenario = Scenario::new(
            spec,
            vec![funded_caller(), TestAccount::new(TARGET).code(code).balance(1_000)],
            TestTx::call(CALLER, TARGET),
        );
        let mut scenario = scenario;
        scenario.watch.extend([OTHER, THIRD]);
        assert_valid_parity(&scenario);
    }
}

#[test]
fn fee_charging_matches() {
    // Full gas-limit charging, no refund, beneficiary paid gas_limit * priority price.
    for spec in MonadHardfork::ALL {
        for (gas_price, priority_fee, basefee) in [
            (1_000_000_000u128, None, 0u64),
            (3_000, Some(1_000u128), 1_500),
            (1_000, Some(500), 50),
        ] {
            let tx = TestTx {
                value: U256::from(123),
                gas_limit: 100_000,
                gas_price,
                priority_fee,
                nonce: 7,
                ..TestTx::call(CALLER, OTHER)
            };
            let mut caller = funded_caller();
            caller.nonce = 7;
            let mut scenario = Scenario::new(spec, vec![caller], tx);
            scenario.basefee = basefee;
            scenario.watch.push(OTHER);
            assert_valid_parity(&scenario);
        }
    }
}

#[test]
fn fee_only_admission_matches() {
    let gas_limit = 100_000u64;
    let gas_price = 1_000_000_000u128;
    let fee = gas_limit as u128 * gas_price;
    for spec in MonadHardfork::ALL {
        for balance in [fee - 1, fee, fee + 1] {
            let tx = TestTx {
                value: U256::from(2),
                gas_limit,
                gas_price,
                ..TestTx::call(CALLER, OTHER)
            };
            let mut scenario =
                Scenario::new(spec, vec![TestAccount::new(CALLER).balance(balance)], tx);
            scenario.watch.push(OTHER);
            assert_parity(&scenario);
        }
    }
}

#[test]
fn refunds_are_disabled() {
    // Clearing a slot would earn a refund on Ethereum.
    let code = vec![op::PUSH0, op::PUSH0, op::SSTORE, op::STOP];
    for spec in MonadHardfork::ALL {
        let scenario = Scenario::new(
            spec,
            vec![
                funded_caller(),
                TestAccount::new(TARGET).code(code.clone()).storage(U256::ZERO, U256::from(5)),
            ],
            TestTx { gas_price: 7, ..TestTx::call(CALLER, TARGET) },
        );
        assert_valid_parity(&scenario);
    }
}

#[test]
fn delegated_account_cannot_create() {
    // A delegated EOA runs CREATE through its delegate's code.
    let mut creator = vec![op::PUSH0, op::PUSH0, op::PUSH0, op::CREATE];
    creator.extend_from_slice(&[op::PUSH0, op::MSTORE, op::PUSH1, 0x20, op::PUSH0, op::RETURN]);
    for spec in MonadHardfork::ALL {
        let scenario = Scenario::new(
            spec,
            vec![
                funded_caller(),
                TestAccount::new(TARGET).delegate(OTHER),
                TestAccount::new(OTHER).code(creator.clone()),
            ],
            TestTx::call(CALLER, TARGET),
        );
        let observed = assert_valid_parity(&scenario);
        assert!(matches!(observed.outcome, Outcome::Halt { .. }), "{observed:?}");
        // The same code creates normally when it is not running for a delegated account.
        let scenario = Scenario::new(
            spec,
            vec![funded_caller(), TestAccount::new(TARGET).code(creator.clone())],
            TestTx::call(CALLER, TARGET),
        );
        let observed = assert_valid_parity(&scenario);
        assert!(matches!(observed.outcome, Outcome::Success { .. }), "{observed:?}");
    }
}

fn precompile_call(address: Address, input: &[u8], gas: u32) -> Vec<u8> {
    let mut code = Vec::new();
    for (index, chunk) in input.chunks(32).enumerate() {
        let mut word = [0u8; 32];
        word[..chunk.len()].copy_from_slice(chunk);
        code.push(0x7f); // PUSH32
        code.extend_from_slice(&word);
        push_u32(&mut code, index as u32 * 32);
        code.push(op::MSTORE);
    }
    let mut call = Vec::new();
    push_u32(&mut call, 0x40);
    push_u32(&mut call, 0x1000);
    push_u32(&mut call, input.len() as u32);
    call.push(op::PUSH0);
    call.push(op::PUSH0);
    push_address(&mut call, address);
    push_u32(&mut call, gas);
    call.push(op::CALL);
    call.push(op::POP);
    code.extend_from_slice(&measure(&call));
    code
}

#[test]
fn precompile_pricing_matches() {
    let ecrecover = alloy_primitives::hex!(
        "456e9aea5e197a1f1af7a3e85a3212fa4049a3ba34c2289b4c860fc0b0c64ef3"
        "000000000000000000000000000000000000000000000000000000000000001c"
        "9242685bf161793cc25603c231bc2f568eb630ea16aa137d2664ac8038825608"
        "4f8ae3bd7535248d0bd448298cc2e2071e56992d0774dc340c368ae950852ada"
    );
    let ec_add = alloy_primitives::hex!(
        "0000000000000000000000000000000000000000000000000000000000000001"
        "0000000000000000000000000000000000000000000000000000000000000002"
        "0000000000000000000000000000000000000000000000000000000000000001"
        "0000000000000000000000000000000000000000000000000000000000000002"
    );
    let ec_mul = alloy_primitives::hex!(
        "0000000000000000000000000000000000000000000000000000000000000001"
        "0000000000000000000000000000000000000000000000000000000000000002"
        "0000000000000000000000000000000000000000000000000000000000000002"
    );
    let mut blake2f = vec![0u8; 213];
    blake2f[3] = 12;
    blake2f[212] = 1;
    let cases: Vec<(u64, Vec<u8>)> = vec![
        (0x01, ecrecover.to_vec()),
        (0x02, b"monad".to_vec()),
        (0x04, b"identity".to_vec()),
        (0x06, ec_add.to_vec()),
        (0x07, ec_mul.to_vec()),
        (0x08, Vec::new()),
        (0x09, blake2f),
        (0x0a, vec![0u8; 192]),
        (0x100, vec![0u8; 160]),
    ];
    for spec in MonadHardfork::ALL {
        for (address, input) in &cases {
            for gas in [1_000_000u32, 5_999, 299] {
                let address = Address::from_word(U256::from(*address).into());
                let scenario = Scenario::new(
                    spec,
                    vec![
                        funded_caller(),
                        TestAccount::new(TARGET).code(precompile_call(address, input, gas)),
                    ],
                    TestTx { gas_limit: 2_000_000, ..TestTx::call(CALLER, TARGET) },
                );
                assert_valid_parity(&scenario);
            }
        }
    }
}

/// Code that calls `dippedIntoReserve()` and returns the result word.
fn reserve_query_code() -> Vec<u8> {
    let mut code = vec![op::PUSH4];
    code.extend_from_slice(&DIPPED_INTO_RESERVE_SELECTOR);
    code.extend_from_slice(&[op::PUSH0, op::MSTORE, op::PUSH1, 0x20, op::PUSH0, op::PUSH1, 0x04]);
    code.extend_from_slice(&[op::PUSH1, 0x1c, op::PUSH0]);
    push_address(&mut code, RESERVE_BALANCE_ADDRESS);
    code.extend_from_slice(&[op::GAS, op::CALL, op::POP, op::PUSH1, 0x20, op::PUSH0, op::RETURN]);
    code
}

#[test]
fn reserve_balance_initial_value_transfer_matches() {
    for spec in MonadHardfork::ALL {
        for restricted in [false, true] {
            for value in [1u64, 3] {
                let mut scenario = Scenario::new(
                    spec,
                    vec![
                        TestAccount::new(CALLER).balance(12),
                        TestAccount::new(TARGET).code(reserve_query_code()),
                    ],
                    TestTx {
                        value: U256::from(value),
                        gas_limit: 100_000,
                        ..TestTx::call(CALLER, TARGET)
                    },
                );
                scenario.chain.max_reserve_balance = U256::from(10);
                if restricted {
                    scenario.chain.parent_senders_and_authorities.insert(CALLER);
                }
                assert_valid_parity(&scenario);
            }
        }
    }
}

#[test]
fn reserve_balance_nested_debits_and_reverts_match() {
    // TARGET forwards value to THIRD from its own balance, then queries the precompile. The
    // forwarding call optionally reverts, which must restore the reserve state.
    let forwarder = |revert_child: bool| {
        let child = if revert_child { OTHER } else { THIRD };
        let mut code = call_code(op::CALL, child, 6, 0, 0);
        code.push(op::POP);
        code.extend_from_slice(&reserve_query_code());
        code
    };
    let reverter = {
        let mut code = call_code(op::CALL, THIRD, 6, 0, 0);
        code.push(op::POP);
        code.extend_from_slice(&[op::PUSH0, op::PUSH0, op::REVERT]);
        code
    };
    for spec in MonadHardfork::ALL {
        for revert_child in [false, true] {
            for (target_code, target_balance) in [(true, 10u128), (false, 10)] {
                let target = if target_code {
                    TestAccount::new(TARGET).code(forwarder(revert_child)).balance(target_balance)
                } else {
                    TestAccount::new(TARGET).delegate(OTHER).balance(target_balance)
                };
                let mut accounts = vec![funded_caller(), target];
                if target_code {
                    accounts.push(TestAccount::new(OTHER).code(reverter.clone()).balance(10));
                } else {
                    accounts.push(TestAccount::new(OTHER).code(forwarder(revert_child)));
                }
                let mut scenario = Scenario::new(spec, accounts, TestTx::call(CALLER, TARGET));
                scenario.chain.max_reserve_balance = U256::from(8);
                scenario.watch.push(THIRD);
                assert_valid_parity(&scenario);
            }
        }
    }
}

#[test]
fn reserve_balance_precompile_rejections_match() {
    for spec in MonadHardfork::ALL {
        for (opcode, value, selector_len, extra) in [
            (op::CALL, 0u32, 4u32, 0u32),
            (op::CALL, 1, 4, 0),
            (op::CALL, 0, 3, 0),
            (op::CALL, 0, 4, 32),
            (op::STATICCALL, 0, 4, 0),
            (op::DELEGATECALL, 0, 4, 0),
            (op::CALLCODE, 0, 4, 0),
        ] {
            let mut code = vec![op::PUSH4];
            code.extend_from_slice(&DIPPED_INTO_RESERVE_SELECTOR);
            code.extend_from_slice(&[op::PUSH1, 0xe0, 0x1b]); // SHL
            code.extend_from_slice(&[op::PUSH0, op::MSTORE]);
            let mut call = Vec::new();
            push_u32(&mut call, 0x20);
            push_u32(&mut call, 0x100);
            push_u32(&mut call, selector_len + extra);
            call.push(op::PUSH0);
            if matches!(opcode, op::CALL | op::CALLCODE) {
                push_u32(&mut call, value);
            }
            push_address(&mut call, RESERVE_BALANCE_ADDRESS);
            push_u32(&mut call, 50_000);
            call.push(opcode);
            code.extend_from_slice(&call);
            code.extend_from_slice(&[
                op::PUSH0,
                op::MSTORE,
                op::PUSH1,
                0x40,
                op::PUSH0,
                op::RETURN,
            ]);
            let scenario = Scenario::new(
                spec,
                vec![funded_caller(), TestAccount::new(TARGET).code(code).balance(10)],
                TestTx::call(CALLER, TARGET),
            );
            assert_valid_parity(&scenario);
        }
    }
}

#[test]
fn delegated_precompile_calls_match() {
    // A same-transaction delegation to the staking or reserve-balance precompile reverts, and a
    // delegation to identity dispatches to the precompile.
    for spec in MonadHardfork::ALL {
        for (delegate, input) in [
            (STAKING_ADDRESS, Bytes::from(vec![0x75, 0x79, 0x91, 0xa8])),
            (RESERVE_BALANCE_ADDRESS, Bytes::copy_from_slice(&DIPPED_INTO_RESERVE_SELECTOR)),
            (Address::with_last_byte(4), Bytes::from_static(b"echo")),
        ] {
            let tx = TestTx {
                data: input,
                priority_fee: Some(0),
                authorizations: vec![(OTHER, delegate, 0)],
                ..TestTx::call(CALLER, OTHER)
            };
            let scenario = Scenario::new(spec, vec![funded_caller()], tx);
            assert_parity(&scenario);
        }
    }
}

#[test]
fn reserve_tracker_observes_same_transaction_sender_delegation() {
    for spec in MonadHardfork::ALL {
        let tx = TestTx {
            value: U256::from(3),
            gas_limit: 100_000,
            priority_fee: Some(0),
            authorizations: vec![(CALLER, THIRD, 1)],
            ..TestTx::call(CALLER, TARGET)
        };
        let mut scenario = Scenario::new(
            spec,
            vec![
                TestAccount::new(CALLER).balance(12),
                TestAccount::new(TARGET).code(reserve_query_code()),
            ],
            tx,
        );
        scenario.chain.max_reserve_balance = U256::from(10);
        assert_valid_parity(&scenario);
    }
}

#[test]
fn transaction_rejections_match_monad_revm() {
    for spec in MonadHardfork::ALL {
        // EIP-7702 with the system sender as an authority.
        let tx = TestTx {
            priority_fee: Some(0),
            authorizations: vec![
                (Address::with_last_byte(5), OTHER, 0),
                (SYSTEM_ADDRESS, OTHER, 0),
            ],
            ..TestTx::call(CALLER, OTHER)
        };
        let scenario = Scenario::new(spec, vec![funded_caller()], tx);
        assert_eq!(run_revm(&scenario).outcome, Outcome::Invalid);
        let (observed, error) = run_evm2_with(&scenario, |_| {});
        assert_eq!(observed.outcome, Outcome::Invalid);
        let error = error.unwrap().unwrap_err();
        assert_eq!(
            error.external_ref::<MonadInvalidTransaction>(),
            Some(&MonadInvalidTransaction::SystemTransactionSenderIsAuthority)
        );

        // Gas limit above the 30M Monad cap.
        let tx = TestTx { gas_limit: 30_000_001, ..TestTx::call(CALLER, OTHER) };
        let scenario = Scenario::new(spec, vec![funded_caller()], tx);
        assert_parity(&scenario);
        let tx = TestTx { gas_limit: 30_000_000, ..TestTx::call(CALLER, OTHER) };
        let scenario = Scenario::new(spec, vec![funded_caller()], tx);
        assert_parity(&scenario);
    }
}

#[test]
fn blob_transactions_are_rejected() {
    use alloy_consensus::{TxEip4844, transaction::TxEip4844Variant};
    let factory = MonadEvmFactory;
    for spec in MonadHardfork::ALL {
        let mut evm =
            factory.create_evm(spec, monad_version(spec, 1), Default::default(), Evm2Db::default());
        let tx = Recovered::new_unchecked(
            TxEnvelope::Eip4844(TxEip4844Variant::TxEip4844(TxEip4844 {
                chain_id: 1,
                blob_versioned_hashes: vec![Default::default()],
                ..Default::default()
            })),
            CALLER,
        );
        let error = evm.transact(&tx).map(|executed| executed.discard()).unwrap_err();
        assert_eq!(
            error.external_ref::<MonadInvalidTransaction>(),
            Some(&MonadInvalidTransaction::Eip4844NotSupported)
        );
    }
}

#[test]
fn staking_view_and_rejections_match() {
    use crate::staking::interface::IMonadStaking::*;
    use alloy_sol_types::SolCall;
    let epoch_slot = U256::from(1);
    let mut epoch_word = [0u8; 32];
    epoch_word[..8].copy_from_slice(&9u64.to_be_bytes());
    for spec in MonadHardfork::ALL {
        for (opcode, input, value) in [
            (op::CALL, getEpochCall::SELECTOR.to_vec(), 0u32),
            (op::CALL, getEpochCall::SELECTOR.to_vec(), 1),
            (op::CALL, vec![0xde, 0xad], 0),
            (op::CALL, vec![0xde, 0xad, 0xbe, 0xef], 0),
            (op::STATICCALL, getEpochCall::SELECTOR.to_vec(), 0),
            (op::CALL, getProposerValIdCall::SELECTOR.to_vec(), 0),
            (op::CALL, getValidatorCall { validatorId: 1 }.abi_encode(), 0),
            (op::CALL, getDelegatorCall { validatorId: 1, delegator: TARGET }.abi_encode(), 0),
            (op::CALL, getConsensusValidatorSetCall { startIndex: 0 }.abi_encode(), 0),
            (op::CALL, delegateCall { validatorId: 1 }.abi_encode(), 0),
            (op::CALL, syscallSnapshotCall {}.abi_encode(), 0),
        ] {
            let mut code = Vec::new();
            for (index, chunk) in input.chunks(32).enumerate() {
                let mut word = [0u8; 32];
                word[..chunk.len()].copy_from_slice(chunk);
                code.push(0x7f);
                code.extend_from_slice(&word);
                push_u32(&mut code, index as u32 * 32);
                code.push(op::MSTORE);
            }
            let mut call = Vec::new();
            push_u32(&mut call, 0x100);
            push_u32(&mut call, 0x1000);
            push_u32(&mut call, input.len() as u32);
            call.push(op::PUSH0);
            if opcode == op::CALL {
                push_u32(&mut call, value);
            }
            push_address(&mut call, STAKING_ADDRESS);
            push_u32(&mut call, 1_000_000);
            call.push(opcode);
            code.extend_from_slice(&call);
            code.extend_from_slice(&[op::PUSH0, op::MSTORE]);
            code.extend_from_slice(&[op::PUSH2, 0x11, 0x00, op::PUSH0, op::RETURN]);
            let scenario = Scenario::new(
                spec,
                vec![
                    funded_caller(),
                    TestAccount::new(TARGET).code(code).balance(10),
                    // A non-empty staking account, so EIP-161 cleanup keeps its storage.
                    TestAccount::new(STAKING_ADDRESS)
                        .balance(1)
                        .storage(epoch_slot, U256::from_be_bytes(epoch_word)),
                ],
                TestTx { gas_limit: 3_000_000, ..TestTx::call(CALLER, TARGET) },
            );
            assert_valid_parity(&scenario);
        }
    }
}

/// `monad-revm` vectors: MIP-8 warms a whole page on SLOAD and amortizes SSTORE per page.
#[test]
fn mip8_vectors() {
    use crate::{COLD_SLOAD_COST, WARM_STORAGE_READ_COST, page::PAGE_WRITE_COST};
    let run = |spec, opcode, second_slot| {
        let code = measure(&storage_ops(opcode, &[0, second_slot]));
        let scenario = Scenario::new(
            spec,
            vec![funded_caller(), TestAccount::new(TARGET).code(code)],
            TestTx::call(CALLER, TARGET),
        );
        measured_gas(&assert_valid_parity(&scenario))
    };
    for spec in [MonadHardfork::MonadTen, MonadHardfork::MonadNext] {
        let same_page = run(spec, op::SLOAD, 127);
        let different_page = run(spec, op::SLOAD, 128);
        assert_eq!(different_page - same_page, COLD_SLOAD_COST - WARM_STORAGE_READ_COST);
        let same_page = run(spec, op::SSTORE, 1);
        let different_page = run(spec, op::SSTORE, 128);
        assert_eq!(
            different_page - same_page,
            COLD_SLOAD_COST - WARM_STORAGE_READ_COST + PAGE_WRITE_COST
        );
    }
    for spec in [MonadHardfork::MonadEight, MonadHardfork::MonadNine] {
        assert_eq!(run(spec, op::SLOAD, 127), run(spec, op::SLOAD, 128));
        assert_eq!(run(spec, op::SSTORE, 1), run(spec, op::SSTORE, 128));
    }
}

/// MIP-3: linear memory pricing and the 8 MiB limit apply from MonadNine.
#[test]
fn mip3_vectors() {
    for spec in MonadHardfork::ALL {
        let mut body = vec![op::PUSH0];
        push_u32(&mut body, 0x2000);
        body.push(op::MSTORE);
        let scenario = Scenario::new(
            spec,
            vec![funded_caller(), TestAccount::new(TARGET).code(measure(&body))],
            TestTx::call(CALLER, TARGET),
        );
        let gas = measured_gas(&assert_valid_parity(&scenario));
        let words = (0x2000 + 0x20) / 32;
        // PUSH0 (2) + PUSH4 (3) + MSTORE (3) + GAS (2) around the expansion.
        let expansion = if MonadHardfork::MonadNine.is_enabled_in(spec) {
            crate::memory::monad_memory_cost(words)
        } else {
            3 * words as u64 + (words * words) as u64 / 512
        };
        assert_eq!(gas, 2 + 3 + 3 + 2 + expansion, "{spec}");

        for (offset, fits) in [(0x7fffe0u32, true), (0x800000, false)] {
            let mut code = vec![op::PUSH0];
            push_u32(&mut code, offset);
            code.extend_from_slice(&[op::MSTORE, op::STOP]);
            let scenario = Scenario::new(
                spec,
                vec![funded_caller(), TestAccount::new(TARGET).code(code)],
                TestTx { gas_limit: 30_000_000, ..TestTx::call(CALLER, TARGET) },
            );
            let observed = assert_valid_parity(&scenario);
            if MonadHardfork::MonadNine.is_enabled_in(spec) {
                // Linear pricing makes 8 MiB affordable; one more word hits the limit.
                assert_eq!(
                    matches!(observed.outcome, Outcome::Success { .. }),
                    fits,
                    "{spec}: {:?}",
                    observed.outcome
                );
            } else {
                // Quadratic pricing makes 8 MiB unaffordable within 30M gas.
                assert!(matches!(observed.outcome, Outcome::Halt { .. }), "{spec}");
            }
        }
    }
}

/// Staking pre-state with one registered validator for `author`, mirroring Foundry's replay test.
fn staking_prestate(author: Address, auth: Address, staking_balance: u128) -> Vec<TestAccount> {
    use crate::staking::storage::{
        consensus_view_key, val_id_secp_key, validator_key, validator_offsets,
    };
    let validator_id = 7u64;
    let mut staking = TestAccount::new(STAKING_ADDRESS).balance(staking_balance);
    // Monad stores validator IDs and packed address/flags values left-aligned.
    staking = staking.storage(val_id_secp_key(&author), U256::from(validator_id) << 192);
    staking = staking.storage(consensus_view_key(validator_id, 0), U256::from(100) * MON);
    staking = staking.storage(consensus_view_key(validator_id, 1), U256::ZERO);
    staking = staking.storage(
        validator_key(validator_id, validator_offsets::ADDRESS_FLAGS),
        U256::from_be_slice(auth.as_slice()) << 96,
    );
    staking = staking
        .storage(validator_key(validator_id, validator_offsets::STAKE), U256::from(100) * MON);
    vec![staking, TestAccount::new(SYSTEM_ADDRESS)]
}

const MON: U256 = crate::staking::constants::MON;

/// Changed staking storage, sorted by key.
type StorageDiff = Vec<(U256, U256)>;

fn revm_staking_syscall(
    accounts: &[TestAccount],
    data: Bytes,
) -> (bool, u64, Vec<Log>, StorageDiff) {
    use revm::handler::SystemCallEvm;
    let scenario =
        Scenario::new(MonadHardfork::MonadNine, accounts.to_vec(), TestTx::call(CALLER, OTHER));
    let mut db = RevmDb::default();
    for account in &scenario.accounts {
        let info = RevmAccountInfo { balance: account.balance, ..Default::default() };
        db.insert_account_info(account.address, info);
        for (key, value) in &account.storage {
            db.insert_account_storage(account.address, *key, *value).unwrap();
        }
    }
    let ctx = monad_revm::monad_context_with_db(db)
        .with_cfg(monad_revm::MonadCfgEnv::new_with_spec(monad_revm::MonadHardfork::MonadNine));
    let mut evm = ctx.build_monad();
    let result = evm.system_call_with_caller(SYSTEM_ADDRESS, STAKING_ADDRESS, data).unwrap();
    let mut storage: StorageDiff = result
        .state
        .get(&STAKING_ADDRESS)
        .map(|account| {
            account
                .storage
                .iter()
                .filter(|(_, slot)| slot.is_changed())
                .map(|(key, slot)| (*key, slot.present_value))
                .collect()
        })
        .unwrap_or_default();
    storage.sort();
    (
        result.result.is_success(),
        result.result.tx_gas_used(),
        result.result.logs().to_vec(),
        storage,
    )
}

fn evm2_staking_syscall(
    accounts: &[TestAccount],
    data: Bytes,
    keys: &[U256],
) -> (bool, u64, Vec<Log>, StorageDiff) {
    let scenario =
        Scenario::new(MonadHardfork::MonadNine, accounts.to_vec(), TestTx::call(CALLER, OTHER));
    let factory = MonadEvmFactory;
    let spec = MonadHardfork::MonadNine;
    let mut evm =
        factory.create_evm(spec, monad_version(spec, 1), Default::default(), evm2_db(&scenario));
    let result = evm.system_call(crate::staking_system_tx(data)).unwrap().commit();
    let storage = keys
        .iter()
        .map(|key| (*key, evm.state_mut().read_committed_storage(&STAKING_ADDRESS, key).unwrap()))
        .collect();
    (result.status, result.tx_gas_used(), result.logs, storage)
}

#[test]
fn staking_syscalls_match() {
    let author = Address::repeat_byte(0x55);
    let auth = Address::repeat_byte(0x66);
    let reward = U256::from(25) * MON;
    let accounts =
        staking_prestate(author, auth, 3_000_000_000_000_000_000 + 25_000_000_000_000_000_000);
    for data in [
        crate::syscall_reward_calldata(author, reward),
        crate::syscall_reward_calldata(Address::repeat_byte(0x77), reward),
        crate::syscall_snapshot_calldata(),
        crate::syscall_on_epoch_change_calldata(1),
    ] {
        let expected = revm_staking_syscall(&accounts, data.clone());
        let keys: Vec<_> = expected.3.iter().map(|(key, _)| *key).collect();
        let actual = evm2_staking_syscall(&accounts, data, &keys);
        // System calls report no gas on either side; compare status, logs and storage.
        assert_eq!((actual.0, &actual.2, &actual.3), (expected.0, &expected.2, &expected.3));
    }
    // The registered-author reward writes the proposer and unclaimed rewards.
    let expected = revm_staking_syscall(&accounts, crate::syscall_reward_calldata(author, reward));
    assert!(expected.0);
    assert_eq!(expected.2.len(), 1);
    assert!(!expected.3.is_empty());
}

#[test]
fn staking_user_writes_match() {
    use crate::staking::interface::IMonadStaking::*;
    use alloy_sol_types::SolCall;
    let author = Address::repeat_byte(0x55);
    let auth = Address::repeat_byte(0x66);
    for spec in MonadHardfork::ALL {
        let mut changed_slots = 0;
        for (input, value) in [
            (delegateCall { validatorId: 7 }.abi_encode(), 1_000_000_000_000_000_000u128),
            (delegateCall { validatorId: 7 }.abi_encode(), 1),
            (delegateCall { validatorId: 8 }.abi_encode(), 1_000_000_000_000_000_000),
            (externalRewardCall { validatorId: 7 }.abi_encode(), 1_000_000_000_000_000_000),
            (
                undelegateCall { validatorId: 7, amount: U256::from(1), withdrawId: 0 }
                    .abi_encode(),
                0,
            ),
            (claimRewardsCall { validatorId: 7 }.abi_encode(), 0),
            (changeCommissionCall { validatorId: 7, commission: U256::from(5) }.abi_encode(), 0),
        ] {
            let mut accounts = staking_prestate(author, auth, 1_000_000_000_000_000_000);
            accounts.push(funded_caller());
            let tx = TestTx {
                data: input.into(),
                value: U256::from(value),
                gas_limit: 2_000_000,
                ..TestTx::call(CALLER, STAKING_ADDRESS)
            };
            let mut scenario = Scenario::new(spec, accounts, tx);
            // Discover every staking slot the reference implementation changed.
            let mut discovery = scenario.clone();
            discovery.watch_storage.clear();
            let reference = run_revm_changed_storage(&discovery, STAKING_ADDRESS);
            changed_slots += reference.len();
            scenario.watch_storage.extend(reference.into_iter().map(|key| (STAKING_ADDRESS, key)));
            assert_valid_parity(&scenario);
        }
        assert!(changed_slots > 10, "{spec}: {changed_slots}");
    }
}

/// Returns the storage keys of `address` that `monad-revm` changed for `scenario`.
fn run_revm_changed_storage(scenario: &Scenario, address: Address) -> Vec<U256> {
    let mut db = RevmDb::default();
    for account in &scenario.accounts {
        let mut info = RevmAccountInfo::default()
            .with_code(RevmBytecode::new_raw(account.code.clone().into()));
        info.balance = account.balance;
        info.nonce = account.nonce;
        db.insert_account_info(account.address, info);
        for (key, value) in &account.storage {
            db.insert_account_storage(account.address, *key, *value).unwrap();
        }
    }
    let ctx = monad_revm::monad_context_with_db(db)
        .with_cfg(monad_revm::MonadCfgEnv::new_with_spec(their_spec(scenario.spec)));
    let mut evm = ctx.build_monad();
    let tx = &scenario.tx;
    let tx_env = TxEnv::builder()
        .caller(tx.caller)
        .kind(tx.to)
        .value(tx.value)
        .data(tx.data.clone())
        .gas_limit(tx.gas_limit)
        .gas_price(tx.gas_price)
        .nonce(tx.nonce)
        .chain_id(Some(1))
        .build_fill();
    let Ok(result) = evm.transact(tx_env) else { return Vec::new() };
    let mut keys: Vec<_> = result
        .state
        .get(&address)
        .map(|account| {
            account
                .storage
                .iter()
                .filter(|(_, slot)| slot.is_changed())
                .map(|(key, _)| *key)
                .collect()
        })
        .unwrap_or_default();
    keys.sort();
    keys
}

#[test]
fn preserved_tracker_survives_synthetic_transaction() {
    // Port of `synthetic_transaction_preserves_reserve_balance_tracker`.
    use crate::{ReserveAccount, ReserveBalanceInit};
    let sender = CALLER;
    let tracked = OTHER;
    let spec = MonadHardfork::MonadNine;
    let scenario = Scenario::new(
        spec,
        vec![TestAccount::new(sender).balance(u128::MAX), TestAccount::new(tracked).balance(1_000)],
        TestTx {
            data: Bytes::copy_from_slice(&DIPPED_INTO_RESERVE_SELECTOR),
            gas_limit: 100_000,
            ..TestTx::call(sender, RESERVE_BALANCE_ADDRESS)
        },
    );
    let (observed, ext) = run_evm2_with(&scenario, |evm| {
        let chain = evm.ext().chain.clone();
        let ext = evm.ext_mut();
        ext.reserve_balance.init(ReserveBalanceInit {
            chain: &chain,
            spec,
            sender,
            effective_gas_price: 0,
            gas_limit: 0,
            sender_is_delegated: false,
            sender_account: None,
        });
        let debited = ReserveAccount {
            balance: U256::from(999),
            original_balance: U256::from(1_000),
            code_hash: alloy_primitives::KECCAK256_EMPTY,
            original_code_hash: alloy_primitives::KECCAK256_EMPTY,
            ..Default::default()
        };
        ext.reserve_balance.on_debit(Some(&debited), tracked);
        assert!(ext.reserve_balance.has_violation());
        ext.set_preserve_reserve_balance_tracker(true);
    });
    let Outcome::Success { output, .. } = observed.outcome else { panic!("{observed:?}") };
    assert_eq!(output[31], 1);
    assert!(ext.unwrap().unwrap().dipped_into_reserve);
}

#[test]
fn opt_in_reserve_violation_revert() {
    // TARGET sends 6 of its 10 balance away with a reserve of 8, which violates the reserve.
    let mut code = call_code(op::CALL, THIRD, 6, 0, 0);
    code.extend_from_slice(&[op::POP, op::STOP]);
    let mut scenario = Scenario::new(
        MonadHardfork::MonadNine,
        vec![
            funded_caller(),
            TestAccount::new(TARGET).delegate(OTHER).balance(10),
            TestAccount::new(OTHER).code(code),
        ],
        TestTx::call(CALLER, TARGET),
    );
    scenario.chain.max_reserve_balance = U256::from(8);
    scenario.watch.push(THIRD);

    let (default_run, ext) = run_evm2_with(&scenario, |_| {});
    let ext = ext.unwrap().unwrap();
    assert!(matches!(default_run.outcome, Outcome::Success { .. }));
    assert!(ext.dipped_into_reserve);
    assert!(!ext.reverted_for_reserve_balance);
    assert_eq!(default_run, run_revm(&scenario));

    let (enforced, ext) =
        run_evm2_with(&scenario, |evm| evm.ext_mut().revert_on_reserve_balance_violation = true);
    let ext = ext.unwrap().unwrap();
    assert!(matches!(enforced.outcome, Outcome::Revert { .. }), "{enforced:?}");
    assert!(ext.reverted_for_reserve_balance);
    assert!(!ext.dipped_into_reserve);
    let third = enforced.balances.iter().find(|(address, _)| *address == THIRD).unwrap();
    assert_eq!(third.1, U256::ZERO);
}

#[test]
fn create_transaction_code_size_limits_match() {
    // Initcode returning `size` zero bytes; Monad allows 128 KiB of deployed code.
    for spec in MonadHardfork::ALL {
        for size in [0x6001u32, 0x20000, 0x20001] {
            let mut initcode = Vec::new();
            push_u32(&mut initcode, size);
            initcode.extend_from_slice(&[op::PUSH0, op::RETURN]);
            let tx = TestTx {
                to: TxKind::Create,
                data: initcode.into(),
                gas_limit: 30_000_000,
                ..TestTx::call(CALLER, OTHER)
            };
            let scenario = Scenario::new(spec, vec![funded_caller()], tx);
            let observed = assert_valid_parity(&scenario);
            assert_eq!(
                matches!(observed.outcome, Outcome::Success { .. }),
                size <= 0x20000,
                "{spec} {size}"
            );
        }
        // Initcode above the 256 KiB Monad limit is rejected, at the limit it is admitted.
        for size in [0x40000usize, 0x40001] {
            let tx = TestTx {
                to: TxKind::Create,
                data: vec![0u8; size].into(),
                gas_limit: 30_000_000,
                ..TestTx::call(CALLER, OTHER)
            };
            let scenario = Scenario::new(spec, vec![funded_caller()], tx);
            let observed = assert_parity(&scenario);
            assert_eq!(observed.outcome == Outcome::Invalid, size > 0x40000, "{spec} {size}");
        }
    }
}

#[test]
fn reserve_balance_create_and_selfdestruct_debits_match() {
    // A delegated EOA endows a contract via CREATE (blocked for delegated accounts) or sends its
    // balance away via SELFDESTRUCT from a delegate, then queries the reserve precompile.
    let mut creator = vec![op::PUSH0, op::PUSH0];
    push_u32(&mut creator, 5);
    creator.extend_from_slice(&[op::CREATE, op::POP]);
    creator.extend_from_slice(&reserve_query_code());
    let mut destroyer = call_code(op::CALL, THIRD, 0, 0, 0);
    destroyer.push(op::POP);
    destroyer.extend_from_slice(&reserve_query_code());
    let mut selfdestructing = Vec::new();
    push_address(&mut selfdestructing, OTHER);
    selfdestructing.push(op::SELFDESTRUCT);
    for spec in MonadHardfork::ALL {
        for (target, extra) in [
            (TestAccount::new(TARGET).code(creator.clone()).balance(10), None),
            (TestAccount::new(TARGET).delegate(OTHER).balance(10), Some(creator.clone())),
            (
                TestAccount::new(TARGET).code(destroyer.clone()).balance(10),
                Some(selfdestructing.clone()),
            ),
        ] {
            let mut accounts = vec![funded_caller(), target];
            if let Some(code) = extra {
                let address = if code == selfdestructing { THIRD } else { OTHER };
                accounts.push(TestAccount::new(address).code(code).balance(10));
            }
            let mut scenario = Scenario::new(spec, accounts, TestTx::call(CALLER, TARGET));
            scenario.chain.max_reserve_balance = U256::from(8);
            scenario.watch.extend([OTHER, THIRD]);
            assert_valid_parity(&scenario);
        }
    }
}

/// Runs `scenario` on evm2 with `features` removed from the Monad version.
fn run_evm2_without(scenario: &Scenario, features: evm2::EvmFeatures) -> Observed {
    let factory = MonadEvmFactory;
    let block = crate::MonadBlockEnv {
        basefee: U256::from(scenario.basefee),
        beneficiary: scenario.beneficiary,
        ..Default::default()
    };
    let mut version = monad_version(scenario.spec, 1);
    version.features.remove(features);
    let mut evm = factory.create_evm(scenario.spec, version, block, evm2_db(scenario));
    let tx = Recovered::new_unchecked(evm2_envelope(&scenario.tx), scenario.tx.caller);
    let outcome = match evm.transact(&tx) {
        Ok(executed) => {
            let result = executed.commit();
            if result.status {
                Outcome::Success {
                    gas_used: result.tx_gas_used(),
                    output: result.output,
                    logs: result.logs,
                }
            } else {
                Outcome::Halt { gas_used: result.tx_gas_used() }
            }
        }
        Err(_) => Outcome::Invalid,
    };
    let balances = scenario
        .watch
        .iter()
        .map(|address| {
            let info = evm.read_account_info(address).unwrap();
            (*address, info.map_or(U256::ZERO, |info| info.balance))
        })
        .collect();
    Observed { outcome, balances, storage: Vec::new() }
}

#[test]
fn standard_feature_flags_are_honored() {
    use evm2::EvmFeatures;
    let balance_of = |observed: &Observed, address: Address| {
        observed.balances.iter().find(|(a, _)| *a == address).unwrap().1
    };
    for spec in MonadHardfork::ALL {
        // `monad-revm` `test_balance_check_disabled_skips_fee_rejection_and_preserves_value_path`.
        let tx = TestTx {
            value: U256::from(2),
            gas_limit: 100_000,
            gas_price: 1_000_000_000,
            ..TestTx::call(CALLER, OTHER)
        };
        let mut scenario = Scenario::new(spec, vec![TestAccount::new(CALLER).balance(1)], tx);
        scenario.watch.push(OTHER);
        assert_eq!(run_evm2(&scenario).outcome, Outcome::Invalid);
        let observed = run_evm2_without(&scenario, EvmFeatures::BALANCE_CHECK);
        assert!(matches!(observed.outcome, Outcome::Success { .. }), "{observed:?}");
        assert_eq!(balance_of(&observed, CALLER), U256::ZERO);
        assert_eq!(balance_of(&observed, OTHER), U256::from(2));

        // Without fee charging nothing is deducted and the beneficiary is not paid.
        let tx = TestTx { gas_limit: 100_000, gas_price: 7, ..TestTx::call(CALLER, OTHER) };
        let scenario = Scenario::new(spec, vec![TestAccount::new(CALLER).balance(1_000_000)], tx);
        let observed = run_evm2_without(&scenario, EvmFeatures::FEE_CHARGE);
        assert_eq!(balance_of(&observed, CALLER), U256::from(1_000_000));
        assert_eq!(balance_of(&observed, scenario.beneficiary), U256::ZERO);
        let observed = run_evm2(&scenario);
        assert_eq!(balance_of(&observed, CALLER), U256::from(1_000_000 - 700_000));
        assert_eq!(balance_of(&observed, scenario.beneficiary), U256::from(700_000));

        // Nonce, base fee, chain ID, block gas limit and EIP-3607 checks can be disabled.
        let tx = TestTx { nonce: 5, ..TestTx::call(CALLER, OTHER) };
        let scenario = Scenario::new(spec, vec![funded_caller()], tx);
        assert_eq!(run_evm2(&scenario).outcome, Outcome::Invalid);
        let observed = run_evm2_without(&scenario, EvmFeatures::NONCE_CHECK);
        assert!(matches!(observed.outcome, Outcome::Success { .. }));

        let tx = TestTx { gas_price: 1, ..TestTx::call(CALLER, OTHER) };
        let mut scenario = Scenario::new(spec, vec![funded_caller()], tx);
        scenario.basefee = 10;
        assert_eq!(run_evm2(&scenario).outcome, Outcome::Invalid);
        let observed = run_evm2_without(&scenario, EvmFeatures::BASE_FEE_CHECK);
        assert!(matches!(observed.outcome, Outcome::Success { .. }));

        let scenario = Scenario::new(
            spec,
            vec![funded_caller().code(vec![op::STOP])],
            TestTx::call(CALLER, OTHER),
        );
        assert_eq!(run_evm2(&scenario).outcome, Outcome::Invalid);
        let observed = run_evm2_without(&scenario, EvmFeatures::EIP3607);
        assert!(matches!(observed.outcome, Outcome::Success { .. }));
    }
}

/// Records the pc the message hooks see while stepping no opcode.
#[derive(Default)]
struct MessagePcs(Vec<usize>);

impl Inspector<crate::MonadEvmTypes> for MessagePcs {
    fn inspector_config(&self) -> InspectorConfig {
        InspectorConfig::new().with_steps(OpcodeSet::EMPTY)
    }

    fn call(
        &mut self,
        interp: &mut Interpreter<'_, '_, crate::MonadEvmTypes>,
        message: &mut Message<crate::MonadEvmTypes>,
    ) -> Option<MessageResult<crate::MonadEvmTypes>> {
        if message.depth > 0 {
            self.0.push(interp.pc());
        }
        None
    }

    fn create(
        &mut self,
        interp: &mut Interpreter<'_, '_, crate::MonadEvmTypes>,
        _message: &mut Message<crate::MonadEvmTypes>,
    ) -> Option<MessageResult<crate::MonadEvmTypes>> {
        self.0.push(interp.pc());
        None
    }
}

#[test]
fn message_hooks_see_monad_message_opcodes_without_steps() {
    let mut code = Vec::new();
    let mut expected = Vec::new();
    for opcode in [op::CALL, op::CALLCODE, op::DELEGATECALL, op::STATICCALL] {
        code.extend(call_code(opcode, OTHER, 0, 0, 0));
        expected.push(code.len() - 1);
        code.push(op::POP);
    }
    // A one-byte initcode, `STOP`, from zeroed memory.
    for opcode in [op::CREATE, op::CREATE2] {
        if opcode == op::CREATE2 {
            code.push(op::PUSH0);
        }
        code.extend([op::PUSH1, 1, op::PUSH0, op::PUSH0, opcode]);
        expected.push(code.len() - 1);
        code.push(op::POP);
    }
    code.push(op::STOP);

    let scenario = Scenario::new(
        MonadHardfork::ALL[MonadHardfork::ALL.len() - 1],
        vec![
            funded_caller(),
            TestAccount::new(TARGET).code(code),
            TestAccount::new(OTHER).code(vec![op::STOP]),
        ],
        TestTx::call(CALLER, TARGET),
    );
    let mut evm = MonadEvmFactory.create_evm(
        scenario.spec,
        monad_version(scenario.spec, 1),
        crate::MonadBlockEnv::default(),
        evm2_db(&scenario),
    );
    let tx = Recovered::new_unchecked(evm2_envelope(&scenario.tx), scenario.tx.caller);
    let mut inspector = MessagePcs::default();
    let executed = evm.transact_with_inspector(&tx, &mut inspector).unwrap();
    assert!(executed.commit().status);
    assert_eq!(inspector.0, expected);
}
