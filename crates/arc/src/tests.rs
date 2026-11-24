//! Execution tests; expected values follow arc-node v0.8.6, not this implementation.

use crate::{
    ARC_MAINNET_CHAIN_ID, ARC_TESTNET_CHAIN_ID, ArcEvmFactory, ArcEvmTypes, ArcHardfork, ArcSpecId,
    ArcTxError, CALL_FROM_ADDRESS, MULTICALL3_FROM_ADDRESS, NATIVE_COIN_AUTHORITY_ADDRESS,
    NATIVE_COIN_CONTROL_ADDRESS, NATIVE_FIAT_TOKEN_ADDRESS, PQ_ADDRESS, arc_precompiles,
    arc_spec_at, arc_spec_at_timestamp,
    precompiles::{ICallFrom, INativeCoinAuthority, INativeCoinControl, IPQ},
    transfer::{ERR_BLOCKED_ADDRESS, ERR_ZERO_ADDRESS, blocklist_slot, revert_reason},
};
use alloy_consensus::{TxEip1559, transaction::Recovered};
use alloy_primitives::{Address, B256, Bytes, Log, TxKind, U256, address, b256};
use alloy_sol_types::{SolCall, SolValue};
use evm2::{
    SpecId, TxResult,
    bytecode::Bytecode,
    env::BlockEnv,
    ethereum::TxEnvelope,
    evm::{AccountInfo, InMemoryDB, PrewarmSet, SYSTEM_ADDRESS, precompile::PrecompileProvider},
    registry::HandlerError,
};

const CALLER: Address = address!("0x00000000000000000000000000000000000ca11e");
const CONTRACT: Address = address!("0x000000000000000000000000000000000000c0de");
const OTHER: Address = address!("0x0000000000000000000000000000000000000b0b");
const BENEFICIARY: Address = address!("0x00000000000000000000000000000000000000be");
const BALANCE: u64 = 1_000_000_000_000_000;
const BASEFEE: u128 = 20;
const GAS_PRICE: u128 = 25;
/// EIP-7708 `Transfer` topic.
const TRANSFER_TOPIC: B256 =
    b256!("0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef");

/// Opcodes used by the test contracts.
mod op {
    pub(super) const ADD: u8 = 0x01;
    pub(super) const CALLER: u8 = 0x33;
    pub(super) const CALLDATASIZE: u8 = 0x36;
    pub(super) const CALLDATACOPY: u8 = 0x37;
    pub(super) const RETURNDATASIZE: u8 = 0x3d;
    pub(super) const RETURNDATACOPY: u8 = 0x3e;
    pub(super) const MSTORE: u8 = 0x52;
    pub(super) const GAS: u8 = 0x5a;
    pub(super) const PUSH1: u8 = 0x60;
    pub(super) const PUSH20: u8 = 0x73;
    pub(super) const PUSH32: u8 = 0x7f;
    pub(super) const CALL: u8 = 0xf1;
    pub(super) const RETURN: u8 = 0xf3;
    pub(super) const DELEGATECALL: u8 = 0xf4;
    pub(super) const STATICCALL: u8 = 0xfa;
    pub(super) const SELFDESTRUCT: u8 = 0xff;
}

/// Pushes `address` with `PUSH20`.
fn push_address(code: &mut Vec<u8>, address: Address) {
    code.push(op::PUSH20);
    code.extend_from_slice(address.as_slice());
}

/// Returns the call's success word followed by its return data.
fn return_call_result(code: &mut Vec<u8>) {
    code.extend([op::PUSH1, 0, op::MSTORE]);
    code.extend([op::RETURNDATASIZE, op::PUSH1, 0, op::PUSH1, 32, op::RETURNDATACOPY]);
    code.extend([op::RETURNDATASIZE, op::PUSH1, 32, op::ADD, op::PUSH1, 0, op::RETURN]);
}

/// Forwards its calldata to `target` with `opcode` and returns the result.
fn proxy(opcode: u8, target: Address) -> Vec<u8> {
    let mut code = vec![op::CALLDATASIZE, op::PUSH1, 0, op::PUSH1, 0, op::CALLDATACOPY];
    code.extend([op::PUSH1, 0, op::PUSH1, 0, op::CALLDATASIZE, op::PUSH1, 0]);
    if opcode == op::CALL {
        code.extend([op::PUSH1, 0]);
    }
    push_address(&mut code, target);
    code.extend([op::GAS, opcode]);
    return_call_result(&mut code);
    code
}

/// Sends `value` to `target` with an empty `CALL` and returns the result.
fn send(target: Address, value: u64) -> Vec<u8> {
    let mut code = vec![op::PUSH1, 0, op::PUSH1, 0, op::PUSH1, 0, op::PUSH1, 0, op::PUSH32];
    code.extend_from_slice(&U256::from(value).to_be_bytes::<32>());
    push_address(&mut code, target);
    code.extend([op::GAS, op::CALL]);
    return_call_result(&mut code);
    code
}

/// Self-destructs to `target`.
fn selfdestruct(target: Address) -> Vec<u8> {
    let mut code = Vec::new();
    push_address(&mut code, target);
    code.push(op::SELFDESTRUCT);
    code
}

/// Returns `msg.sender` as a word.
fn echo_caller() -> Vec<u8> {
    vec![op::CALLER, op::PUSH1, 0, op::MSTORE, op::PUSH1, 32, op::PUSH1, 0, op::RETURN]
}

/// Chain state and transaction of one execution.
struct Run {
    spec: ArcSpecId,
    accounts: Vec<(Address, u64, Vec<u8>)>,
    storage: Vec<(Address, U256, U256)>,
    blocklist: Vec<Address>,
    to: TxKind,
    value: u64,
    input: Vec<u8>,
}

impl Run {
    fn new(to: Address) -> Self {
        Self {
            spec: ArcHardfork::LATEST.into(),
            accounts: vec![(CALLER, BALANCE, Vec::new())],
            storage: Vec::new(),
            blocklist: Vec::new(),
            to: TxKind::Call(to),
            value: 0,
            input: Vec::new(),
        }
    }

    fn account(mut self, address: Address, balance: u64, code: Vec<u8>) -> Self {
        self.accounts.push((address, balance, code));
        self
    }

    fn exec(&self) -> (Result<TxResult<ArcEvmTypes>, HandlerError>, Vec<U256>) {
        let mut db = InMemoryDB::default();
        // On Arc, the precompile accounts exist with nonce 1 and code `0xef`.
        for address in crate::ARC_PRECOMPILE_ADDRESSES {
            let code = Bytecode::new_raw(vec![0xef].into());
            db.insert_account_info(&address, AccountInfo::default().with_nonce(1).with_code(code));
        }
        for (address, balance, code) in &self.accounts {
            let mut info = AccountInfo::default().with_balance(U256::from(*balance));
            if !code.is_empty() {
                info = info.with_code(Bytecode::new_raw(code.clone().into()));
            }
            db.insert_account_info(address, info);
        }
        for (address, slot, value) in &self.storage {
            db.insert_account_storage(address, slot, value);
        }
        for account in &self.blocklist {
            db.insert_account_storage(
                &NATIVE_COIN_CONTROL_ADDRESS,
                &blocklist_slot(*account),
                &U256::from(1),
            );
        }
        let factory = ArcEvmFactory;
        let block = BlockEnv::<ArcEvmTypes> {
            number: U256::from(1),
            timestamp: U256::from(1_800_000_000u64),
            beneficiary: BENEFICIARY,
            basefee: U256::from(BASEFEE),
            gas_limit: U256::from(30_000_000),
            ..Default::default()
        };
        let mut evm = factory.create_evm(
            self.spec,
            factory.version(self.spec, ARC_MAINNET_CHAIN_ID),
            block,
            db,
        );
        let tx = TxEnvelope::Eip1559(TxEip1559 {
            chain_id: ARC_MAINNET_CHAIN_ID,
            gas_limit: 1_000_000,
            max_fee_per_gas: GAS_PRICE,
            max_priority_fee_per_gas: GAS_PRICE,
            to: self.to,
            value: U256::from(self.value),
            input: self.input.clone().into(),
            ..Default::default()
        });
        let result = evm.transact(&Recovered::new_unchecked(tx, CALLER)).map(|tx| tx.commit());
        let balances = [CALLER, CONTRACT, OTHER, BENEFICIARY]
            .iter()
            .map(|address| {
                evm.read_account_info(address).unwrap().map_or(U256::ZERO, |info| info.balance)
            })
            .collect();
        (result, balances)
    }
}

/// Splits a call result returned by [`return_call_result`].
fn call_result(output: &Bytes) -> (bool, Bytes) {
    (output[31] == 1, output.slice(32..))
}

/// Returns the EIP-7708 log of a native transfer.
fn transfer_log(from: Address, to: Address, value: u64) -> Log {
    Log::new_unchecked(
        SYSTEM_ADDRESS,
        vec![TRANSFER_TOPIC, from.into_word(), to.into_word()],
        U256::from(value).to_be_bytes_vec().into(),
    )
}

#[test]
fn spec_follows_chain_schedules() {
    let spec = |chain, block, timestamp| arc_spec_at(chain, block, timestamp).unwrap();
    let arc = |hardfork, eth| ArcSpecId::new(Some(hardfork), eth);
    assert_eq!(spec(ARC_MAINNET_CHAIN_ID, 0, 0), arc(ArcHardfork::Zero6, SpecId::OSAKA));
    assert_eq!(
        spec(ARC_MAINNET_CHAIN_ID, 1, 1_789_052_399),
        arc(ArcHardfork::Zero6, SpecId::OSAKA)
    );
    assert_eq!(
        spec(ARC_MAINNET_CHAIN_ID, 1, 1_789_052_400),
        arc(ArcHardfork::Zero8, SpecId::OSAKA)
    );
    assert_eq!(spec(ARC_TESTNET_CHAIN_ID, 11_172_018, 0), ArcSpecId::new(None, SpecId::PRAGUE));
    assert_eq!(spec(ARC_TESTNET_CHAIN_ID, 11_172_019, 0), arc(ArcHardfork::Zero3, SpecId::PRAGUE));
    assert_eq!(
        spec(ARC_TESTNET_CHAIN_ID, 30_000_000, 1_779_890_400),
        arc(ArcHardfork::Zero4, SpecId::OSAKA)
    );
    assert_eq!(
        spec(ARC_TESTNET_CHAIN_ID, 30_000_000, 1_779_894_517),
        arc(ArcHardfork::Zero6, SpecId::OSAKA)
    );
    assert_eq!(
        spec(ARC_TESTNET_CHAIN_ID, 30_000_000, 1_781_791_200),
        arc(ArcHardfork::Zero7, SpecId::OSAKA)
    );
    assert_eq!(
        spec(ARC_TESTNET_CHAIN_ID, 30_000_000, 1_788_447_600),
        arc(ArcHardfork::Zero8, SpecId::OSAKA)
    );
    assert_eq!(arc_spec_at(1, 0, 0), None);

    // Timestamps match the block activations, but for block 11172018, sharing Zero3's second.
    let at = |timestamp| arc_spec_at_timestamp(ARC_TESTNET_CHAIN_ID, timestamp).unwrap().hardfork();
    assert_eq!(at(1_763_149_895), None);
    assert_eq!(at(1_763_149_896), Some(ArcHardfork::Zero3));
    assert_eq!(at(1_770_651_920), Some(ArcHardfork::Zero3));
    assert_eq!(at(1_770_651_921), Some(ArcHardfork::Zero4));
    assert_eq!(at(1_788_447_600), Some(ArcHardfork::Zero8));
    assert_eq!(
        arc_spec_at_timestamp(ARC_MAINNET_CHAIN_ID, 0),
        Some(arc(ArcHardfork::Zero6, SpecId::OSAKA))
    );
    assert_eq!(ArcHardfork::default(), ArcHardfork::LATEST);
    assert_eq!("zero7".parse::<ArcSpecId>().unwrap(), ArcHardfork::Zero7.into());
    assert_eq!(ArcHardfork::Zero7.to_string(), "Zero7");
    assert!("Zero9".parse::<ArcHardfork>().is_err());
}

#[test]
fn blocklist_slot_matches_arc_node() {
    // `cast index address 0xD308a07F97db36C338e8FE2AfB09267781d00811 2`, from arc-node's tests.
    let slot = blocklist_slot(address!("0xD308a07F97db36C338e8FE2AfB09267781d00811"));
    assert_eq!(
        B256::from(slot),
        b256!("0xc0814ebfa96e99aee5c17f259ae3205e7b664343916807a4a968c9f94e32f89b")
    );
}

#[test]
fn native_transfer_logs_and_pays_the_whole_fee() {
    let mut run = Run::new(OTHER);
    run.value = 5;
    let (result, balances) = run.exec();
    let result = result.unwrap();
    assert!(result.status);
    assert_eq!(result.logs, [transfer_log(CALLER, OTHER, 5)]);
    // arc-node credits the base fee to the beneficiary instead of burning it.
    let fee = 21_000 * GAS_PRICE as u64;
    assert_eq!(balances, [BALANCE - fee - 5, 0, 5, fee].map(U256::from));
}

#[test]
fn blocklisted_sender_and_recipient_are_rejected() {
    let mut run = Run::new(OTHER);
    run.blocklist = vec![CALLER];
    let (result, _) = run.exec();
    assert_eq!(result.unwrap_err().external_ref(), Some(&ArcTxError::BlockedAddress));

    let mut run = Run::new(OTHER);
    run.blocklist = vec![OTHER];
    run.value = 1;
    let (result, _) = run.exec();
    assert_eq!(result.unwrap_err().external_ref(), Some(&ArcTxError::BlockedAddress));

    // Without value, a blocklisted recipient can still be called.
    run.value = 0;
    assert!(run.exec().0.unwrap().status);
}

#[test]
fn first_frame_value_to_zero_address_is_rejected() {
    let mut run = Run::new(Address::ZERO);
    run.value = 1;
    let (result, _) = run.exec();
    assert_eq!(
        result.unwrap_err().external_ref(),
        Some(&ArcTxError::RejectedTransfer(ERR_ZERO_ADDRESS))
    );
}

#[test]
fn value_call_to_blocklisted_address_reverts_before_running() {
    let mut run = Run::new(CONTRACT).account(CONTRACT, 100, send(OTHER, 7));
    run.blocklist = vec![OTHER];
    let (result, balances) = run.exec();
    let result = result.unwrap();
    assert!(result.status);
    assert_eq!(call_result(&result.output), (false, revert_reason(ERR_BLOCKED_ADDRESS)));
    assert!(result.logs.is_empty());
    assert_eq!(balances[1..3], [U256::from(100), U256::ZERO]);

    let allowed = Run::new(CONTRACT).account(CONTRACT, 100, send(OTHER, 7)).exec().0.unwrap();
    assert_eq!(call_result(&allowed.output), (true, Bytes::new()));
    assert_eq!(allowed.logs, [transfer_log(CONTRACT, OTHER, 7)]);
    // The rejected child returns all its gas: only copying its 100-byte revert data costs more.
    assert_eq!(result.tx_gas_used() - allowed.tx_gas_used(), 24);
}

#[test]
fn value_call_to_zero_address_reverts() {
    let run = Run::new(CONTRACT).account(CONTRACT, 100, send(Address::ZERO, 7));
    let result = run.exec().0.unwrap();
    assert_eq!(call_result(&result.output), (false, revert_reason(ERR_ZERO_ADDRESS)));
}

#[test]
fn native_coin_authority_moves_native_usdc_for_the_token_only() {
    let calldata =
        INativeCoinAuthority::transferCall { from: CONTRACT, to: OTHER, amount: U256::from(40) }
            .abi_encode();
    let mut run = Run::new(NATIVE_FIAT_TOKEN_ADDRESS)
        .account(NATIVE_FIAT_TOKEN_ADDRESS, 0, proxy(op::CALL, NATIVE_COIN_AUTHORITY_ADDRESS))
        .account(CONTRACT, 100, Vec::new());
    run.input = calldata.clone();
    let (result, balances) = run.exec();
    let result = result.unwrap();
    assert_eq!(call_result(&result.output), (true, true.abi_encode().into()));
    assert_eq!(result.logs, [transfer_log(CONTRACT, OTHER, 40)]);
    assert_eq!(balances[1..3], [U256::from(60), U256::from(40)]);

    let mut run =
        Run::new(CONTRACT).account(CONTRACT, 100, proxy(op::CALL, NATIVE_COIN_AUTHORITY_ADDRESS));
    run.input = calldata;
    let result = run.exec().0.unwrap();
    assert_eq!(
        call_result(&result.output),
        (false, revert_reason("Not enabled for native coin transfers"))
    );
}

#[test]
fn total_supply_is_readable_in_a_static_call() {
    let mut run = Run::new(CONTRACT).account(
        CONTRACT,
        0,
        proxy(op::STATICCALL, NATIVE_COIN_AUTHORITY_ADDRESS),
    );
    run.storage = vec![(NATIVE_COIN_AUTHORITY_ADDRESS, U256::from(2), U256::from(1_234))];
    run.input = INativeCoinAuthority::totalSupplyCall {}.abi_encode();
    let result = run.exec().0.unwrap();
    assert_eq!(call_result(&result.output), (true, U256::from(1_234).abi_encode().into()));

    // A state change in a static context reverts and consumes all forwarded gas.
    run.input = INativeCoinAuthority::mintCall { to: OTHER, amount: U256::from(1) }.abi_encode();
    let result = run.exec().0.unwrap();
    assert_eq!(
        call_result(&result.output),
        (false, revert_reason("State change during static call"))
    );
}

#[test]
fn delegatecall_rejection_pays_the_penalty_from_zero8() {
    let calldata =
        INativeCoinAuthority::transferCall { from: CONTRACT, to: OTHER, amount: U256::from(1) }
            .abi_encode();
    // The token calls a contract that delegates to the precompile, keeping the token as caller.
    let gas_used = |hardfork: ArcHardfork| {
        let mut run = Run::new(NATIVE_FIAT_TOKEN_ADDRESS)
            .account(NATIVE_FIAT_TOKEN_ADDRESS, 0, proxy(op::CALL, CONTRACT))
            .account(CONTRACT, 0, proxy(op::DELEGATECALL, NATIVE_COIN_AUTHORITY_ADDRESS));
        run.spec = hardfork.into();
        run.input = calldata.clone();
        let result = run.exec().0.unwrap();
        let (success, inner) = call_result(&result.output);
        assert!(success);
        assert_eq!(call_result(&inner), (false, revert_reason("Delegate call not allowed")));
        result.tx_gas_used()
    };
    assert_eq!(gas_used(ArcHardfork::Zero8) - gas_used(ArcHardfork::Zero7), 200);
}

#[test]
fn native_coin_control_updates_the_blocklist() {
    let mut run = Run::new(NATIVE_FIAT_TOKEN_ADDRESS).account(
        NATIVE_FIAT_TOKEN_ADDRESS,
        0,
        proxy(op::CALL, NATIVE_COIN_CONTROL_ADDRESS),
    );
    run.input = INativeCoinControl::blocklistCall { account: OTHER }.abi_encode();
    let result = run.exec().0.unwrap();
    assert_eq!(call_result(&result.output), (true, true.abi_encode().into()));
    assert_eq!(result.logs.len(), 1);
    assert_eq!(result.logs[0].address, NATIVE_COIN_CONTROL_ADDRESS);

    run.blocklist = vec![OTHER];
    run.input = INativeCoinControl::isBlocklistedCall { account: OTHER }.abi_encode();
    let result = run.exec().0.unwrap();
    assert_eq!(call_result(&result.output), (true, true.abi_encode().into()));
}

#[test]
fn selfdestruct_of_a_balance_checks_the_beneficiary() {
    let mut run = Run::new(CONTRACT).account(CONTRACT, 100, selfdestruct(OTHER));
    run.blocklist = vec![OTHER];
    let (result, balances) = run.exec();
    let result = result.unwrap();
    assert!(!result.status);
    assert_eq!(result.output, revert_reason(ERR_BLOCKED_ADDRESS));
    assert_eq!(balances[1], U256::from(100));

    let run = Run::new(CONTRACT).account(CONTRACT, 100, selfdestruct(CONTRACT));
    let result = run.exec().0.unwrap();
    assert!(!result.status);
    assert!(result.output.is_empty());

    let run = Run::new(CONTRACT).account(CONTRACT, 100, selfdestruct(OTHER));
    let (result, balances) = run.exec();
    let result = result.unwrap();
    assert!(result.status);
    assert_eq!(result.logs, [transfer_log(CONTRACT, OTHER, 100)]);
    assert_eq!(balances[1..3], [U256::ZERO, U256::from(100)]);
}

#[test]
fn call_from_calls_as_the_transaction_sender() {
    let mut run = Run::new(MULTICALL3_FROM_ADDRESS)
        .account(MULTICALL3_FROM_ADDRESS, 0, proxy(op::CALL, CALL_FROM_ADDRESS))
        .account(CONTRACT, 0, echo_caller());
    run.input = ICallFrom::callFromCall { sender: CALLER, target: CONTRACT, data: Bytes::new() }
        .abi_encode();
    let result = run.exec().0.unwrap();
    let (success, output) = call_result(&result.output);
    assert!(success);
    let returned = ICallFrom::callFromCall::abi_decode_returns(&output).unwrap();
    assert!(returned.success);
    assert_eq!(returned.returnData, Bytes::from(CALLER.into_word().to_vec()));

    // Other callers are rejected, and before Zero7 the address runs its `0xef` code.
    let mut run = Run::new(CONTRACT).account(CONTRACT, 0, proxy(op::CALL, CALL_FROM_ADDRESS));
    run.input =
        ICallFrom::callFromCall { sender: CALLER, target: OTHER, data: Bytes::new() }.abi_encode();
    let result = run.exec().0.unwrap();
    assert_eq!(call_result(&result.output), (false, revert_reason("unauthorized caller")));
    run.spec = ArcHardfork::Zero6.into();
    let result = run.exec().0.unwrap();
    assert_eq!(call_result(&result.output), (false, Bytes::new()));
}

#[test]
fn arc_precompiles_start_cold() {
    let precompiles = arc_precompiles(ArcHardfork::LATEST.into());
    let mut warm = PrewarmSet::default();
    precompiles.warm_addresses(&mut warm);
    assert!(warm.is_warm(&Address::with_last_byte(1)));
    for address in [NATIVE_COIN_AUTHORITY_ADDRESS, NATIVE_COIN_CONTROL_ADDRESS, CALL_FROM_ADDRESS] {
        assert!(precompiles.contains(&address));
        assert!(!warm.is_warm(&address));
    }
    assert!(!arc_precompiles(ArcHardfork::Zero6.into()).contains(&CALL_FROM_ADDRESS));
}

#[test]
fn pq_verifies_slh_dsa_signatures() {
    use slh_dsa::{
        Sha2_128s, SigningKey,
        signature::{Keypair, Signer},
    };

    let key = SigningKey::<Sha2_128s>::slh_keygen_internal(&[1; 16], &[2; 16], &[3; 16]);
    let message = b"Hello, World!";
    let signature = key.sign(message);
    let call = |vk: Vec<u8>| IPQ::verifySlhDsaSha2128sCall {
        vk: vk.into(),
        message: message.to_vec().into(),
        sig: signature.to_bytes().to_vec().into(),
    };
    let vk = key.verifying_key().to_bytes().to_vec();
    let mut run = Run::new(CONTRACT).account(CONTRACT, 0, proxy(op::STATICCALL, PQ_ADDRESS));
    run.input = call(vk.clone()).abi_encode();
    let result = run.exec().0.unwrap();
    assert_eq!(call_result(&result.output), (true, true.abi_encode().into()));

    let mut wrong = vk.clone();
    wrong[31] ^= 1;
    run.input = call(wrong).abi_encode();
    let result = run.exec().0.unwrap();
    assert_eq!(call_result(&result.output), (true, false.abi_encode().into()));

    run.input = call(vk[..31].to_vec()).abi_encode();
    let result = run.exec().0.unwrap();
    assert_eq!(call_result(&result.output), (false, revert_reason("Invalid verifying key length")));
}

#[test]
fn value_create_at_blocklisted_address_reverts_before_running() {
    // CREATE with value 5 and empty initcode, then return the address and the return data.
    let mut code = vec![op::PUSH1, 0, op::PUSH1, 0, op::PUSH1, 5, 0xf0];
    return_call_result(&mut code);
    let created = CONTRACT.create(0);
    let mut run = Run::new(CONTRACT).account(CONTRACT, 100, code.clone());
    run.blocklist = vec![created];
    let (result, balances) = run.exec();
    let result = result.unwrap();
    assert_eq!(result.output[..32], [0; 32]);
    assert_eq!(result.output.slice(32..), revert_reason(ERR_BLOCKED_ADDRESS));
    assert_eq!(balances[1], U256::from(100));

    let result = Run::new(CONTRACT).account(CONTRACT, 100, code).exec().0.unwrap();
    assert_eq!(result.output[..32], created.into_word()[..]);
    assert_eq!(result.logs, [transfer_log(CONTRACT, created, 5)]);
}
