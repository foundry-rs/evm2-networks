//! End-to-end execution tests against the contracts in `testdata/Mocks.sol`.
//!
//! Expected amounts are derived from celo-revm's fee rules, not from this implementation.

use crate::{
    CELO_FEE_HANDLER_ADDRESS, CELO_MAINNET_CHAIN_ID, CELO_MAINNET_FEE_CURRENCY_DIRECTORY,
    CELO_TOKEN_ADDRESS, CELO_TRANSFER_ADDRESS, CeloBlockEnv, CeloEvm, CeloEvmFactory,
    CeloTxEnvelope, CeloTxError, FeeCurrencyContext, FeeCurrencyInfo, TxCip64,
};
use alloy_consensus::{Signed, TxEip1559, TxEip2930, TxLegacy, transaction::Recovered};
use alloy_eips::eip2718::Encodable2718;
use alloy_primitives::{
    Address, B256, Bytes, Log, Signature, TxKind, U256, address, b256, bytes, keccak256,
    map::HashMap,
};
use alloy_sol_types::{SolCall, SolEvent, sol};
use evm2::{
    TxResult,
    bytecode::Bytecode,
    evm::{AccountInfo, InMemoryDB},
    registry::HandlerError,
};
use op_evm2::{OpSpecId, TxDeposit};

sol! {
    function probe() external;
    function boom() external;
    function transfer(address to, uint256 value) external;
    function probe(address directory) external;

    event Debit(address from, uint256 value);
    event Credit(address from, address feeRecipient, address communityFund, uint256 refund, uint256 tip, uint256 baseFee);
    event Probe(uint256 transientValue, uint256 gasPrice);
    event BalanceCost(uint256 gas);
    event Costs(uint256 balance, uint256 call);
}

const CALLER: Address = address!("0x00000000000000000000000000000000000ca11e");
const COINBASE: Address = address!("0x00000000000000000000000000000000c0ffee00");
const TOKEN: Address = address!("0x0000000000000000000000000000000000070c3e");
const PROBER: Address = address!("0x0000000000000000000000000000000000000b0b");
const DIRECTORY: Address = CELO_MAINNET_FEE_CURRENCY_DIRECTORY;

const BLOCK: u64 = 100;
const BASEFEE: u64 = 1_000;
/// CELO to token rate 3/2: the base fee in the token is 1,500.
const RATE: (u64, u64) = (3, 2);
const BASE_FEE_IN_TOKEN: u128 = 1_500;
const INTRINSIC_GAS: u64 = 50_000;
const GAS_LIMIT: u64 = 200_000;
const MAX_FEE: u128 = 10_000;
const TIP: u128 = 100;
/// `min(MAX_FEE, BASE_FEE_IN_TOKEN + TIP)`.
const PRICE: u128 = 1_600;
const NATIVE_BALANCE: u128 = 10u128.pow(18);
const TOKEN_BALANCE: u128 = 10u128.pow(18);

fn code(hex: &str) -> Bytecode {
    Bytecode::new_raw(alloy_primitives::hex::decode(hex.trim()).unwrap().into())
}

/// Storage slot of `balanceOf[account]` in `FeeToken`.
fn balance_slot(account: Address) -> U256 {
    let mut preimage = [0u8; 64];
    preimage[12..32].copy_from_slice(account.as_slice());
    U256::from_be_bytes(keccak256(preimage).0)
}

/// A database with a funded caller, the directory registering `token`, and the mock contracts.
fn db(token: Address, token_balance: u128, failure: u64) -> InMemoryDB {
    let mut db = InMemoryDB::default();
    let info = |balance: u128| AccountInfo::default().with_balance(U256::from(balance));
    db.insert_account_info(&CALLER, info(NATIVE_BALANCE));
    db.insert_account_info(
        &DIRECTORY,
        info(0).with_code(code(include_str!("../testdata/Directory.bin-runtime"))),
    );
    for (slot, value) in [
        (0, U256::from_be_slice(token.as_slice())),
        (1, U256::from(RATE.0)),
        (2, U256::from(RATE.1)),
        (3, U256::from(INTRINSIC_GAS)),
    ] {
        db.insert_account_storage(&DIRECTORY, &U256::from(slot), &value);
    }
    db.insert_account_info(
        &token,
        info(0).with_code(code(include_str!("../testdata/FeeToken.bin-runtime"))),
    );
    db.insert_account_storage(&token, &balance_slot(CALLER), &U256::from(token_balance));
    db.insert_account_storage(&token, &U256::from(1), &U256::from(failure));
    db.insert_account_info(
        &CELO_TOKEN_ADDRESS,
        info(0).with_code(code(include_str!("../testdata/GoldToken.bin-runtime"))),
    );
    db.insert_account_info(
        &PROBER,
        info(0).with_code(code(include_str!("../testdata/Prober.bin-runtime"))),
    );
    db
}

fn block(number: u64, basefee: u64) -> CeloBlockEnv {
    CeloBlockEnv {
        number: U256::from(number),
        basefee: U256::from(basefee),
        beneficiary: COINBASE,
        gas_limit: U256::from(30_000_000),
        ..Default::default()
    }
}

fn evm(spec: OpSpecId, db: InMemoryDB, block: CeloBlockEnv) -> CeloEvm<'static> {
    let factory = CeloEvmFactory;
    factory.create_evm(spec, factory.version(spec, CELO_MAINNET_CHAIN_ID), block, db)
}

fn signed<T: Into<crate::CeloTypedTx>>(tx: T, from: Address) -> Recovered<CeloTxEnvelope>
where
    Signed<T>: Encodable2718,
{
    let envelope =
        CeloTxEnvelope::from_signed(Signed::new_unhashed(tx, Signature::test_signature()));
    Recovered::new_unchecked(envelope, from)
}

fn cip64(fee_currency: Option<Address>, to: Address, input: Bytes, nonce: u64) -> TxCip64 {
    TxCip64 {
        inner: TxEip1559 {
            chain_id: CELO_MAINNET_CHAIN_ID,
            nonce,
            gas_limit: GAS_LIMIT,
            max_fee_per_gas: MAX_FEE,
            max_priority_fee_per_gas: TIP,
            to: TxKind::Call(to),
            input,
            ..Default::default()
        },
        fee_currency,
    }
}

fn transact(
    evm: &mut CeloEvm<'_>,
    tx: Recovered<CeloTxEnvelope>,
) -> Result<TxResult<crate::CeloEvmTypes>, HandlerError> {
    evm.transact(&tx).map(|tx| tx.commit())
}

fn token_balance(evm: &mut CeloEvm<'_>, token: Address, account: Address) -> u128 {
    evm.state_mut().storage_slot_untracked(&token, &balance_slot(account)).unwrap().to()
}

fn native(evm: &mut CeloEvm<'_>, account: Address) -> AccountInfo {
    evm.read_account_info(&account).unwrap().unwrap_or_default()
}

fn decode<E: SolEvent>(log: &Log) -> E {
    E::decode_log_data(&log.data).unwrap()
}

fn topics(result: &TxResult<crate::CeloEvmTypes>) -> Vec<B256> {
    result.logs.iter().map(|log| log.topics()[0]).collect()
}

#[test]
fn cip64_pays_fees_in_fee_currency() {
    let mut evm = evm(OpSpecId::JOVIAN, db(TOKEN, TOKEN_BALANCE, 0), block(BLOCK, BASEFEE));
    let input = probe_0Call {}.abi_encode().into();
    let result = transact(&mut evm, signed(cip64(Some(TOKEN), TOKEN, input, 0), CALLER)).unwrap();
    assert!(result.status);
    assert_eq!(result.ext.base_fee_in_erc20, Some(BASE_FEE_IN_TOKEN));
    let used = u128::from(result.tx_gas_used());

    // Debit logs, then the transaction's logs, then credit logs.
    assert_eq!(
        topics(&result),
        [Debit::SIGNATURE_HASH, Probe::SIGNATURE_HASH, Credit::SIGNATURE_HASH]
    );
    let debit = decode::<Debit>(&result.logs[0]);
    assert_eq!((debit.from, debit.value), (CALLER, U256::from(u128::from(GAS_LIMIT) * PRICE)));
    // The debit's transient storage is cleared and `GASPRICE` is the fee-currency price.
    let probe = decode::<Probe>(&result.logs[1]);
    assert_eq!((probe.transientValue, probe.gasPrice), (U256::ZERO, U256::from(PRICE)));
    let credit = decode::<Credit>(&result.logs[2]);
    assert_eq!(
        (credit.from, credit.feeRecipient, credit.communityFund),
        (CALLER, COINBASE, CELO_FEE_HANDLER_ADDRESS)
    );
    assert_eq!(credit.refund, U256::from((u128::from(GAS_LIMIT) - used) * PRICE));
    assert_eq!(credit.tip, U256::from(used * TIP));
    assert_eq!(credit.baseFee, U256::from(used * BASE_FEE_IN_TOKEN));

    assert_eq!(token_balance(&mut evm, TOKEN, CALLER), TOKEN_BALANCE - used * PRICE);
    assert_eq!(token_balance(&mut evm, TOKEN, COINBASE), used * TIP);
    assert_eq!(token_balance(&mut evm, TOKEN, CELO_FEE_HANDLER_ADDRESS), used * BASE_FEE_IN_TOKEN);
    let caller = native(&mut evm, CALLER);
    assert_eq!((caller.balance, caller.nonce), (U256::from(NATIVE_BALANCE), 1));

    // The same call paying in CELO runs as EIP-1559 and costs the currency's intrinsic gas less.
    let mut native_evm = evm_native();
    let input = probe_0Call {}.abi_encode().into();
    let native_result =
        transact(&mut native_evm, signed(cip64(None, TOKEN, input, 0), CALLER)).unwrap();
    assert!(native_result.status);
    assert_eq!(native_result.ext.base_fee_in_erc20, Some(u128::from(BASEFEE)));
    assert_eq!(result.tx_gas_used(), native_result.tx_gas_used() + INTRINSIC_GAS);
    let native_price = u128::from(BASEFEE) + TIP;
    let native_used = u128::from(native_result.tx_gas_used());
    assert_eq!(
        native(&mut native_evm, CALLER).balance,
        U256::from(NATIVE_BALANCE - native_used * native_price)
    );
}

fn evm_native() -> CeloEvm<'static> {
    evm(OpSpecId::JOVIAN, db(TOKEN, TOKEN_BALANCE, 0), block(BLOCK, BASEFEE))
}

#[test]
fn cip64_revert_keeps_fee_logs() {
    let mut evm = evm_native();
    let input = boomCall {}.abi_encode().into();
    let result = transact(&mut evm, signed(cip64(Some(TOKEN), TOKEN, input, 0), CALLER)).unwrap();
    assert!(!result.status);
    assert_eq!(topics(&result), [Debit::SIGNATURE_HASH, Credit::SIGNATURE_HASH]);
    let used = u128::from(result.tx_gas_used());
    assert_eq!(token_balance(&mut evm, TOKEN, CALLER), TOKEN_BALANCE - used * PRICE);
}

#[test]
fn cip64_credit_uses_floor_gas() {
    let mut evm = evm_native();
    let mut input = probe_0Call {}.abi_encode();
    input.extend([0xff; 4_000]);
    // EIP-7623: 10 gas per token, a zero byte is one token and a non-zero byte four.
    let tokens: u64 = input.iter().map(|byte| if *byte == 0 { 1 } else { 4 }).sum();
    let floor = 21_000 + 10 * tokens;
    let mut tx = cip64(Some(TOKEN), TOKEN, input.into(), 0);
    tx.inner.gas_limit = 300_000;
    let result = transact(&mut evm, signed(tx, CALLER)).unwrap();
    assert!(result.status);
    assert_eq!(result.tx_gas_used(), floor);
    let used = u128::from(floor);
    let credit = decode::<Credit>(&result.logs[2]);
    assert_eq!(credit.refund, U256::from((300_000 - used) * PRICE));
    // Every token unit debited is credited back or paid out.
    let paid = TOKEN_BALANCE - token_balance(&mut evm, TOKEN, CALLER);
    let received = token_balance(&mut evm, TOKEN, COINBASE)
        + token_balance(&mut evm, TOKEN, CELO_FEE_HANDLER_ADDRESS);
    assert_eq!((paid, received), (used * PRICE, used * PRICE));
}

#[test]
fn rejected_cip64_has_no_effects() {
    let probe = || Bytes::from(probe_0Call {}.abi_encode());
    let cases = [
        (db(TOKEN, TOKEN_BALANCE, 0), cip64(Some(PROBER), TOKEN, probe(), 0)),
        (db(TOKEN, TOKEN_BALANCE, 0), cip64(Some(TOKEN), TOKEN, probe(), 1)),
        (db(TOKEN, TOKEN_BALANCE, 1), cip64(Some(TOKEN), TOKEN, probe(), 0)),
        (db(TOKEN, TOKEN_BALANCE, 2), cip64(Some(TOKEN), TOKEN, probe(), 0)),
        // Covers `gas_limit * effective_gas_price`, not `gas_limit * max_fee_per_gas`.
        (db(TOKEN, u128::from(GAS_LIMIT) * PRICE, 0), cip64(Some(TOKEN), TOKEN, probe(), 0)),
    ];
    let mut errors = Vec::new();
    for (db, tx) in cases {
        let mut evm = evm(OpSpecId::JOVIAN, db, block(BLOCK, BASEFEE));
        let before = token_balance(&mut evm, TOKEN, CALLER);
        let error = transact(&mut evm, signed(tx, CALLER)).unwrap_err();
        errors.push(error.external_ref::<CeloTxError>().cloned().ok_or(error));
        assert_eq!(token_balance(&mut evm, TOKEN, CALLER), before);
        assert_eq!(native(&mut evm, CALLER).nonce, 0);
    }
    assert_eq!(
        errors,
        [
            Ok(CeloTxError::FeeCurrencyNotRegistered(PROBER)),
            Err(HandlerError::InvalidNonce { expected: 0, got: 1 }),
            Ok(CeloTxError::DebitFailed),
            Ok(CeloTxError::CreditFailed),
            Err(HandlerError::InsufficientFunds),
        ]
    );
}

#[test]
fn fee_currency_context_is_loaded_without_side_effects() {
    let input = Bytes::from(probe_1Call { directory: DIRECTORY }.abi_encode());
    let tx = || {
        signed(
            TxLegacy {
                chain_id: Some(CELO_MAINNET_CHAIN_ID),
                gas_price: u128::from(BASEFEE),
                gas_limit: GAS_LIMIT,
                to: TxKind::Call(PROBER),
                input: input.clone(),
                ..Default::default()
            },
            CALLER,
        )
    };
    let context = FeeCurrencyContext {
        block: Some(U256::from(BLOCK)),
        currencies: HashMap::from_iter([(
            TOKEN,
            FeeCurrencyInfo {
                exchange_rate: (U256::from(RATE.0), U256::from(RATE.1)),
                intrinsic_gas: INTRINSIC_GAS,
            },
        )]),
    };

    let mut loading = evm_native();
    let loaded = transact(&mut loading, tx()).unwrap();
    assert_eq!(loading.ext().fee_currency_context, context);

    let mut injected = evm_native();
    injected.ext_mut().fee_currency_context = context;
    let reference = transact(&mut injected, tx()).unwrap();

    // The directory reads leave the directory account and its storage cold.
    assert_eq!(loaded.logs, reference.logs);
    assert_eq!(loaded.tx_gas_used(), reference.tx_gas_used());
    let costs = decode::<Costs>(&loaded.logs[0]);
    assert!(costs.balance >= U256::from(2_600), "{}", costs.balance);
}

/// The mainnet CIP-64 transaction at block 75,046,581 whose sender could not cover
/// `gas_limit * max_fee_per_gas` in the fee currency.
#[test]
fn cip64_max_fee_exception() {
    let fee_currency = address!("0x0e2a3e05bc9a16f5292a6170456a710cb89c6f72");
    let sender = address!("0x1de6939e8a03df7bdc970a951b67628d2d138ed9");
    let tx = TxCip64 {
        inner: TxEip1559 {
            chain_id: CELO_MAINNET_CHAIN_ID,
            nonce: 0x1d,
            gas_limit: 0x30d40,
            max_fee_per_gas: 0x6c65312b3,
            max_priority_fee_per_gas: 0x8f8403c,
            to: TxKind::Call(address!("0x48065fbbe25f71c9282ddf5e1cd6d6a887483d5e")),
            value: U256::ZERO,
            access_list: Default::default(),
            input: bytes!(
                "a9059cbb00000000000000000000000003d904993bf9a19e3fe78bed6bec435603d2e6150000000000000000000000000000000000000000000000000000000000105f46"
            ),
        },
        fee_currency: Some(fee_currency),
    };
    let signature = Signature::new(
        b256!("0x3c6f794c1d0150430f72a84840900b64f3095bac2329b22d427cd2ce1845d5c5").into(),
        b256!("0x6ae569be2db73db63ec20ebf618098c130949ca79b4a34cadcfe60cfb1992035").into(),
        true,
    );
    let envelope = CeloTxEnvelope::from_signed(Signed::new_unhashed(tx, signature));
    assert_eq!(
        keccak256(envelope.enveloped_tx().unwrap()),
        b256!("0xe9e0248cf5b02ce016b195690fbb168f08eeeff7b9b353a52ecf98f4229ba834")
    );

    let run = |number| {
        let mut db = db(fee_currency, 0, 0);
        db.insert_account_info(&sender, AccountInfo::default().with_nonce(0x1d));
        // The historical balance: enough for the effective price, not for the maximum fee.
        db.insert_account_storage(
            &fee_currency,
            &balance_slot(sender),
            &U256::from(5_295_000_000_000_000u64),
        );
        db.insert_account_storage(&DIRECTORY, &U256::from(1), &U256::from(1));
        db.insert_account_storage(&DIRECTORY, &U256::from(2), &U256::from(1));
        // Base fee 12,010,858,000 plus the tip gives the historical price of 12,161,345,100.
        let mut evm = evm(OpSpecId::ISTHMUS, db, block(number, 12_010_858_000));
        transact(&mut evm, Recovered::new_unchecked(envelope.clone(), sender))
    };
    assert!(run(75046581).unwrap().status);
    assert_eq!(run(75046582).unwrap_err(), HandlerError::InsufficientFunds);
}

/// The mainnet EIP-2930 transaction at block 53,619,115 signed for chain 44787.
#[test]
fn chain_id_exception() {
    let sender = address!("0x5421e1e4fcc98af133059723ba049b4ea1e9de91");
    let tx = TxEip2930 {
        chain_id: 44787,
        nonce: 5,
        gas_price: 0x6fc23ac00,
        gas_limit: 0x7530,
        to: TxKind::Call(address!("0xc04b2ffacc30c7fe19741e27ea150cccc212e072")),
        value: U256::from(0xb5e620f48000u64),
        access_list: Default::default(),
        input: Bytes::new(),
    };
    let signature = Signature::new(
        b256!("0x197400aceb14cacc9a75710ebb4d3cba85538fc96a2b254d51a0db742c24ad08").into(),
        b256!("0x2c18b58821fe02d107ff1fa9f4fd157bafb571bb83867d56618de3e1045141bb").into(),
        true,
    );
    let envelope = CeloTxEnvelope::from_signed(Signed::new_unhashed(tx, signature));
    assert_eq!(
        keccak256(envelope.enveloped_tx().unwrap()),
        b256!("0xd6bdf3261df7e7a4db6bbc486bf091eb62dfd2883e335c31219b6a37d3febca1")
    );

    let run = |number| {
        let mut db = InMemoryDB::default();
        db.insert_account_info(
            &sender,
            AccountInfo::default().with_nonce(5).with_balance(U256::from(NATIVE_BALANCE)),
        );
        let mut evm = evm(OpSpecId::ISTHMUS, db, block(number, 0));
        transact(&mut evm, Recovered::new_unchecked(envelope.clone(), sender))
    };
    assert!(run(53619115).unwrap().status);
    assert_eq!(
        run(53619116).unwrap_err(),
        HandlerError::InvalidChainId { expected: CELO_MAINNET_CHAIN_ID, got: 44787 }
    );
}

#[test]
fn native_base_fee_goes_to_fee_handler() {
    let mut evm = evm_native();
    let tx = TxLegacy {
        chain_id: Some(CELO_MAINNET_CHAIN_ID),
        gas_price: 1_500,
        gas_limit: 21_000,
        to: TxKind::Call(COINBASE),
        ..Default::default()
    };
    assert!(transact(&mut evm, signed(tx, CALLER)).unwrap().status);
    assert_eq!(native(&mut evm, CALLER).balance, U256::from(NATIVE_BALANCE - 21_000 * 1_500));
    assert_eq!(native(&mut evm, COINBASE).balance, U256::from(21_000 * 500));
    assert_eq!(native(&mut evm, CELO_FEE_HANDLER_ADDRESS).balance, U256::from(21_000 * 1_000));
}

#[test]
fn transfer_precompile() {
    let recipient = address!("0x00000000000000000000000000000000000ba5e0");
    let call = |spec, to, input: Vec<u8>| {
        let mut evm = evm(spec, db(TOKEN, 0, 0), block(BLOCK, 0));
        let tx = TxLegacy {
            chain_id: Some(CELO_MAINNET_CHAIN_ID),
            gas_limit: GAS_LIMIT,
            to: TxKind::Call(to),
            input: input.into(),
            ..Default::default()
        };
        let result = transact(&mut evm, signed(tx, CALLER)).unwrap();
        (result, native(&mut evm, recipient).balance)
    };
    let transfer = transferCall { to: recipient, value: U256::from(5) }.abi_encode();

    let (isthmus, balance) = call(OpSpecId::ISTHMUS, CELO_TOKEN_ADDRESS, transfer.clone());
    assert!(isthmus.status);
    assert_eq!(balance, U256::from(5));
    let (jovian, _) = call(OpSpecId::JOVIAN, CELO_TOKEN_ADDRESS, transfer);
    assert!(jovian.status);
    // Before Jovian the recipient stays cold (2,600); from Jovian it is warm (100).
    let cost = |result: &TxResult<crate::CeloEvmTypes>| decode::<BalanceCost>(&result.logs[0]).gas;
    assert_eq!(cost(&isthmus) - cost(&jovian), U256::from(2_500));

    // Only the CELO token may call it.
    let mut input = [0u8; 96];
    input[12..32].copy_from_slice(CALLER.as_slice());
    input[44..64].copy_from_slice(recipient.as_slice());
    input[95] = 5;
    let (direct, balance) = call(OpSpecId::JOVIAN, CELO_TRANSFER_ADDRESS, input.to_vec());
    assert!(!direct.status);
    assert_eq!(direct.tx_gas_used(), GAS_LIMIT);
    assert_eq!(balance, U256::ZERO);
}

#[test]
fn deposit_with_unaffordable_value_fails() {
    let mut evm = evm_native();
    let from = address!("0x00000000000000000000000000000000000de905");
    let deposit = TxDeposit {
        from,
        to: TxKind::Call(COINBASE),
        mint: 10,
        value: U256::from(100),
        gas_limit: 100_000,
        ..Default::default()
    };
    let result =
        transact(&mut evm, Recovered::new_unchecked(CeloTxEnvelope::deposit(deposit), from))
            .unwrap();
    assert!(!result.status && result.ext.failed_deposit);
    assert_eq!(result.tx_gas_used(), 100_000);
    let from = native(&mut evm, from);
    assert_eq!((from.balance, from.nonce), (U256::from(10), 1));
    assert_eq!(native(&mut evm, COINBASE).balance, U256::ZERO);
    // The first transaction of the block loads the fee currency context.
    assert_eq!(evm.ext().fee_currency_context.block, Some(U256::from(BLOCK)));
}
