//! End-to-end execution tests.
//!
//! Expected gas and balances are derived from Nitro's formulas (`arbos/tx_processor.go`,
//! `core/state_transition.go`, `precompiles/`), not from this implementation.

use crate::{
    ARB_INFO_ADDRESS, ARB_SYS_ADDRESS, ARBITRUM_ONE_CHAIN_ID, ARBOS_STATE_ADDRESS, ArbBlockEnv,
    ArbBlockEnvExt, ArbEvmFactory, ArbEvmTypes, ArbHeaderInfo, ArbOsVersion, ArbTxEnvelope,
    BATCH_POSTER_ADDRESS, L1_PRICER_FUNDS_POOL_ADDRESS,
    state::{ArbOsStorage, l1_pricing, l2_pricing, root},
};
use alloy_consensus::{TxEip1559, TxLegacy, transaction::Recovered};
use alloy_primitives::{Address, TxKind, U256, address, b256, hex, uint};
use evm2::{
    TxResult,
    bytecode::Bytecode,
    ethereum::TxEnvelope,
    evm::{AccountInfo, InMemoryDB},
    interpreter::InstrStop,
    registry::HandlerError,
};

const CALLER: Address = address!("0x00000000000000000000000000000000000ca11e");
const CONTRACT: Address = address!("0x000000000000000000000000000000000000c0de");
const NETWORK_FEE_ACCOUNT: Address = address!("0x00000000000000000000000000000000000000ee");
const INFRA_FEE_ACCOUNT: Address = address!("0x00000000000000000000000000000000000000ef");
const CALLER_BALANCE: u64 = 1_000_000_000_000;
const BASEFEE: u64 = 10;
const MIN_BASE_FEE: u64 = 4;
const L2_BLOCK: u64 = 400_000_000;
const L1_BLOCK: u64 = 24_000_000;

/// Returns `GASPRICE` as a word.
const GASPRICE_CODE: [u8; 9] =
    [op::GASPRICE, op::PUSH1, 0, op::MSTORE, op::PUSH1, 32, op::PUSH1, 0, op::RETURN];
/// Returns `NUMBER` as a word.
const NUMBER_CODE: [u8; 9] =
    [op::NUMBER, op::PUSH1, 0, op::MSTORE, op::PUSH1, 32, op::PUSH1, 0, op::RETURN];
/// Runs out of gas in an infinite loop.
const LOOP_CODE: [u8; 4] = [op::JUMPDEST, op::PUSH1, 0, op::JUMP];

/// Opcode bytes used by the test contracts.
mod op {
    pub(super) const GASPRICE: u8 = 0x3a;
    pub(super) const BLOCKHASH: u8 = 0x40;
    pub(super) const NUMBER: u8 = 0x43;
    pub(super) const MSTORE: u8 = 0x52;
    pub(super) const SSTORE: u8 = 0x55;
    pub(super) const JUMP: u8 = 0x56;
    pub(super) const JUMPDEST: u8 = 0x5b;
    pub(super) const PUSH1: u8 = 0x60;
    pub(super) const PUSH4: u8 = 0x63;
    pub(super) const RETURN: u8 = 0xf3;
}

/// Transaction and environment for one execution.
struct Run {
    spec: ArbOsVersion,
    coinbase: Address,
    tx: TxEnvelope,
    poster_gas: u64,
    code: Vec<u8>,
    storage: Vec<(U256, U256)>,
    /// ArbOS state slots and values.
    arbos: Vec<(U256, U256)>,
    l1_block_number: Option<u64>,
}

impl Run {
    fn new(spec: ArbOsVersion) -> Self {
        Self {
            spec,
            coinbase: BATCH_POSTER_ADDRESS,
            tx: legacy(BASEFEE as u128, 1_000_000, TxKind::Call(CONTRACT), Vec::new()),
            poster_gas: 0,
            code: Vec::new(),
            storage: Vec::new(),
            arbos: vec![
                (
                    ArbOsStorage::ROOT.slot(root::NETWORK_FEE_ACCOUNT),
                    NETWORK_FEE_ACCOUNT.into_word().into(),
                ),
                (
                    ArbOsStorage::ROOT.slot(root::INFRA_FEE_ACCOUNT),
                    INFRA_FEE_ACCOUNT.into_word().into(),
                ),
                (
                    ArbOsStorage::L2_PRICING.slot(l2_pricing::MIN_BASE_FEE_WEI),
                    U256::from(MIN_BASE_FEE),
                ),
                (
                    ArbOsStorage::L2_PRICING.slot(l2_pricing::PER_BLOCK_GAS_LIMIT),
                    U256::from(32_000_000),
                ),
                (
                    ArbOsStorage::L2_PRICING.slot(l2_pricing::PER_TX_GAS_LIMIT),
                    U256::from(32_000_000),
                ),
            ],
            l1_block_number: Some(L1_BLOCK),
        }
    }

    /// Executes the transaction and returns its result, and the balances of `watch` and the ArbOS
    /// state values at `slots` afterwards.
    fn exec(
        &self,
        watch: &[Address],
        slots: &[U256],
    ) -> (Result<TxResult<ArbEvmTypes>, HandlerError>, Vec<U256>, Vec<U256>) {
        let mut db = InMemoryDB::default();
        db.insert_account_info(
            &CALLER,
            AccountInfo::default().with_balance(U256::from(CALLER_BALANCE)),
        );
        db.insert_account_info(
            &CONTRACT,
            AccountInfo::default().with_code(Bytecode::new_raw(self.code.clone().into())),
        );
        for (key, value) in &self.storage {
            db.insert_account_storage(&CONTRACT, key, value);
        }
        // ArbOS creates the account holding its state with nonce 1.
        db.insert_account_info(&ARBOS_STATE_ADDRESS, AccountInfo::default().with_nonce(1));
        for (slot, value) in &self.arbos {
            db.insert_account_storage(&ARBOS_STATE_ADDRESS, slot, value);
        }

        let factory = ArbEvmFactory;
        let block = ArbBlockEnv {
            number: U256::from(L2_BLOCK),
            beneficiary: self.coinbase,
            basefee: U256::from(BASEFEE),
            gas_limit: U256::from(1u64 << 50),
            prevrandao: U256::from(1),
            ext: ArbBlockEnvExt { l1_block_number: self.l1_block_number },
            ..Default::default()
        };
        let version = factory.version(self.spec, ARBITRUM_ONE_CHAIN_ID);
        let mut evm = factory.create_evm(self.spec, version, block, db);
        let tx = ArbTxEnvelope { tx: self.tx.clone(), poster_gas: self.poster_gas };
        let result = evm.transact(&Recovered::new_unchecked(tx, CALLER)).map(|tx| tx.commit());
        let balances = watch
            .iter()
            .map(|address| {
                evm.read_account_info(address).unwrap().map_or(U256::ZERO, |info| info.balance)
            })
            .collect();
        let values = slots
            .iter()
            .map(|slot| evm.state_mut().storage_slot_untracked(&ARBOS_STATE_ADDRESS, slot).unwrap())
            .collect();
        (result, balances, values)
    }
}

fn legacy(gas_price: u128, gas_limit: u64, to: TxKind, input: Vec<u8>) -> TxEnvelope {
    TxEnvelope::Legacy(TxLegacy {
        chain_id: Some(ARBITRUM_ONE_CHAIN_ID),
        gas_price,
        gas_limit,
        to,
        input: input.into(),
        ..Default::default()
    })
}

fn eip1559(max_fee: u128, priority_fee: u128) -> TxEnvelope {
    TxEnvelope::Eip1559(TxEip1559 {
        chain_id: ARBITRUM_ONE_CHAIN_ID,
        gas_limit: 1_000_000,
        max_fee_per_gas: max_fee,
        max_priority_fee_per_gas: priority_fee,
        to: TxKind::Call(CONTRACT),
        ..Default::default()
    })
}

#[test]
fn fees_are_split_between_network_infra_and_poster() {
    // A plain call to a contract without code, paying a 1,000 gas poster charge.
    let mut run = Run::new(ArbOsVersion::V61);
    run.tx = legacy(30, 100_000, TxKind::Call(CONTRACT), Vec::new());
    run.poster_gas = 1_000;
    let watch = [CALLER, NETWORK_FEE_ACCOUNT, INFRA_FEE_ACCOUNT, L1_PRICER_FUNDS_POOL_ADDRESS];
    let slots = [
        ArbOsStorage::L1_PRICING.slot(l1_pricing::L1_FEES_AVAILABLE),
        ArbOsStorage::L2_PRICING.slot(l2_pricing::GAS_BACKLOG),
    ];
    let (result, balances, values) = run.exec(&watch, &slots);
    let result = result.unwrap();

    // Tips are dropped, so the transaction pays the base fee.
    assert_eq!(result.tx_gas_used(), 22_000);
    assert_eq!(result.ext.paid_gas_price, U256::from(BASEFEE));
    assert_eq!(result.ext.poster_fee, U256::from(1_000 * BASEFEE));
    let compute_gas = 21_000;
    assert_eq!(
        balances,
        [
            U256::from(CALLER_BALANCE - 22_000 * BASEFEE),
            U256::from(compute_gas * (BASEFEE - MIN_BASE_FEE)),
            U256::from(compute_gas * MIN_BASE_FEE),
            U256::from(1_000 * BASEFEE),
        ]
    );
    // The poster fee is recorded as available L1 fees, and the compute gas grows the backlog.
    assert_eq!(values, [U256::from(1_000 * BASEFEE), U256::from(compute_gas)]);

    // With single-gas pricing constraints, from ArbOS 50, every constraint's backlog grows.
    let constraint = |index: u64| {
        ArbOsStorage::GAS_CONSTRAINTS
            .open(&index.to_be_bytes())
            .slot(l2_pricing::CONSTRAINT_BACKLOG)
    };
    run.arbos.extend([
        (ArbOsStorage::GAS_CONSTRAINTS.slot(0), U256::from(2)),
        (constraint(1), U256::from(5)),
    ]);
    let slots =
        [ArbOsStorage::L2_PRICING.slot(l2_pricing::GAS_BACKLOG), constraint(0), constraint(1)];
    let (_, _, values) = run.exec(&[], &slots);
    assert_eq!(values, [U256::ZERO, U256::from(compute_gas), U256::from(compute_gas + 5)]);
}

#[test]
fn arbos_state_layout_matches_arbitrum_one() {
    // Slots at which `eth_getStorageAt` on Arbitrum One returns the network and infrastructure
    // fee accounts, the minimum base fee, the number of gas constraints and the third
    // constraint's backlog.
    let mut run = Run::new(ArbOsVersion::V61);
    run.poster_gas = 1_000;
    run.arbos = vec![
        (
            uint!(0x15fed0451499512d95f3ec5a41c878b9de55f21878b5b4e190d4667ec709b403_U256),
            NETWORK_FEE_ACCOUNT.into_word().into(),
        ),
        (
            uint!(0x15fed0451499512d95f3ec5a41c878b9de55f21878b5b4e190d4667ec709b406_U256),
            INFRA_FEE_ACCOUNT.into_word().into(),
        ),
        (
            uint!(0xe54de2a4cdacc0a0059d2b6e16348103df8c4aff409c31e40ec73d11926c8203_U256),
            U256::from(MIN_BASE_FEE),
        ),
        (
            uint!(0x52232757544c763eb1c1511dc67b97f352c88a089b72a204b89e1c66fc278300_U256),
            U256::from(3),
        ),
    ];
    let backlog = uint!(0x15feb681c0d80d6dd4522f2158aecf87aabe907423539f227812e8c90210b402_U256);
    let (result, balances, values) =
        run.exec(&[NETWORK_FEE_ACCOUNT, INFRA_FEE_ACCOUNT], &[backlog]);
    assert!(result.unwrap().status);
    let compute_gas = 21_000;
    assert_eq!(
        balances,
        [
            U256::from(compute_gas * (BASEFEE - MIN_BASE_FEE)),
            U256::from(compute_gas * MIN_BASE_FEE)
        ]
    );
    assert_eq!(values, [U256::from(compute_gas)]);
}

#[test]
fn tips_are_collected_only_when_enabled_for_sequenced_blocks() {
    // `min(30, 10 + 5)`, a tip of 5 per gas over the base fee.
    let mut run = Run::new(ArbOsVersion::V61);
    run.code = GASPRICE_CODE.to_vec();
    run.tx = eip1559(30, 5);
    let dropped = run.exec(&[], &[]).0.unwrap();
    assert_eq!(U256::from_be_slice(&dropped.output), U256::from(BASEFEE));
    assert_eq!(dropped.ext.paid_gas_price, U256::from(BASEFEE));

    run.arbos.push((ArbOsStorage::ROOT.slot(root::COLLECT_TIPS), U256::from(1)));
    let (result, balances, _) = run.exec(&[CALLER, NETWORK_FEE_ACCOUNT], &[]);
    let result = result.unwrap();
    let gas_used = result.tx_gas_used();
    assert_eq!(U256::from_be_slice(&result.output), U256::from(15));
    assert_eq!(result.ext.paid_gas_price, U256::from(15));
    assert_eq!(
        balances,
        [U256::from(CALLER_BALANCE - gas_used * 15), U256::from(gas_used * (15 - MIN_BASE_FEE))]
    );

    // Delayed-inbox messages, whose coinbase is not the batch poster, never pay tips.
    run.coinbase = address!("0x00000000000000000000000000000000000c0b0b");
    let delayed = run.exec(&[], &[]).0.unwrap();
    assert_eq!(U256::from_be_slice(&delayed.output), U256::from(BASEFEE));

    // Before ArbOS 3, `GASPRICE` returns the effective gas price even when the tip is dropped.
    run.spec = ArbOsVersion::V2;
    run.coinbase = BATCH_POSTER_ADDRESS;
    let early = run.exec(&[], &[]).0.unwrap();
    assert_eq!(U256::from_be_slice(&early.output), U256::from(15));
    assert_eq!(early.ext.paid_gas_price, U256::from(BASEFEE));
}

#[test]
fn priority_fee_is_only_checked_when_the_tip_is_kept() {
    // The fee cap equals the base fee, so the effective price keeps no tip to drop and Nitro
    // checks the priority fee against the fee cap.
    let mut run = Run::new(ArbOsVersion::V61);
    run.tx = eip1559(BASEFEE as u128, 20);
    let error = run.exec(&[], &[]).0;
    assert!(matches!(error, Err(HandlerError::PriorityFeeGreaterThanMaxFee)), "{error:?}");

    // A dropped tip zeroes the priority fee first.
    run.tx = eip1559(15, 20);
    assert!(run.exec(&[], &[]).0.unwrap().status);
}

#[test]
fn poster_gas_is_not_refundable() {
    // Clears two non-zero slots: 4 PUSH1 and two cold clearing SSTOREs (5,000 each) refunding
    // 4,800 each.
    let mut run = Run::new(ArbOsVersion::V61);
    run.code = vec![op::PUSH1, 0, op::PUSH1, 0, op::SSTORE, op::PUSH1, 0, op::PUSH1, 1, op::SSTORE];
    run.storage = vec![(U256::ZERO, U256::from(1)), (U256::from(1), U256::from(1))];
    run.poster_gas = 10_000;
    let spent = 21_000 + 12 + 10_000 + 10_000;
    // The refund is capped at a fifth of the gas used without the poster gas.
    let refund = (spent - 10_000) / 5;
    assert!(refund < 9_600);
    assert_eq!(run.exec(&[], &[]).0.unwrap().tx_gas_used(), spent - refund);
}

#[test]
fn execution_gas_is_capped_by_arbos() {
    // From ArbOS 50 the transaction gas limit, intrinsic gas included, is capped.
    let mut run = Run::new(ArbOsVersion::V61);
    run.code = LOOP_CODE.to_vec();
    run.arbos
        .push((ArbOsStorage::L2_PRICING.slot(l2_pricing::PER_TX_GAS_LIMIT), U256::from(100_000)));
    let (result, balances, _) = run.exec(&[CALLER], &[]);
    let result = result.unwrap();
    assert_eq!(result.stop, InstrStop::OutOfGas);
    assert_eq!(result.tx_gas_used(), 100_000);
    // The held gas is refunded.
    assert_eq!(balances, [U256::from(CALLER_BALANCE - 100_000 * BASEFEE)]);

    // Before, execution gas was capped at the block gas limit.
    run.spec = ArbOsVersion::V40;
    run.arbos.push((
        ArbOsStorage::L2_PRICING.slot(l2_pricing::PER_BLOCK_GAS_LIMIT),
        U256::from(200_000),
    ));
    assert_eq!(run.exec(&[], &[]).0.unwrap().tx_gas_used(), 21_000 + 200_000);
}

#[test]
fn calldata_floor_requires_the_arbos_feature() {
    let mut run = Run::new(ArbOsVersion::V40);
    run.tx = legacy(BASEFEE as u128, 1_000_000, TxKind::Call(CONTRACT), vec![1; 1_000]);
    assert_eq!(run.exec(&[], &[]).0.unwrap().tx_gas_used(), 21_000 + 16 * 1_000);

    // EIP-7623: 21,000 plus 10 gas per token, four tokens per non-zero byte.
    run.arbos.push((ArbOsStorage::FEATURES.slot(0), U256::from(1)));
    assert_eq!(run.exec(&[], &[]).0.unwrap().tx_gas_used(), 21_000 + 40 * 1_000);
}

#[test]
fn number_returns_the_l1_block_number_from_the_header() {
    // Arbitrum One block 517,283,379.
    let header = ArbHeaderInfo::from_mix_hash(b256!(
        "0x0000000000028d05000000000190890b000000000000003d0001000000000000"
    ))
    .unwrap();
    assert_eq!(
        header,
        ArbHeaderInfo { l1_block_number: 0x190890b, arbos_version: ArbOsVersion::V61 }
    );
    let mut run = Run::new(header.arbos_version);
    run.code = NUMBER_CODE.to_vec();
    run.l1_block_number = Some(header.l1_block_number);
    let result = run.exec(&[], &[]).0.unwrap();
    assert_eq!(U256::from_be_slice(&result.output), U256::from(0x190890b));

    // Without a header value, the L1 block number is read from the ArbOS state.
    run.l1_block_number = None;
    run.arbos.push((ArbOsStorage::BLOCKHASHES.slot(0), U256::from(L1_BLOCK + 7)));
    let result = run.exec(&[], &[]).0.unwrap();
    assert_eq!(U256::from_be_slice(&result.output), U256::from(L1_BLOCK + 7));

    // `BLOCKHASH` returns the L1 block hashes ArbOS records, for the 256 blocks before it.
    let hash = U256::from(0xbeef);
    run.arbos.push((ArbOsStorage::BLOCKHASHES.slot(1 + (L1_BLOCK + 6) % 256), hash));
    for (number, expected) in [(L1_BLOCK + 6, hash), (L1_BLOCK + 7, U256::ZERO)] {
        let [a, b, c, d] = (number as u32).to_be_bytes();
        run.code = vec![op::PUSH4, a, b, c, d, op::BLOCKHASH];
        run.code.extend(&NUMBER_CODE[1..]);
        let result = run.exec(&[], &[]).0.unwrap();
        assert_eq!(U256::from_be_slice(&result.output), expected, "{number}");
    }

    // Nitro reserves ArbOS 12 without an upgrade.
    assert!(
        ArbHeaderInfo::from_mix_hash(b256!(
            "0x00000000000000010000000000000002000000000000000c0000000000000000"
        ))
        .is_err()
    );
}

#[test]
fn arb_sys_returns_l2_block_and_version() {
    let call = |input: Vec<u8>| {
        let mut run = Run::new(ArbOsVersion::V61);
        run.tx = legacy(BASEFEE as u128, 100_000, TxKind::Call(ARB_SYS_ADDRESS), input);
        run.exec(&[], &[]).0.unwrap()
    };
    // 4 non-zero calldata bytes, 800 gas to open the ArbOS state and 3 for the result word.
    let block_number = call(hex!("a3b1b31d").to_vec());
    assert_eq!(U256::from_be_slice(&block_number.output), U256::from(L2_BLOCK));
    assert_eq!(block_number.tx_gas_used(), 21_000 + 4 * 16 + 803);
    let version = call(hex!("051038f2").to_vec());
    assert_eq!(U256::from_be_slice(&version.output), U256::from(55 + 61));
    let chain_id = call(hex!("d127f54a").to_vec());
    assert_eq!(U256::from_be_slice(&chain_id.output), U256::from(ARBITRUM_ONE_CHAIN_ID));

    // `arbBlockHash` of the current block reverts with `InvalidBlockNumber(requested, current)`,
    // paying 3 gas per word of the argument and of the revert data.
    let mut input = hex!("2b407a82").to_vec();
    input.extend(U256::from(L2_BLOCK).to_be_bytes::<32>());
    let invalid = call(input);
    assert!(!invalid.status);
    let mut expected = hex!("d5dc642d").to_vec();
    expected.extend(U256::from(L2_BLOCK).to_be_bytes::<32>());
    expected.extend(U256::from(L2_BLOCK).to_be_bytes::<32>());
    assert_eq!(invalid.output, expected);
    // The block number has 3 non-zero bytes.
    let calldata = 4 * 16 + 3 * 16 + 29 * 4;
    assert_eq!(invalid.tx_gas_used(), 21_000 + calldata + 800 + 3 + 9);

    // An unknown selector reverts and consumes all gas.
    let unknown = call(hex!("deadbeef").to_vec());
    assert!(!unknown.status);
    assert_eq!(unknown.tx_gas_used(), 100_000);
}

#[test]
fn arb_info_returns_code() {
    let mut run = Run::new(ArbOsVersion::V61);
    run.code = vec![0xaa, 0xbb, 0xcc];
    let mut input = hex!("7e105ce2").to_vec();
    input.extend(CONTRACT.into_word());
    run.tx = legacy(BASEFEE as u128, 100_000, TxKind::Call(ARB_INFO_ADDRESS), input);
    let result = run.exec(&[], &[]).0.unwrap();

    // ABI-encoded `bytes`: the offset, the length and the padded code.
    let mut expected = U256::from(32).to_be_bytes::<32>().to_vec();
    expected.extend(U256::from(3).to_be_bytes::<32>());
    expected.extend([0xaa, 0xbb, 0xcc]);
    expected.resize(96, 0);
    assert_eq!(result.output, expected);
    // The address word has 2 non-zero bytes. Opening the state (800), the argument word (3), the
    // code read (2,100 and 3 per code word) and three result words (9).
    let calldata = 4 * 16 + 2 * 16 + 30 * 4;
    assert_eq!(result.tx_gas_used(), 21_000 + calldata + 800 + 3 + 2_100 + 3 + 9);
}

#[test]
fn precompile_sets_follow_arbos_versions() {
    // Calls a precompile without input and returns the result, or the handler error.
    let call = |spec, address: Address| {
        let mut run = Run::new(spec);
        run.tx = legacy(BASEFEE as u128, 100_000, TxKind::Call(address), Vec::new());
        run.exec(&[], &[]).0
    };
    let p256 = address!("0x0000000000000000000000000000000000000100");
    let kzg = address!("0x000000000000000000000000000000000000000a");
    let bls_g1_add = address!("0x000000000000000000000000000000000000000b");
    let arb_wasm = address!("0x0000000000000000000000000000000000000071");

    // P256 is absent before ArbOS 30, then costs 3,450 gas and 6,900 from ArbOS 50.
    assert_eq!(call(ArbOsVersion::V20, p256).unwrap().tx_gas_used(), 21_000);
    assert_eq!(call(ArbOsVersion::V30, p256).unwrap().tx_gas_used(), 21_000 + 3_450);
    assert_eq!(call(ArbOsVersion::V50, p256).unwrap().tx_gas_used(), 21_000 + 6_900);
    // KZG arrives with ArbOS 30, and fails on empty input.
    assert!(call(ArbOsVersion::V20, kzg).unwrap().status);
    assert!(!call(ArbOsVersion::V30, kzg).unwrap().status);
    // ArbOS 40 runs Prague but keeps the Cancun precompiles, so BLS12-381 arrives with ArbOS 50.
    assert!(call(ArbOsVersion::V40, bls_g1_add).unwrap().status);
    assert!(!call(ArbOsVersion::V50, bls_g1_add).unwrap().status);
    // ArbWasm arrives with ArbOS 30 and, like every unported ArbOS precompile, aborts.
    assert!(call(ArbOsVersion::V20, arb_wasm).unwrap().status);
    assert!(matches!(call(ArbOsVersion::V30, arb_wasm), Err(HandlerError::Fatal(_))));
}

#[test]
fn stylus_programs_abort() {
    let run = |spec, code: &[u8]| {
        let mut run = Run::new(spec);
        run.code = code.to_vec();
        run.exec(&[], &[]).0
    };
    let classic = hex!("eff00000");
    let root = hex!("eff00200");
    assert!(matches!(run(ArbOsVersion::V30, &classic), Err(HandlerError::Fatal(_))));
    assert!(matches!(run(ArbOsVersion::V60, &root), Err(HandlerError::Fatal(_))));
    // Before Stylus, and before root programs, the prefix is an undefined opcode.
    assert_eq!(run(ArbOsVersion::V20, &classic).unwrap().stop, InstrStop::OpcodeNotFound);
    assert_eq!(run(ArbOsVersion::V51, &root).unwrap().stop, InstrStop::OpcodeNotFound);
}
