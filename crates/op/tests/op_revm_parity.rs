//! Differential parity tests against op-revm.
//!
//! Each scenario runs the same transaction from the same pre-state through op-revm (the pinned
//! Foundry revision) and through `op-evm2`, then compares the outcome class, the receipt gas used,
//! and the post-state balances and nonces of every account the fee path touches.

#![allow(missing_docs)]

use alloy_consensus::{TxEip1559, TxLegacy, transaction::Recovered};
use alloy_primitives::{Address, B256, Bytes, TxKind, U256, bytes, hex};
use evm2::{
    EvmFeatures,
    bytecode::Bytecode,
    env::BlockEnvExt,
    evm::{AccountInfo as Evm2AccountInfo, InMemoryDB as Evm2Db},
};
use op_evm2::{
    L1BlockInfo as Evm2L1, OpEvmFactory, OpSpecId as Evm2Spec, OpTxEnvelope, TxDeposit,
    constants::*,
};
use op_revm::{
    DefaultOp, L1BlockInfo as RevmL1, OpBuilder, OpHaltReason, OpSpecId as RevmSpec, OpTransaction,
};
use revm::{
    Context, ExecuteEvm,
    bytecode::Bytecode as RevmBytecode,
    context::{BlockEnv, CfgEnv, TxEnv, result::ExecutionResult},
    database::InMemoryDB as RevmDb,
    state::AccountInfo as RevmAccountInfo,
};

const CALLER: Address = Address::with_last_byte(0xaa);
const TARGET: Address = Address::with_last_byte(0xbb);
const COINBASE: Address = Address::with_last_byte(0xcc);
const INVALID: Address = Address::with_last_byte(0xdd);
const REVERTER: Address = Address::with_last_byte(0xee);
/// Clears storage slot 0 (initially 1), earning an SSTORE refund.
const REFUNDER: Address = Address::with_last_byte(0xf0);

/// Init code that deploys the single byte `0x2a`.
const INIT_CODE: [u8; 10] = [0x60, 0x2a, 0x60, 0x00, 0x53, 0x60, 0x01, 0x60, 0x00, 0xf3];

/// Accounts compared after execution, including the address a create transaction deploys to.
fn watched() -> Vec<Address> {
    let mut accounts = WATCHED.to_vec();
    accounts.push(CALLER.create(0));
    accounts
}

const WATCHED: [Address; 9] = [
    CALLER,
    TARGET,
    COINBASE,
    INVALID,
    REVERTER,
    REFUNDER,
    BASE_FEE_RECIPIENT,
    L1_FEE_RECIPIENT,
    OPERATOR_FEE_RECIPIENT,
];

const CODES: [(Address, &[u8]); 3] = [
    (INVALID, &[0xfe]),
    (REVERTER, &[0x60, 0x00, 0x60, 0x00, 0xfd]),
    (REFUNDER, &[0x60, 0x00, 0x60, 0x00, 0x55, 0x00]),
];

#[derive(Clone, Copy, Debug)]
enum Kind {
    Legacy { gas_price: u128 },
    Eip1559 { max_fee: u128, priority: u128 },
    Deposit { mint: u128, system: bool },
}

#[derive(Clone, Debug)]
struct Scenario {
    name: &'static str,
    spec: RevmSpec,
    kind: Kind,
    to: Address,
    /// Deploy [`INIT_CODE`] instead of calling `to`.
    create: bool,
    value: u64,
    gas_limit: u64,
    basefee: u64,
    caller_balance: u64,
    enveloped: Option<Bytes>,
    l1: RevmL1,
    /// L1Block storage to seed; when set, the cached info is stale so it must be reloaded.
    l1_storage: Vec<(U256, U256)>,
    fee_charge: bool,
    balance_check: bool,
}

impl Default for Scenario {
    fn default() -> Self {
        Self {
            name: "",
            spec: RevmSpec::REGOLITH,
            kind: Kind::Legacy { gas_price: 3 },
            to: TARGET,
            create: false,
            value: 0,
            gas_limit: 100_000,
            basefee: 2,
            caller_balance: 10_000_000_000,
            enveloped: Some(bytes!("FACADE")),
            l1: RevmL1::default(),
            l1_storage: Vec::new(),
            fee_charge: true,
            balance_check: true,
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
enum Outcome {
    Invalid,
    Success { gas_used: u64 },
    Revert { gas_used: u64 },
    Halt { gas_used: u64 },
    FailedDeposit { gas_used: u64 },
}

#[derive(Debug, PartialEq, Eq)]
struct Observed {
    outcome: Outcome,
    accounts: Vec<(Address, U256, u64)>,
}

const BLOCK_NUMBER: u64 = 7;

fn evm2_spec(spec: RevmSpec) -> Evm2Spec {
    let name: &'static str = spec.into();
    name.parse().unwrap()
}

fn evm2_l1(l1: &RevmL1) -> Evm2L1 {
    Evm2L1 {
        l2_block: l1.l2_block,
        l1_base_fee: l1.l1_base_fee,
        l1_fee_overhead: l1.l1_fee_overhead,
        l1_base_fee_scalar: l1.l1_base_fee_scalar,
        l1_blob_base_fee: l1.l1_blob_base_fee,
        l1_blob_base_fee_scalar: l1.l1_blob_base_fee_scalar,
        operator_fee_scalar: l1.operator_fee_scalar,
        operator_fee_constant: l1.operator_fee_constant,
        da_footprint_gas_scalar: l1.da_footprint_gas_scalar,
        empty_ecotone_scalars: l1.empty_ecotone_scalars,
        tx_l1_cost: l1.tx_l1_cost,
    }
}

fn cached_l1(s: &Scenario) -> RevmL1 {
    let number = if s.l1_storage.is_empty() { BLOCK_NUMBER } else { BLOCK_NUMBER + 1 };
    RevmL1 { l2_block: Some(U256::from(number)), ..s.l1.clone() }
}

fn run_op_revm(s: &Scenario) -> Observed {
    let mut db = RevmDb::default();
    db.insert_account_info(
        CALLER,
        RevmAccountInfo { balance: U256::from(s.caller_balance), ..Default::default() },
    );
    for (address, code) in CODES {
        db.insert_account_info(
            address,
            RevmAccountInfo {
                code: Some(RevmBytecode::new_raw(Bytes::from_static(code))),
                code_hash: alloy_primitives::keccak256(code),
                ..Default::default()
            },
        );
    }
    db.insert_account_storage(REFUNDER, U256::ZERO, U256::from(1)).unwrap();
    for (slot, value) in &s.l1_storage {
        db.insert_account_storage(L1_BLOCK_CONTRACT, *slot, *value).unwrap();
    }

    let mut cfg = CfgEnv::new_with_spec(s.spec);
    cfg.chain_id = 10;
    cfg.disable_fee_charge = !s.fee_charge;
    cfg.disable_balance_check = !s.balance_check;
    let block = BlockEnv {
        number: U256::from(BLOCK_NUMBER),
        beneficiary: COINBASE,
        basefee: s.basefee,
        gas_limit: 30_000_000,
        ..Default::default()
    };
    let base = TxEnv::builder()
        .caller(CALLER)
        .kind(if s.create { TxKind::Create } else { TxKind::Call(s.to) })
        .data(if s.create { Bytes::from_static(&INIT_CODE) } else { Bytes::new() })
        .value(U256::from(s.value))
        .gas_limit(s.gas_limit)
        .chain_id(Some(10))
        .nonce(0);
    let tx = match s.kind {
        Kind::Legacy { gas_price } => OpTransaction::builder()
            .base(base.tx_type(Some(0)).gas_price(gas_price).chain_id(None))
            .build_fill(),
        Kind::Eip1559 { max_fee, priority } => OpTransaction::builder()
            .base(base.tx_type(Some(2)).gas_price(max_fee).gas_priority_fee(Some(priority)))
            .build_fill(),
        Kind::Deposit { mint, system } => {
            let builder = OpTransaction::builder()
                .base(base.gas_price(0).chain_id(None))
                .source_hash(B256::with_last_byte(1))
                .mint(mint);
            let builder = if system {
                builder.is_system_transaction()
            } else {
                builder.not_system_transaction()
            };
            builder.build().unwrap()
        }
    };

    let mut tx = tx;
    if !matches!(s.kind, Kind::Deposit { .. }) {
        tx.enveloped_tx = s.enveloped.clone();
    }
    let mut evm = Context::op()
        .with_db(db)
        .with_chain(cached_l1(s))
        .with_block(block)
        .with_cfg(cfg)
        .build_op();
    let initial = |address: Address| {
        if address == CALLER { U256::from(s.caller_balance) } else { U256::ZERO }
    };
    match evm.transact(tx) {
        Err(_) => Observed {
            outcome: Outcome::Invalid,
            accounts: watched().iter().map(|a| (*a, initial(*a), 0)).collect(),
        },
        Ok(out) => {
            let gas_used = out.result.tx_gas_used();
            let outcome = match &out.result {
                ExecutionResult::Success { .. } => Outcome::Success { gas_used },
                ExecutionResult::Revert { .. } => Outcome::Revert { gas_used },
                ExecutionResult::Halt { reason: OpHaltReason::FailedDeposit, .. } => {
                    Outcome::FailedDeposit { gas_used }
                }
                ExecutionResult::Halt { .. } => Outcome::Halt { gas_used },
            };
            let accounts = watched()
                .iter()
                .map(|address| match out.state.get(address) {
                    Some(account) => (*address, account.info.balance, account.info.nonce),
                    None => (*address, initial(*address), 0),
                })
                .collect();
            Observed { outcome, accounts }
        }
    }
}

fn run_op_evm2(s: &Scenario) -> Observed {
    let mut db = Evm2Db::default();
    db.insert_account_info(
        &CALLER,
        Evm2AccountInfo::default().with_balance(U256::from(s.caller_balance)),
    );
    for (address, code) in CODES {
        db.insert_account_info(
            &address,
            Evm2AccountInfo::default().with_code(Bytecode::new_legacy(Bytes::from_static(code))),
        );
    }
    db.insert_account_storage(&REFUNDER, &U256::ZERO, &U256::from(1));
    for (slot, value) in &s.l1_storage {
        db.insert_account_storage(&L1_BLOCK_CONTRACT, slot, value);
    }

    let spec = evm2_spec(s.spec);
    let factory = OpEvmFactory;
    let mut version = factory.version(spec, 10);
    if !s.fee_charge {
        version.features.remove(EvmFeatures::FEE_CHARGE);
    }
    if !s.balance_check {
        version.features.remove(EvmFeatures::BALANCE_CHECK);
    }
    let block = BlockEnvExt {
        number: U256::from(BLOCK_NUMBER),
        beneficiary: COINBASE,
        basefee: U256::from(s.basefee),
        gas_limit: U256::from(30_000_000),
        ..Default::default()
    };
    let mut evm = factory.create_evm(spec, version, block, db);
    evm.ext_mut().l1_block_info = evm2_l1(&cached_l1(s));

    let to = if s.create { TxKind::Create } else { TxKind::Call(s.to) };
    let input = if s.create { Bytes::from_static(&INIT_CODE) } else { Bytes::new() };
    let value = U256::from(s.value);
    let envelope = match s.kind {
        Kind::Legacy { gas_price } => OpTxEnvelope::new(
            TxLegacy { gas_price, gas_limit: s.gas_limit, to, value, input, ..Default::default() },
            s.enveloped.clone(),
        ),
        Kind::Eip1559 { max_fee, priority } => OpTxEnvelope::new(
            TxEip1559 {
                chain_id: 10,
                gas_limit: s.gas_limit,
                max_fee_per_gas: max_fee,
                max_priority_fee_per_gas: priority,
                to,
                value,
                input,
                ..Default::default()
            },
            s.enveloped.clone(),
        ),
        Kind::Deposit { mint, system } => OpTxEnvelope::deposit(TxDeposit {
            source_hash: B256::with_last_byte(1),
            from: CALLER,
            to,
            mint,
            value,
            gas_limit: s.gas_limit,
            is_system_transaction: system,
            input,
        }),
    };
    let tx = Recovered::new_unchecked(envelope, CALLER);
    let outcome = match evm.transact(&tx).map(|executed| executed.commit()) {
        Err(_) => Outcome::Invalid,
        Ok(result) => {
            let gas_used = result.tx_gas_used();
            if result.ext.failed_deposit {
                Outcome::FailedDeposit { gas_used }
            } else if result.status {
                Outcome::Success { gas_used }
            } else if result.is_revert() {
                Outcome::Revert { gas_used }
            } else {
                Outcome::Halt { gas_used }
            }
        }
    };
    let accounts = watched()
        .iter()
        .map(|address| {
            let info = evm.state_mut().account_info_untracked(address).unwrap().unwrap_or_default();
            (*address, info.balance, info.nonce)
        })
        .collect();
    Observed { outcome, accounts }
}

fn regolith_l1() -> RevmL1 {
    RevmL1 {
        l1_base_fee: U256::from(1_000),
        l1_fee_overhead: Some(U256::from(1_000)),
        l1_base_fee_scalar: U256::from(1_000),
        ..Default::default()
    }
}

/// OP mainnet Ecotone block 118024092 L1 attributes (op-revm vector).
fn ecotone_l1() -> RevmL1 {
    RevmL1 {
        l1_base_fee: U256::from(47036678951u64),
        l1_base_fee_scalar: U256::from(1368),
        l1_blob_base_fee: Some(U256::from(57422457042u64)),
        l1_blob_base_fee_scalar: Some(U256::from(810949)),
        ..Default::default()
    }
}

/// OP mainnet Fjord block 124665056 L1 attributes plus operator fee parameters.
fn fjord_l1(operator_fee_scalar: u64, operator_fee_constant: u64) -> RevmL1 {
    RevmL1 {
        l1_base_fee: U256::from(1055991687),
        l1_base_fee_scalar: U256::from(5227),
        l1_blob_base_fee_scalar: Some(U256::from(1014213)),
        l1_blob_base_fee: Some(U256::from(1)),
        operator_fee_scalar: Some(U256::from(operator_fee_scalar)),
        operator_fee_constant: Some(U256::from(operator_fee_constant)),
        ..Default::default()
    }
}

/// The second transaction of OP mainnet Ecotone block 118024092 (op-revm vector).
const ECOTONE_TX: [u8; 182] = hex!(
    "02f8b30a832253fc8402d11f39842c8a46398301388094dc6ff44d5d932cbd77b52e5612ba0529dc6226f180b844a9059cbb000000000000000000000000d43e02db81f4d46cdf8521f623d21ea0ec7562a50000000000000000000000000000000000000000000000008ac7230489e80000c001a02947e24750723b48f886931562c55d9e07f856d8e06468e719755e18bbc3a570a0784da9ce59fd7754ea5be6e17a86b348e441348cd48ace59d174772465eadbd1"
);

fn scenarios() -> Vec<Scenario> {
    let isthmus_storage = {
        let mut packed = [0u8; 32];
        packed[31] = 6;
        packed[23] = 5;
        packed[19] = 7;
        vec![
            (L1_BASE_FEE_SLOT, U256::from(1_000_000_000u64)),
            (ECOTONE_L1_BLOB_BASE_FEE_SLOT, U256::from(2)),
            (
                ECOTONE_L1_FEE_SCALARS_SLOT,
                U256::from_limbs([0, (3_000 << (64 - BASE_FEE_SCALAR_OFFSET * 2)) | 4, 0, 0]),
            ),
            (OPERATOR_FEE_SCALARS_SLOT, U256::from_be_bytes(packed)),
        ]
    };
    let bedrock_storage = vec![
        (L1_BASE_FEE_SLOT, U256::from(7_000)),
        (L1_OVERHEAD_SLOT, U256::from(2_100)),
        (L1_SCALAR_SLOT, U256::from(1_000_000)),
    ];
    let mut out = vec![
        Scenario { name: "regolith legacy transfer", l1: regolith_l1(), ..Default::default() },
        Scenario {
            name: "regolith legacy exact balance",
            l1: regolith_l1(),
            gas_limit: 30_000,
            caller_balance: 30_000 * 3 + 1_048,
            ..Default::default()
        },
        Scenario {
            name: "regolith legacy short of the L1 fee",
            l1: regolith_l1(),
            gas_limit: 30_000,
            caller_balance: 30_000 * 3 + 1_047,
            ..Default::default()
        },
        Scenario {
            name: "bedrock legacy, L1 info from storage",
            spec: RevmSpec::BEDROCK,
            l1_storage: bedrock_storage,
            ..Default::default()
        },
        Scenario {
            name: "ecotone 1559 refund",
            spec: RevmSpec::ECOTONE,
            kind: Kind::Eip1559 { max_fee: 10, priority: 3 },
            to: REFUNDER,
            basefee: 5,
            enveloped: Some(Bytes::from_static(&ECOTONE_TX)),
            l1: ecotone_l1(),
            ..Default::default()
        },
        Scenario {
            name: "ecotone empty scalars uses bedrock function",
            spec: RevmSpec::ECOTONE,
            l1: RevmL1 { empty_ecotone_scalars: true, ..regolith_l1() },
            ..Default::default()
        },
        Scenario {
            name: "fjord revert",
            spec: RevmSpec::FJORD,
            kind: Kind::Eip1559 { max_fee: 10, priority: 3 },
            to: REVERTER,
            basefee: 5,
            enveloped: Some(Bytes::from_static(&ECOTONE_TX)),
            l1: fjord_l1(0, 0),
            ..Default::default()
        },
        Scenario {
            name: "isthmus operator fee with refund",
            spec: RevmSpec::ISTHMUS,
            kind: Kind::Eip1559 { max_fee: 10, priority: 3 },
            to: REFUNDER,
            basefee: 5,
            l1: fjord_l1(10_000_000, 50),
            ..Default::default()
        },
        Scenario {
            name: "isthmus halt",
            spec: RevmSpec::ISTHMUS,
            to: INVALID,
            l1: fjord_l1(10_000_000, 50),
            ..Default::default()
        },
        Scenario {
            name: "isthmus empty envelope still refunds operator fee",
            spec: RevmSpec::ISTHMUS,
            enveloped: Some(Bytes::new()),
            l1: fjord_l1(10_000_000, 50),
            ..Default::default()
        },
        Scenario {
            name: "jovian operator fee, L1 info from storage",
            spec: RevmSpec::JOVIAN,
            kind: Kind::Eip1559 { max_fee: 10, priority: 3 },
            to: REFUNDER,
            basefee: 5,
            l1_storage: isthmus_storage,
            ..Default::default()
        },
        Scenario {
            name: "jovian short of the operator fee",
            spec: RevmSpec::JOVIAN,
            gas_limit: 30_000,
            caller_balance: 30_000 * 3 + 30_000 * 200 + 49,
            l1: RevmL1 {
                operator_fee_scalar: Some(U256::from(2)),
                operator_fee_constant: Some(U256::from(50)),
                ..Default::default()
            },
            ..Default::default()
        },
        Scenario {
            name: "karst legacy",
            spec: RevmSpec::KARST,
            l1: fjord_l1(2, 50),
            ..Default::default()
        },
        Scenario {
            name: "jovian fee charge disabled",
            spec: RevmSpec::JOVIAN,
            kind: Kind::Eip1559 { max_fee: 10, priority: 3 },
            basefee: 5,
            l1: fjord_l1(2, 50),
            fee_charge: false,
            ..Default::default()
        },
        Scenario {
            name: "jovian balance check disabled, funded caller",
            spec: RevmSpec::JOVIAN,
            l1: fjord_l1(2, 50),
            balance_check: false,
            ..Default::default()
        },
        Scenario {
            name: "isthmus legacy create",
            spec: RevmSpec::ISTHMUS,
            create: true,
            value: 3,
            l1: fjord_l1(10_000_000, 50),
            ..Default::default()
        },
        Scenario {
            name: "canyon deposit create",
            spec: RevmSpec::CANYON,
            kind: Kind::Deposit { mint: 1_000, system: false },
            create: true,
            value: 3,
            caller_balance: 0,
            ..Default::default()
        },
        Scenario {
            name: "missing enveloped tx",
            spec: RevmSpec::JOVIAN,
            enveloped: None,
            ..Default::default()
        },
    ];
    for spec in [RevmSpec::BEDROCK, RevmSpec::REGOLITH, RevmSpec::JOVIAN] {
        for (to, value, gas_limit, system) in [
            (TARGET, 5, 50_000, false),
            (TARGET, 5, 50_000, true),
            (REVERTER, 0, 50_000, false),
            (INVALID, 5, 50_000, false),
            (INVALID, 5, 50_000, true),
            (REFUNDER, 0, 50_000, false),
            (TARGET, 0, 20_000, false),
            (TARGET, 0, 20_000, true),
            // The value exceeds the mint plus the caller's balance.
            (TARGET, 5_000, 50_000, false),
            (TARGET, 5_000, 50_000, true),
        ] {
            out.push(Scenario {
                name: "deposit",
                spec,
                kind: Kind::Deposit { mint: 1_000, system },
                to,
                value,
                gas_limit,
                caller_balance: 100,
                l1: regolith_l1(),
                ..Default::default()
            });
        }
    }
    out
}

#[test]
fn fee_and_settlement_parity_with_op_revm() {
    let mut failures = Vec::new();
    for scenario in scenarios() {
        let expected = run_op_revm(&scenario);
        let actual = run_op_evm2(&scenario);
        if expected != actual {
            failures.push(format!(
                "{} ({:?} {:?} -> {}):\n  op-revm:  {expected:?}\n  op-evm2: {actual:?}",
                scenario.name, scenario.spec, scenario.kind, scenario.to
            ));
        }
    }
    assert!(failures.is_empty(), "{} mismatches:\n{}", failures.len(), failures.join("\n"));
}

#[test]
fn scenarios_exercise_every_outcome() {
    let outcomes: Vec<_> = scenarios().iter().map(run_op_evm2).map(|o| o.outcome).collect();
    assert!(outcomes.iter().any(|o| matches!(o, Outcome::Invalid)));
    assert!(outcomes.iter().any(|o| matches!(o, Outcome::Success { .. })));
    assert!(outcomes.iter().any(|o| matches!(o, Outcome::Revert { .. })));
    assert!(outcomes.iter().any(|o| matches!(o, Outcome::Halt { .. })));
    assert!(outcomes.iter().any(|o| matches!(o, Outcome::FailedDeposit { .. })));

    // Both create scenarios deploy to `CALLER.create(0)` with the transferred value.
    let created = CALLER.create(0);
    for scenario in scenarios().iter().filter(|s| s.create) {
        let observed = run_op_evm2(scenario);
        assert!(matches!(observed.outcome, Outcome::Success { .. }), "{}", scenario.name);
        assert!(observed.accounts.contains(&(created, U256::from(3), 1)), "{}", scenario.name);
    }
}
