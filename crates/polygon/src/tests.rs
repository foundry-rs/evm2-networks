//! End-to-end execution tests.
//!
//! Expected gas and balances are derived from Bor's formulas (`core/vm/operations_acl.go`,
//! `core/state_transition.go`), not from this implementation.

use crate::{
    POLYGON_FEE_ADDRESS, POLYGON_FEE_TRANSFER_LOG_TOPIC, POLYGON_MAINNET_CHAIN_ID,
    POLYGON_RIO_COINBASE, PolygonBlockEnv, PolygonEvmFactory, PolygonHardfork, polygon_tx_registry,
};
use alloy_consensus::{TxLegacy, transaction::Recovered};
use alloy_primitives::{Address, Bytes, Log, TxKind, U256, address};
use evm2::{
    TxResult,
    ethereum::TxEnvelope,
    evm::{AccountInfo, InMemoryDB},
    interpreter::InstrStop,
    registry::HandlerError,
};

const CALLER: Address = address!("0x00000000000000000000000000000000000ca11e");
const CONTRACT: Address = address!("0x000000000000000000000000000000000000c0de");
const CALLER_BALANCE: u64 = 1_000_000_000_000_000_000;
const COINBASE_BALANCE: u64 = 5;

/// Burnt contract active at [`MAINNET_BLOCK`].
const BURNT_CONTRACT: Address = address!("0x3ef57def668054dd750bd260526105c4eeef104f");
const MAINNET_BLOCK: u64 = 90_000_000;

/// Transaction and environment for one execution.
struct Run {
    spec: PolygonHardfork,
    chain_id: u64,
    block: u64,
    basefee: u64,
    gas_price: u128,
    gas_limit: u64,
    to: TxKind,
    input: Vec<u8>,
    code: Vec<u8>,
    storage: Vec<(U256, U256)>,
}

impl Run {
    fn new(spec: PolygonHardfork) -> Self {
        Self {
            spec,
            chain_id: POLYGON_MAINNET_CHAIN_ID,
            block: MAINNET_BLOCK,
            basefee: 0,
            gas_price: 0,
            gas_limit: 1_000_000,
            to: TxKind::Call(CONTRACT),
            input: Vec::new(),
            code: Vec::new(),
            storage: Vec::new(),
        }
    }

    fn code(mut self, code: &[u8]) -> Self {
        self.code = code.to_vec();
        self
    }

    /// Executes the transaction and returns its result and the balances of `watch` afterwards.
    fn exec(
        &self,
        watch: &[Address],
    ) -> (Result<TxResult<crate::PolygonEvmTypes>, HandlerError>, Vec<U256>) {
        let mut db = InMemoryDB::default();
        db.insert_account_info(
            &CALLER,
            AccountInfo::default().with_balance(U256::from(CALLER_BALANCE)),
        );
        db.insert_account_info(
            &POLYGON_RIO_COINBASE,
            AccountInfo::default().with_balance(U256::from(COINBASE_BALANCE)),
        );
        db.insert_account_info(
            &CONTRACT,
            AccountInfo::default()
                .with_code(evm2::bytecode::Bytecode::new_raw(self.code.clone().into())),
        );
        for (key, value) in &self.storage {
            db.insert_account_storage(&CONTRACT, key, value);
        }

        let factory = PolygonEvmFactory;
        let block = PolygonBlockEnv {
            number: U256::from(self.block),
            beneficiary: POLYGON_RIO_COINBASE,
            basefee: U256::from(self.basefee),
            ..Default::default()
        };
        let mut evm =
            factory.create_evm(self.spec, factory.version(self.spec, self.chain_id), block, db);
        let tx = TxEnvelope::Legacy(TxLegacy {
            chain_id: Some(self.chain_id),
            gas_price: self.gas_price,
            gas_limit: self.gas_limit,
            to: self.to,
            input: self.input.clone().into(),
            ..Default::default()
        });
        let result = evm.transact(&Recovered::new_unchecked(tx, CALLER)).map(|tx| tx.commit());
        let balances = watch
            .iter()
            .map(|address| {
                evm.read_account_info(address).unwrap().map_or(U256::ZERO, |info| info.balance)
            })
            .collect();
        (result, balances)
    }

    fn result(&self) -> TxResult<crate::PolygonEvmTypes> {
        self.exec(&[]).0.unwrap()
    }
}

/// Opcode bytes used by the test contracts.
mod op {
    pub(super) const STOP: u8 = 0x00;
    pub(super) const CLZ: u8 = 0x1e;
    pub(super) const MSTORE: u8 = 0x52;
    pub(super) const SLOAD: u8 = 0x54;
    pub(super) const SSTORE: u8 = 0x55;
    pub(super) const PUSH1: u8 = 0x60;
    pub(super) const PUSH2: u8 = 0x61;
    pub(super) const RETURN: u8 = 0xf3;
    pub(super) const REVERT: u8 = 0xfd;
}

/// `CLZ(1)` returned as a word.
const CLZ_CODE: &[u8] =
    &[op::PUSH1, 1, op::CLZ, op::PUSH1, 0, op::MSTORE, op::PUSH1, 32, op::PUSH1, 0, op::RETURN];

#[test]
fn clz_activates_at_lisovo() {
    let dandeli = Run::new(PolygonHardfork::Dandeli).code(CLZ_CODE).result();
    assert!(!dandeli.status);
    assert_eq!(dandeli.stop, InstrStop::NotActivated);

    for spec in [PolygonHardfork::Lisovo, PolygonHardfork::Chicago, PolygonHardfork::Austin] {
        let result = Run::new(spec).code(CLZ_CODE).result();
        assert!(result.status, "{spec}");
        assert_eq!(result.output, Bytes::from(U256::from(255).to_be_bytes::<32>()), "{spec}");
    }
}

#[test]
fn pip88_sload_pricing() {
    // A cold then a warm load of slot 0.
    let code = [op::PUSH1, 0, op::SLOAD, op::PUSH1, 0, op::SLOAD, op::STOP];
    let gas = |spec| Run::new(spec).code(&code).result().tx_gas_used();
    // 21,000 intrinsic + 2 × PUSH1 + cold SLOAD + warm SLOAD (100).
    assert_eq!(gas(PolygonHardfork::Giugliano), 21_000 + 6 + 2_100 + 100);
    assert_eq!(gas(PolygonHardfork::Chicago), 21_000 + 6 + 5_460 + 100);
    assert_eq!(gas(PolygonHardfork::Austin), 21_000 + 6 + 5_460 + 100);
}

#[test]
fn pip88_sload_out_of_gas_on_cold_surcharge() {
    // Enough gas for the Ethereum cold surcharge but not PIP-88's.
    let code = [op::PUSH1, 0, op::SLOAD, op::STOP];
    let mut run = Run::new(PolygonHardfork::Chicago).code(&code);
    run.gas_limit = 21_000 + 3 + 5_000;
    let result = run.result();
    assert_eq!(result.stop, InstrStop::OutOfGas);

    run.spec = PolygonHardfork::Giugliano;
    assert!(run.result().status);
}

#[test]
fn pip88_sstore_pricing() {
    // Clearing a cold, non-zero slot: `cold + (5,000 - cold)` gas and the clearing refund.
    let clear = [op::PUSH1, 0, op::PUSH1, 0, op::SSTORE, op::STOP];
    // Writing a cold slot then restoring its original value: one clean write, one dirty write
    // (warm read cost) and the reset refund `(5,000 - cold) - 100`.
    let restore = [op::PUSH1, 2, op::PUSH1, 0, op::SSTORE, op::PUSH1, 1, op::PUSH1, 0, op::SSTORE];
    // Creating a cold slot: `cold + 20,000`.
    let create = [op::PUSH1, 1, op::PUSH1, 1, op::SSTORE, op::STOP];
    let gas = |spec, code: &[u8]| {
        let mut run = Run::new(spec).code(code);
        run.storage = vec![(U256::ZERO, U256::from(1))];
        run.result().tx_gas_used()
    };

    let spent = 21_000 + 6 + 5_000;
    assert_eq!(gas(PolygonHardfork::Giugliano, &clear), spent - 4_800);
    assert_eq!(gas(PolygonHardfork::Chicago, &clear), spent - 3_960);

    let spent = 21_000 + 12 + 5_000 + 100;
    assert_eq!(gas(PolygonHardfork::Giugliano, &restore), spent - 2_800);
    assert_eq!(gas(PolygonHardfork::Chicago, &restore), spent - 1_960);

    assert_eq!(gas(PolygonHardfork::Giugliano, &create), 21_000 + 6 + 2_100 + 20_000);
    assert_eq!(gas(PolygonHardfork::Chicago, &create), 21_000 + 6 + 2_940 + 20_000);
}

#[test]
fn code_size_limit_from_ahmedabad() {
    // A create transaction whose initcode returns `size` zero bytes.
    let deploys = |spec, size: u16| {
        let [hi, lo] = size.to_be_bytes();
        let mut run = Run::new(spec);
        run.to = TxKind::Create;
        run.input = vec![op::PUSH2, hi, lo, op::PUSH1, 0, op::RETURN];
        run.gas_limit = 10_000_000;
        run.result().status
    };
    assert!(deploys(PolygonHardfork::Cancun, 24_576));
    assert!(!deploys(PolygonHardfork::Cancun, 24_577));
    assert!(deploys(PolygonHardfork::Ahmedabad, 32_768));
    assert!(!deploys(PolygonHardfork::Ahmedabad, 32_769));
    assert!(deploys(PolygonHardfork::Austin, 32_768));
    assert!(!deploys(PolygonHardfork::Austin, 32_769));
}

#[test]
fn tx_gas_limit_cap_from_madhugiri() {
    let exec = |spec, gas_limit| {
        let mut run = Run::new(spec).code(&[op::STOP]);
        run.gas_limit = gas_limit;
        run.exec(&[]).0
    };
    assert!(exec(PolygonHardfork::Madhugiri, 33_554_432).is_ok());
    assert_eq!(
        exec(PolygonHardfork::Madhugiri, 33_554_433).unwrap_err(),
        HandlerError::TxGasLimitGreaterThanCap { gas_limit: 33_554_433, cap: 33_554_432 }
    );
    assert!(exec(PolygonHardfork::Rio, 33_554_433).is_ok());
}

/// Bor's fee transfer log for a transaction paying `tip` from [`CALLER`] to the coinbase.
fn fee_log(tip: u64) -> Log {
    let words = [
        U256::from(tip),
        U256::from(CALLER_BALANCE),
        U256::from(COINBASE_BALANCE),
        U256::from(CALLER_BALANCE - tip),
        U256::from(COINBASE_BALANCE + tip),
    ];
    Log::new_unchecked(
        POLYGON_FEE_ADDRESS,
        vec![
            POLYGON_FEE_TRANSFER_LOG_TOPIC,
            POLYGON_FEE_ADDRESS.into_word(),
            CALLER.into_word(),
            POLYGON_RIO_COINBASE.into_word(),
        ],
        words.iter().flat_map(|word| word.to_be_bytes::<32>()).collect::<Vec<_>>().into(),
    )
}

#[test]
fn base_fee_credited_to_burnt_contract() {
    // London (Jaipur) activation block with the first mainnet burnt contract, and the latest one.
    for (spec, block, burnt_contract) in [
        (
            PolygonHardfork::Jaipur,
            23_850_000,
            address!("0x70bca57f4579f58670ab2d18ef16e02c17553c38"),
        ),
        (PolygonHardfork::Chicago, MAINNET_BLOCK, BURNT_CONTRACT),
    ] {
        let mut run = Run::new(spec).code(&[op::STOP]);
        run.block = block;
        run.basefee = 7;
        run.gas_price = 10;
        let (result, balances) = run.exec(&[CALLER, POLYGON_RIO_COINBASE, burnt_contract]);
        let result = result.unwrap();
        assert_eq!(result.tx_gas_used(), 21_000, "{spec}");
        assert_eq!(
            balances,
            [
                U256::from(CALLER_BALANCE - 21_000 * 10),
                U256::from(COINBASE_BALANCE + 21_000 * 3),
                U256::from(21_000 * 7),
            ],
            "{spec}"
        );
        assert_eq!(result.logs, [fee_log(21_000 * 3)], "{spec}");
    }
}

#[test]
fn fee_log_kept_on_revert() {
    let code = [op::PUSH1, 0, op::PUSH1, 0, op::REVERT];
    let mut run = Run::new(PolygonHardfork::Chicago).code(&code);
    run.basefee = 7;
    run.gas_price = 10;
    let result = run.result();
    assert_eq!(result.stop, InstrStop::Revert);
    let gas_used = 21_000 + 6;
    assert_eq!(result.tx_gas_used(), gas_used);
    assert_eq!(result.logs, [fee_log(gas_used * 3)]);
}

#[test]
fn no_fee_log_without_tip() {
    let mut run = Run::new(PolygonHardfork::Chicago).code(&[op::STOP]);
    run.basefee = 10;
    run.gas_price = 10;
    let (result, balances) = run.exec(&[POLYGON_RIO_COINBASE, BURNT_CONTRACT]);
    assert!(result.unwrap().logs.is_empty());
    assert_eq!(balances, [U256::from(COINBASE_BALANCE), U256::from(21_000 * 10)]);
}

#[test]
fn base_fee_burned_on_unknown_chain() {
    let mut run = Run::new(PolygonHardfork::Chicago).code(&[op::STOP]);
    run.chain_id = 1;
    run.basefee = 7;
    run.gas_price = 10;
    let (result, balances) = run.exec(&[CALLER, POLYGON_RIO_COINBASE, BURNT_CONTRACT]);
    assert_eq!(result.unwrap().logs, [fee_log(21_000 * 3)]);
    assert_eq!(
        balances,
        [
            U256::from(CALLER_BALANCE - 21_000 * 10),
            U256::from(COINBASE_BALANCE + 21_000 * 3),
            U256::ZERO,
        ]
    );
}

#[test]
fn pre_london_pays_full_price_to_coinbase() {
    let mut run = Run::new(PolygonHardfork::Berlin).code(&[op::STOP]);
    run.block = 14_000_000;
    run.gas_price = 10;
    let (result, balances) = run.exec(&[POLYGON_RIO_COINBASE]);
    assert_eq!(result.unwrap().logs, [fee_log(21_000 * 10)]);
    assert_eq!(balances, [U256::from(COINBASE_BALANCE + 21_000 * 10)]);
}

#[test]
fn tx_types_per_fork() {
    let types =
        |spec| (0..=4).filter(|ty| polygon_tx_registry(spec).contains(*ty)).collect::<Vec<_>>();
    assert_eq!(types(PolygonHardfork::Istanbul), [0]);
    assert_eq!(types(PolygonHardfork::Berlin), [0, 1]);
    assert_eq!(types(PolygonHardfork::Jaipur), [0, 1, 2]);
    // No EIP-4844 on Polygon.
    assert_eq!(types(PolygonHardfork::Cancun), [0, 1, 2]);
    assert_eq!(types(PolygonHardfork::Bhilai), [0, 1, 2, 4]);
    assert_eq!(types(PolygonHardfork::Austin), [0, 1, 2, 4]);
}
