//! End-to-end execution tests.
//!
//! Expected balances are derived from bsc's fee settlement (`core/state_transition.go`), not from
//! this implementation.

use crate::{
    BSC_MAINNET_CHAIN_ID, BSC_MAX_BLOBS_PER_TX, BSC_SYSTEM_ADDRESS, BscBlockEnv, BscEvmFactory,
    BscEvmTypes, BscHardfork,
};
use alloy_consensus::{TxEip1559, TxEip4844, TxLegacy, transaction::Recovered};
use alloy_eips::eip4844::DATA_GAS_PER_BLOB;
use alloy_primitives::{Address, B256, TxKind, U256, address};
use evm2::{
    TxResult,
    ethereum::TxEnvelope,
    evm::{AccountInfo, InMemoryDB},
    interpreter::InstrStop,
    registry::HandlerError,
};

const CALLER: Address = address!("0x00000000000000000000000000000000000ca11e");
const CONTRACT: Address = address!("0x000000000000000000000000000000000000c0de");
const COINBASE: Address = address!("0x5cf810ab8c718ac065b45f892a5badab2b2946b9");
const CALLER_BALANCE: u64 = 1_000_000_000_000_000_000;
const COINBASE_BALANCE: u64 = 5;
const SYSTEM_BALANCE: u64 = 7;

/// Runs `tx` from [`CALLER`] and returns the result and the balances of the caller, the coinbase
/// and the system address afterwards.
fn exec(
    spec: BscHardfork,
    block: BscBlockEnv,
    code: &[u8],
    tx: TxEnvelope,
) -> (Result<TxResult<BscEvmTypes>, HandlerError>, [U256; 3]) {
    let mut db = InMemoryDB::default();
    for (address, balance) in [
        (CALLER, CALLER_BALANCE),
        (COINBASE, COINBASE_BALANCE),
        (BSC_SYSTEM_ADDRESS, SYSTEM_BALANCE),
    ] {
        db.insert_account_info(&address, AccountInfo::default().with_balance(U256::from(balance)));
    }
    db.insert_account_info(
        &CONTRACT,
        AccountInfo::default().with_code(evm2::bytecode::Bytecode::new_raw(code.to_vec().into())),
    );
    let factory = BscEvmFactory;
    let block = BscBlockEnv { beneficiary: COINBASE, ..block };
    let mut evm = factory.create_evm(spec, factory.version(spec, BSC_MAINNET_CHAIN_ID), block, db);
    let result = evm.transact(&Recovered::new_unchecked(tx, CALLER)).map(|tx| tx.commit());
    let balances = [CALLER, COINBASE, BSC_SYSTEM_ADDRESS].map(|address| {
        evm.read_account_info(&address).unwrap().map_or(U256::ZERO, |info| info.balance)
    });
    (result, balances)
}

/// `PUSH1 0 PUSH1 0 SSTORE STOP`: one cold zero-to-zero store.
const SSTORE_CODE: &[u8] = &[0x60, 0x00, 0x60, 0x00, 0x55, 0x00];

#[test]
fn fee_goes_to_system_address() {
    let gas_price = 3_000_000_000u128;
    let tx = TxEnvelope::Legacy(TxLegacy {
        chain_id: Some(BSC_MAINNET_CHAIN_ID),
        gas_price,
        gas_limit: 100_000,
        to: TxKind::Call(CONTRACT),
        ..Default::default()
    });
    let (result, [caller, coinbase, system]) =
        exec(BscHardfork::Pasteur, BscBlockEnv::default(), SSTORE_CODE, tx);
    let result = result.unwrap();
    assert!(result.status);
    // Intrinsic 21,000, two pushes 6, cold SLOAD-for-SSTORE 2,100 plus warm 100.
    let gas_used = 21_000 + 6 + 2_200;
    assert_eq!(result.tx_gas_used(), gas_used);
    let fee = U256::from(gas_used) * U256::from(gas_price);
    assert_eq!(caller, U256::from(CALLER_BALANCE) - fee);
    assert_eq!(coinbase, U256::from(COINBASE_BALANCE));
    assert_eq!(system, U256::from(SYSTEM_BALANCE) + fee);
}

#[test]
fn base_fee_is_burnt() {
    let tx = TxEnvelope::Eip1559(TxEip1559 {
        chain_id: BSC_MAINNET_CHAIN_ID,
        max_fee_per_gas: 10,
        max_priority_fee_per_gas: 3,
        gas_limit: 50_000,
        to: TxKind::Call(CONTRACT),
        ..Default::default()
    });
    let block = BscBlockEnv { basefee: U256::from(4), ..Default::default() };
    let (result, [caller, coinbase, system]) = exec(BscHardfork::Pasteur, block, &[], tx);
    assert_eq!(result.unwrap().tx_gas_used(), 21_000);
    // Effective price 4 + 3: the sender pays 7 per gas, the system address receives the tip.
    assert_eq!(caller, U256::from(CALLER_BALANCE - 21_000 * 7));
    assert_eq!(coinbase, U256::from(COINBASE_BALANCE));
    assert_eq!(system, U256::from(SYSTEM_BALANCE + 21_000 * 3));
}

fn blob_tx(blobs: usize) -> TxEnvelope {
    // A KZG versioned hash starts with the version byte 0x01.
    let mut blob_hash = B256::ZERO;
    blob_hash[0] = 1;
    TxEnvelope::Eip4844(
        TxEip4844 {
            chain_id: BSC_MAINNET_CHAIN_ID,
            max_fee_per_gas: 2,
            max_priority_fee_per_gas: 2,
            max_fee_per_blob_gas: 5,
            gas_limit: 50_000,
            to: CONTRACT,
            blob_versioned_hashes: vec![blob_hash; blobs],
            ..Default::default()
        }
        .into(),
    )
}

#[test]
fn blob_fee_goes_to_system_address() {
    let block = BscBlockEnv { blob_basefee: U256::from(3), ..Default::default() };
    let (result, [caller, _, system]) = exec(BscHardfork::Pasteur, block, &[], blob_tx(2));
    assert_eq!(result.unwrap().tx_gas_used(), 21_000);
    let blob_fee = 2 * DATA_GAS_PER_BLOB * 3;
    assert_eq!(caller, U256::from(CALLER_BALANCE - 21_000 * 2 - blob_fee));
    assert_eq!(system, U256::from(SYSTEM_BALANCE + 21_000 * 2 + blob_fee));
}

#[test]
fn blob_limit_is_six_in_every_fork() {
    for spec in [BscHardfork::Cancun, BscHardfork::Prague, BscHardfork::Pasteur] {
        let (result, _) = exec(spec, BscBlockEnv::default(), &[], blob_tx(BSC_MAX_BLOBS_PER_TX));
        assert!(result.unwrap().status, "{spec}");
        let (result, _) =
            exec(spec, BscBlockEnv::default(), &[], blob_tx(BSC_MAX_BLOBS_PER_TX + 1));
        assert!(result.is_err(), "{spec}");
    }
    // Blob transactions are rejected before Cancun.
    let (result, _) = exec(BscHardfork::FeynmanFix, BscBlockEnv::default(), &[], blob_tx(1));
    assert!(result.is_err());
}

#[test]
fn clz_activates_at_osaka() {
    // `CLZ(1)` returned as a word.
    let code = [0x60, 1, 0x1e, 0x60, 0, 0x52, 0x60, 32, 0x60, 0, 0xf3];
    let tx = || {
        TxEnvelope::Legacy(TxLegacy {
            gas_limit: 100_000,
            to: TxKind::Call(CONTRACT),
            ..Default::default()
        })
    };
    let (fermi, _) = exec(BscHardfork::Fermi, BscBlockEnv::default(), &code, tx());
    assert_eq!(fermi.unwrap().stop, InstrStop::NotActivated);
    let (osaka, _) = exec(BscHardfork::Osaka, BscBlockEnv::default(), &code, tx());
    let osaka = osaka.unwrap();
    assert!(osaka.status);
    assert_eq!(osaka.output[31], 255);
}

#[test]
fn precompile_reverts_keep_gas_and_halts_consume_it() {
    let gas_limit = 121_000;
    let call = |address: u8| {
        let tx = TxEnvelope::Legacy(TxLegacy {
            gas_limit,
            to: TxKind::Call(Address::with_last_byte(address)),
            ..Default::default()
        });
        let (result, _) = exec(BscHardfork::Pasteur, BscBlockEnv::default(), &[], tx);
        let result = result.unwrap();
        (result.stop, result.tx_gas_used())
    };
    // Malformed input to 0x66 and 0x68 reverts after charging the precompile's gas.
    assert_eq!(call(0x66), (InstrStop::Revert, 21_000 + 1_000));
    assert_eq!(call(0x68), (InstrStop::Revert, 21_000 + 10_000));
    // 0x69 and the deprecated or unsupported light-client precompiles halt.
    for address in [0x64, 0x65, 0x67, 0x69] {
        assert_eq!(call(address), (InstrStop::PrecompileError, gas_limit), "{address:#x}");
    }
}
