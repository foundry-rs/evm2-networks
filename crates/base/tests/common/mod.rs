//! Shared harness for the differential parity tests against the revm-based `base-common-evm`.

#![allow(dead_code, unreachable_pub)]

use std::collections::BTreeMap;

use alloy_evm::Evm;
use alloy_primitives::{Address, B256, Bytes, Log, U256, keccak256};
use base_common_consensus::Predeploys;
use base_common_evm::{BaseHaltReason, BaseTransaction, Builder, DefaultBase};
use base_common_genesis::BaseUpgrade;
use base_evm2::{BaseEvm, BaseEvmFactory, BaseSpecId, BaseTxEnvelope, L1BlockInfo, base_version};
use evm2::{
    EvmFeatures, TxResult, bytecode::Bytecode as Evm2Bytecode, env::BlockEnv,
    evm::InMemoryDB as Evm2Db, registry::HandlerError,
};
use revm::{
    Database, ExecuteCommitEvm,
    bytecode::Bytecode as RevmBytecode,
    context::{BlockEnv as RevmBlockEnv, CfgEnv, Context, ContextTr, TxEnv},
    context_interface::result::{ExecutionResult, Output},
    database::InMemoryDB as RevmDb,
    inspector::NoOpInspector,
    state::AccountInfo as RevmAccountInfo,
};

pub const CHAIN_ID: u64 = 8453;
pub const BLOCK_NUMBER: u64 = 1_000;
pub const COINBASE: Address = Address::repeat_byte(0xc0);

/// An account seeded into both engines before execution.
#[derive(Clone, Debug)]
pub struct Seed {
    pub address: Address,
    pub balance: U256,
    pub nonce: u64,
    pub code: Vec<u8>,
    pub storage: Vec<(U256, U256)>,
}

impl Seed {
    pub fn eoa(address: Address, balance: U256) -> Self {
        Self { address, balance, nonce: 0, code: vec![], storage: vec![] }
    }

    pub fn contract(address: Address, code: Vec<u8>) -> Self {
        Self { address, balance: U256::ZERO, nonce: 1, code, storage: vec![] }
    }

    pub fn with_storage(mut self, storage: Vec<(U256, U256)>) -> Self {
        self.storage = storage;
        self
    }
}

/// Engine configuration shared by both sides.
#[derive(Clone, Copy, Debug)]
pub struct Env {
    pub upgrade: BaseUpgrade,
    pub basefee: u64,
    pub fee_charge: bool,
    pub balance_check: bool,
    pub base_fee_check: bool,
    pub activation_admin: Option<Address>,
}

impl Env {
    pub const fn new(upgrade: BaseUpgrade) -> Self {
        Self {
            upgrade,
            basefee: 0,
            fee_charge: true,
            balance_check: true,
            base_fee_check: true,
            activation_admin: None,
        }
    }

    pub const fn with_basefee(mut self, basefee: u64) -> Self {
        self.basefee = basefee;
        self
    }
}

/// `L1Block` predeploy storage with non-zero fee parameters for every upgrade.
pub fn l1_block_storage() -> Vec<(U256, U256)> {
    let mut scalars = [0u8; 32];
    scalars[16..20].copy_from_slice(&2_269u32.to_be_bytes());
    scalars[20..24].copy_from_slice(&1_055_762u32.to_be_bytes());
    let mut operator = [0u8; 32];
    operator[18..20].copy_from_slice(&400u16.to_be_bytes());
    operator[20..24].copy_from_slice(&2_000u32.to_be_bytes());
    operator[24..32].copy_from_slice(&7u64.to_be_bytes());
    vec![
        (L1BlockInfo::L1_BASE_FEE_SLOT, U256::from(3_000_000_000u64)),
        (L1BlockInfo::ECOTONE_L1_FEE_SCALARS_SLOT, U256::from_be_bytes(scalars)),
        (L1BlockInfo::L1_OVERHEAD_SLOT, U256::from(188)),
        (L1BlockInfo::L1_SCALAR_SLOT, U256::from(684_000)),
        (L1BlockInfo::ECOTONE_L1_BLOB_BASE_FEE_SLOT, U256::from(5)),
        (L1BlockInfo::OPERATOR_FEE_SCALARS_SLOT, U256::from_be_bytes(operator)),
    ]
}

/// The post-state of one account.
#[derive(Debug, PartialEq, Eq)]
pub struct AccountState {
    pub balance: U256,
    pub nonce: u64,
    pub code_hash: B256,
    pub storage: BTreeMap<U256, U256>,
    /// Every non-zero storage slot known to the engine's committed database.
    pub nonzero_storage: BTreeMap<U256, U256>,
}

/// The engine-independent outcome of one executed transaction.
#[derive(Debug, PartialEq, Eq)]
pub struct TxOutcome {
    pub success: bool,
    pub gas_used: u64,
    pub failed_deposit: bool,
    pub created: Option<Address>,
    pub output: Bytes,
    pub logs: Vec<Log>,
}

/// The engine-independent outcome of executing a sequence of transactions.
#[derive(Debug, PartialEq, Eq)]
pub enum Outcome {
    /// A transaction was rejected.
    Invalid,
    /// Every transaction executed.
    Executed { txs: Vec<TxOutcome>, accounts: BTreeMap<Address, AccountState> },
}

/// Accounts and slots whose post-state is compared.
pub type Compare = Vec<(Address, Vec<U256>)>;

fn norm_code_hash(hash: B256) -> B256 {
    if hash == B256::ZERO { keccak256([]) } else { hash }
}

/// Builds the evm2 engine.
pub fn evm2(env: Env, seeds: &[Seed]) -> BaseEvm<'static> {
    let mut db = Evm2Db::default();
    for seed in seeds {
        let mut info =
            evm2::AccountInfo { balance: seed.balance, nonce: seed.nonce, ..Default::default() };
        if !seed.code.is_empty() {
            info.code = Some(Evm2Bytecode::new_legacy(Bytes::from(seed.code.clone())));
        }
        db.insert_account_info(&seed.address, info);
        for (key, value) in &seed.storage {
            db.insert_account_storage(&seed.address, key, value);
        }
    }
    if !seeds.iter().any(|seed| seed.address == Predeploys::L1_BLOCK_INFO) {
        db.insert_account_info(&Predeploys::L1_BLOCK_INFO, evm2::AccountInfo::default());
    }
    for (key, value) in l1_block_storage() {
        db.insert_account_storage(&Predeploys::L1_BLOCK_INFO, &key, &value);
    }

    let spec = BaseSpecId::new(env.upgrade);
    let mut version = base_version(spec, CHAIN_ID);
    version.features.set(EvmFeatures::FEE_CHARGE, env.fee_charge);
    version.features.set(EvmFeatures::BALANCE_CHECK, env.balance_check);
    version.features.set(EvmFeatures::BASE_FEE_CHECK, env.base_fee_check);
    let block = BlockEnv::<base_evm2::BaseEvmTypes> {
        number: U256::from(BLOCK_NUMBER),
        beneficiary: COINBASE,
        basefee: U256::from(env.basefee),
        gas_limit: U256::from(30_000_000u64),
        ..Default::default()
    };
    BaseEvmFactory::new(env.activation_admin).create_evm(spec, version, block, db)
}

/// Executes `tx` on the revm reference, commits, and reads back `compare`.
pub fn run_revm(
    env: Env,
    seeds: &[Seed],
    tx: BaseTransaction<TxEnv>,
    compare: &Compare,
) -> Outcome {
    run_revm_seq(env, seeds, vec![tx], compare)
}

/// Executes `txs` in order on the revm reference, committing each, and reads back `compare`.
pub fn run_revm_seq(
    env: Env,
    seeds: &[Seed],
    txs: Vec<BaseTransaction<TxEnv>>,
    compare: &Compare,
) -> Outcome {
    let mut db = RevmDb::default();
    for seed in seeds {
        let mut info =
            RevmAccountInfo { balance: seed.balance, nonce: seed.nonce, ..Default::default() };
        if !seed.code.is_empty() {
            info.code = Some(RevmBytecode::new_legacy(Bytes::from(seed.code.clone())));
            info.code_hash = info.code.as_ref().unwrap().hash_slow();
        }
        db.insert_account_info(seed.address, info);
        for (key, value) in &seed.storage {
            db.insert_account_storage(seed.address, *key, *value).unwrap();
        }
    }
    if !seeds.iter().any(|seed| seed.address == Predeploys::L1_BLOCK_INFO) {
        db.insert_account_info(Predeploys::L1_BLOCK_INFO, RevmAccountInfo::default());
    }
    for (key, value) in l1_block_storage() {
        db.insert_account_storage(Predeploys::L1_BLOCK_INFO, key, value).unwrap();
    }

    let mut cfg = CfgEnv::new_with_spec(base_common_evm::BaseSpecId::new(env.upgrade));
    cfg.chain_id = CHAIN_ID;
    cfg.disable_fee_charge = !env.fee_charge;
    cfg.disable_balance_check = !env.balance_check;
    cfg.disable_base_fee = !env.base_fee_check;
    let block = RevmBlockEnv {
        number: U256::from(BLOCK_NUMBER),
        beneficiary: COINBASE,
        basefee: env.basefee,
        gas_limit: 30_000_000,
        ..Default::default()
    };
    let mut evm = Context::base()
        .with_db(db)
        .with_block(block)
        .with_cfg(cfg)
        .build_base_with_activation_admin_address(env.activation_admin)
        .with_inspector(NoOpInspector {});

    let mut outcomes = Vec::new();
    for tx in txs {
        // The EIP-8130 executor lives at Alloy's transaction boundary, outside REVM's
        // single-frame ExecuteEvm handler, which deliberately rejects AA envelopes.
        let Ok(result) = evm.transact_raw(tx) else { return Outcome::Invalid };
        evm.commit(result.state);
        let result = result.result;
        let (created, output) = match &result {
            ExecutionResult::Success { output: Output::Create(bytes, address), .. } => {
                (*address, bytes.clone())
            }
            ExecutionResult::Success { output: Output::Call(bytes), .. } => (None, bytes.clone()),
            ExecutionResult::Revert { output, .. } => (None, output.clone()),
            ExecutionResult::Halt { .. } => (None, Bytes::new()),
        };
        outcomes.push(TxOutcome {
            success: result.is_success(),
            gas_used: result.tx_gas_used(),
            failed_deposit: matches!(
                result,
                ExecutionResult::Halt { reason: BaseHaltReason::FailedDeposit, .. }
            ),
            created,
            output,
            logs: result.logs().to_vec(),
        });
    }
    let db = evm.ctx_mut().db_mut();
    let mut accounts = BTreeMap::new();
    for (address, slots) in compare {
        let nonzero_storage = db
            .cache
            .accounts
            .get(address)
            .map(|account| {
                account
                    .storage
                    .iter()
                    .filter(|(_, value)| !value.is_zero())
                    .map(|(slot, value)| (*slot, *value))
                    .collect()
            })
            .unwrap_or_default();
        let info = db.basic(*address).unwrap().unwrap_or_default();
        let storage =
            slots.iter().map(|slot| (*slot, db.storage(*address, *slot).unwrap())).collect();
        accounts.insert(
            *address,
            AccountState {
                balance: info.balance,
                nonce: info.nonce,
                code_hash: norm_code_hash(info.code_hash),
                storage,
                nonzero_storage,
            },
        );
    }
    Outcome::Executed { txs: outcomes, accounts }
}

/// Every non-zero committed storage slot of `address` in evm2: the seeded database overlaid with
/// the committed transaction state.
fn evm2_nonzero_storage(evm: &BaseEvm<'static>, address: &Address) -> BTreeMap<U256, U256> {
    let overlay = evm.overlay_db().cache.storage.get(address);
    let mut storage = BTreeMap::new();
    if !overlay.is_some_and(|overlay| overlay.wiped)
        && let Some(seeded) =
            evm.database_as::<Evm2Db>().and_then(|db| db.cache.storage.get(address))
    {
        storage.extend(seeded.slots.iter().map(|(slot, value)| (*slot, *value)));
    }
    if let Some(overlay) = overlay {
        storage.extend(overlay.slots.iter().map(|(slot, value)| (*slot, *value)));
    }
    storage.retain(|_, value| !value.is_zero());
    storage
}

/// Executes `tx` on evm2, commits, and reads back `compare`.
pub fn run_evm2(
    env: Env,
    seeds: &[Seed],
    tx: BaseTxEnvelope,
    signer: Address,
    compare: &Compare,
) -> Outcome {
    run_evm2_seq(env, seeds, vec![(tx, signer)], compare)
}

/// Executes `txs` in order on evm2, committing each, and reads back `compare`.
pub fn run_evm2_seq(
    env: Env,
    seeds: &[Seed],
    txs: Vec<(BaseTxEnvelope, Address)>,
    compare: &Compare,
) -> Outcome {
    let mut evm = evm2(env, seeds);
    let mut outcomes = Vec::new();
    for (tx, signer) in txs {
        let result: Result<TxResult<base_evm2::BaseEvmTypes>, HandlerError> =
            evm.transact(&tx.with_signer(signer)).map(|executed| executed.commit());
        let Ok(result) = result else { return Outcome::Invalid };
        outcomes.push(TxOutcome {
            success: result.status,
            gas_used: result.tx_gas_used(),
            failed_deposit: result.ext.failed_deposit,
            created: result.created_address,
            output: result.output.clone(),
            logs: result.logs,
        });
    }
    let dumps: Vec<_> =
        compare.iter().map(|(address, _)| evm2_nonzero_storage(&evm, address)).collect();
    let state = evm.state_mut();
    let mut accounts = BTreeMap::new();
    for ((address, slots), nonzero_storage) in compare.iter().zip(dumps) {
        let info = state.account_info_untracked(address).unwrap().unwrap_or_default();
        let storage = slots
            .iter()
            .map(|slot| (*slot, state.storage_slot_untracked(address, slot).unwrap()))
            .collect();
        accounts.insert(
            *address,
            AccountState {
                balance: info.balance,
                nonce: info.nonce,
                code_hash: norm_code_hash(info.code_hash),
                storage,
                nonzero_storage,
            },
        );
    }
    Outcome::Executed { txs: outcomes, accounts }
}
