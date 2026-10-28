//! Native AA execution parity against Base's pinned reference executor.

mod common;

use alloy_eips::eip2718::Encodable2718;
use alloy_primitives::{Address, B256, Bytes, U256, keccak256};
use base_common_consensus::{Call, Eip8130Constants, Eip8130Signed, Predeploys, TxEip8130};
use base_common_evm::{BaseTransaction, Eip8130ExecutionMode, Eip8130TransactionParts};
use base_common_genesis::BaseUpgrade;
use base_evm2::{BaseTxEnvelope, precompiles::NONCE_MANAGER_ADDRESS};
use common::{CHAIN_ID, COINBASE, Compare, Env, Outcome, Seed, run_evm2_seq, run_revm_seq};
use k256::ecdsa::SigningKey;
use revm::context::TxEnv;

const TARGET: Address = Address::repeat_byte(0x32);
const REVERTER: Address = Address::repeat_byte(0x43);
const FUNDS: u128 = 10_000_000_000_000_000_000;

fn key(byte: u8) -> SigningKey {
    SigningKey::from_slice(&[byte; 32]).unwrap()
}

fn address(key: &SigningKey) -> Address {
    let point = key.verifying_key().to_sec1_point(false);
    Address::from_slice(&keccak256(&point.as_bytes()[1..])[12..])
}

fn signature(key: &SigningKey, hash: B256) -> Bytes {
    let (signature, recovery) = key.sign_prehash_recoverable(hash.as_slice());
    let mut bytes = signature.to_bytes().to_vec();
    bytes.push(recovery.to_byte() + 27);
    bytes.into()
}

fn transaction() -> TxEip8130 {
    TxEip8130 {
        chain_id: CHAIN_ID,
        gas_limit: 500_000,
        max_fee_per_gas: 1_000,
        max_priority_fee_per_gas: 17,
        calls: vec![vec![Call { to: TARGET, data: Bytes::new() }]],
        ..Default::default()
    }
}

fn signed(tx: TxEip8130, sender: &SigningKey) -> Eip8130Signed {
    let auth = signature(sender, tx.sender_signature_hash());
    Eip8130Signed::new(tx, auth, Bytes::new())
}

fn compare(sender: Address, payer: Address) -> Compare {
    vec![
        (sender, vec![]),
        (payer, vec![]),
        (TARGET, vec![U256::ZERO]),
        (REVERTER, vec![]),
        (NONCE_MANAGER_ADDRESS, vec![]),
        (COINBASE, vec![]),
        (Predeploys::L1_FEE_VAULT, vec![]),
        (Predeploys::BASE_FEE_VAULT, vec![]),
        (Predeploys::OPERATOR_FEE_VAULT, vec![]),
    ]
}

fn seeds(sender: Address, payer: Address, code: Vec<u8>) -> Vec<Seed> {
    let mut seeds = vec![
        Seed::eoa(sender, U256::from(FUNDS)),
        Seed::contract(TARGET, code),
        Seed::contract(REVERTER, vec![0x5f, 0x5f, 0xfd]),
    ];
    if payer != sender {
        seeds.push(Seed::eoa(payer, U256::from(FUNDS)));
    }
    seeds
}

fn reference(signed: Eip8130Signed, sender: Address, simulated: bool) -> BaseTransaction<TxEnv> {
    let encoded = Bytes::from(signed.encoded_2718());
    let base = TxEnv::builder().caller(sender).gas_limit(signed.tx().gas_limit).build_fill();
    let mut parts = Eip8130TransactionParts::new(signed);
    if simulated {
        parts.mode = Eip8130ExecutionMode::Simulate;
    }
    BaseTransaction {
        base,
        enveloped_tx: Some(encoded),
        eip8130: Some(parts),
        ..Default::default()
    }
}

fn parity(
    signed: Vec<Eip8130Signed>,
    sender: Address,
    payer: Address,
    seeds: &[Seed],
    simulated: bool,
) -> Outcome {
    let env = Env::new(BaseUpgrade::Zenith).with_basefee(100);
    let native = signed
        .iter()
        .cloned()
        .map(|signed| {
            let mut envelope = BaseTxEnvelope::from(signed);
            if simulated {
                envelope.set_eip8130_simulation(None);
            }
            (envelope, sender)
        })
        .collect();
    let reference = signed.into_iter().map(|signed| reference(signed, sender, simulated)).collect();
    let native = run_evm2_seq(env, seeds, native, &compare(sender, payer));
    let reference = run_revm_seq(env, seeds, reference, &compare(sender, payer));
    assert_eq!(native, reference, "AA gas, logs, fees, nonce, code, or storage diverged");
    native
}

#[test]
fn protocol_and_channel_nonce_fee_refund_parity() {
    let key = key(1);
    let sender = address(&key);
    for nonce_key in [U256::ZERO, U256::from(7)] {
        // Alternating zero/nonzero storage writes exercise refunds across distinct protocol
        // calls. The nonce channel's first-use cost must disappear on the second transaction.
        // ADDRESS BALANCE also checks that dispatch warmed the target before executing it.
        let code = vec![0x30, 0x31, 0x50, 0x5f, 0x35, 0x5f, 0x55, 0x00];
        let txs = (0..2)
            .map(|nonce_sequence| {
                let mut tx = transaction();
                tx.nonce_key = nonce_key;
                tx.nonce_sequence = nonce_sequence;
                tx.calls = vec![vec![
                    Call { to: TARGET, data: U256::ONE.to_be_bytes::<32>().to_vec().into() },
                    Call { to: TARGET, data: Bytes::new() },
                ]];
                signed(tx, &key)
            })
            .collect();
        let outcome = parity(txs, sender, sender, &seeds(sender, sender, code), false);
        let Outcome::Executed { txs, accounts } = outcome else { panic!("valid AA rejected") };
        assert!(txs.iter().all(|tx| tx.success));
        assert_eq!(accounts[&sender].nonce, if nonce_key.is_zero() { 2 } else { 0 });
        assert_eq!(accounts[&TARGET].storage[&U256::ZERO], U256::ZERO);
        assert!(accounts[&sender].balance < U256::from(FUNDS));
    }
}

#[test]
fn failed_phase_rolls_back_its_calls_but_keeps_prior_phase_and_nonce() {
    let key = key(2);
    let sender = address(&key);
    let mut tx = transaction();
    let store =
        |value| Call { to: TARGET, data: U256::from(value).to_be_bytes::<32>().to_vec().into() };
    tx.calls = vec![
        vec![store(3)],
        vec![store(9), Call { to: REVERTER, data: Bytes::new() }],
        vec![store(17)],
    ];
    let signed = signed(tx, &key);
    let seeds = seeds(sender, sender, vec![0x5f, 0x35, 0x5f, 0x55, 0x00]);
    let outcome = parity(vec![signed.clone()], sender, sender, &seeds, false);
    let Outcome::Executed { txs, accounts } = outcome else { panic!("included AA rejected") };
    assert!(!txs[0].success);
    assert_eq!(accounts[&TARGET].storage[&U256::ZERO], U256::from(3));
    assert_eq!(accounts[&sender].nonce, 1);
    let mut evm = common::evm2(Env::new(BaseUpgrade::Zenith).with_basefee(100), &seeds);
    let result = evm.transact(&BaseTxEnvelope::from(signed).with_signer(sender)).unwrap().commit();
    assert_eq!(result.ext.eip8130_phase_statuses, Some(vec![1, 0, 0]));
}

#[test]
fn simulation_preserves_state_even_when_committed_and_prices_failure_gross_gas() {
    let key = key(3);
    let sender = address(&key);
    for target in [TARGET, REVERTER] {
        let mut tx = transaction();
        tx.nonce_sequence = 73; // The simulation must not validate or increment this nonce.
        tx.calls[0][0].to = target;
        let signed = Eip8130Signed::new(tx, Bytes::from(vec![0; 65]), Bytes::new());
        let outcome = parity(
            vec![signed],
            sender,
            sender,
            &seeds(sender, sender, vec![0x60, 0x07, 0x5f, 0x55, 0x00]),
            true,
        );
        let Outcome::Executed { txs, accounts } = outcome else { panic!("simulation rejected") };
        assert_eq!(txs[0].success, target == TARGET);
        assert_eq!(accounts[&sender].nonce, 0);
        assert_eq!(accounts[&sender].balance, U256::from(FUNDS));
        assert_eq!(accounts[&TARGET].storage[&U256::ZERO], U256::ZERO);
    }
}

#[test]
fn wrong_authentication_chain_id_and_nonce_are_rejected() {
    let key = key(4);
    let sender = address(&key);
    for invalid in 0..3 {
        let mut tx = transaction();
        if invalid == 1 {
            tx.chain_id += 1;
        }
        if invalid == 2 {
            tx.nonce_sequence = 1;
        }
        let signed = if invalid == 0 {
            Eip8130Signed::new(tx, Bytes::from(vec![0; 65]), Bytes::new())
        } else {
            signed(tx, &key)
        };
        assert_eq!(
            parity(vec![signed], sender, sender, &seeds(sender, sender, vec![0x00]), false),
            Outcome::Invalid
        );
    }
}

#[test]
fn sponsor_pays_authentication_and_execution_without_debiting_sender() {
    let sender_key = key(5);
    let payer_key = key(6);
    let sender = address(&sender_key);
    let payer = address(&payer_key);
    let mut tx = transaction();
    tx.payer = Some(payer);
    let sender_auth = signature(&sender_key, tx.sender_signature_hash());
    let mut payer_auth = Eip8130Constants::K1_AUTHENTICATOR.to_vec();
    payer_auth.extend_from_slice(&signature(&payer_key, tx.payer_signature_hash(sender)));
    let signed = Eip8130Signed::new(tx, sender_auth, payer_auth.into());
    let outcome = parity(vec![signed], sender, payer, &seeds(sender, payer, vec![0x00]), false);
    let Outcome::Executed { txs, accounts } = outcome else { panic!("sponsored AA rejected") };
    assert!(txs[0].success);
    assert_eq!(accounts[&sender].balance, U256::from(FUNDS));
    assert!(accounts[&payer].balance < U256::from(FUNDS));
    assert_eq!(accounts[&sender].nonce, 1);
    assert_eq!(accounts[&payer].nonce, 0);
}
