//! BLS signature verification precompile (`0x66`).
//!
//! Port of bsc's `blsSignatureVerify` (`core/vm/contracts.go`), which uses Prysm's blst
//! bindings. Test vectors come from reth-bsc (MIT).

use alloy_primitives::Bytes;
use blst::{
    BLST_ERROR,
    min_pk::{PublicKey, Signature},
};
use evm2::{
    evm::precompile::PrecompileOutput,
    interpreter::GasTracker,
    precompiles::{PrecompileError, PrecompileResult},
};

/// Base gas of the BLS signature verification precompile.
pub const BLS_SIGNATURE_VERIFY_BASE_GAS: u64 = 1_000;

/// Gas per public key of the BLS signature verification precompile.
pub const BLS_SIGNATURE_VERIFY_PER_KEY_GAS: u64 = 3_500;

const MSG_HASH_LENGTH: usize = 32;
const SIGNATURE_LENGTH: usize = 96;
const PUBKEY_LENGTH: usize = 48;

/// Ethereum consensus proof-of-possession ciphersuite, used by Prysm.
const DST: &[u8] = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";

/// Verifies a BLS signature over a 32-byte message against one or more public keys.
///
/// Input: `msg (32) | signature (96) | pubkey (48) * n`. Returns `[0x01]` if the signature is
/// valid (aggregate over all keys when `n > 1`), empty bytes if it is not, and reverts on
/// malformed input, signatures or keys. Malformed lengths are charged the base gas only.
pub fn run(input: &[u8], gas: &mut GasTracker) -> PrecompileResult {
    let Some(keys) = input.len().checked_sub(MSG_HASH_LENGTH + SIGNATURE_LENGTH) else {
        gas.spend(BLS_SIGNATURE_VERIFY_BASE_GAS)?;
        return revert();
    };
    if keys == 0 || !keys.is_multiple_of(PUBKEY_LENGTH) {
        gas.spend(BLS_SIGNATURE_VERIFY_BASE_GAS)?;
        return revert();
    }
    let keys = keys / PUBKEY_LENGTH;
    gas.spend(BLS_SIGNATURE_VERIFY_BASE_GAS + keys as u64 * BLS_SIGNATURE_VERIFY_PER_KEY_GAS)?;

    let (msg, rest) = input.split_at(MSG_HASH_LENGTH);
    let (signature, pubkeys) = rest.split_at(SIGNATURE_LENGTH);
    // Prysm group-checks the signature but accepts the point at infinity, which an aggregate
    // signature can be.
    let Ok(signature) = Signature::uncompress(signature) else { return revert() };
    if signature.validate(false).is_err() {
        return revert();
    }
    let mut pubkeys_parsed = Vec::with_capacity(keys);
    for pubkey in pubkeys.as_chunks::<PUBKEY_LENGTH>().0 {
        // `validate` rejects the point at infinity and points outside the subgroup.
        let Ok(pubkey) = PublicKey::uncompress(pubkey) else { return revert() };
        if pubkey.validate().is_err() {
            return revert();
        }
        pubkeys_parsed.push(pubkey);
    }

    let valid = if let [pubkey] = pubkeys_parsed.as_slice() {
        signature.verify(false, msg, DST, &[], pubkey, false)
    } else {
        let pubkeys = pubkeys_parsed.iter().collect::<Vec<_>>();
        signature.fast_aggregate_verify(true, msg, DST, &pubkeys)
    } == BLST_ERROR::BLST_SUCCESS;
    let output = if valid { Bytes::from_static(&[1]) } else { Bytes::new() };
    Ok(PrecompileOutput::new(output))
}

fn revert() -> PrecompileResult {
    Err(PrecompileError::Revert(Bytes::new()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::hex;

    const MSG: [u8; 32] = hex!("6377c7e66081cb65e473c1b95db5195a27d04a7108b468890224bedbe1a8a6eb");
    const SIG_SINGLE: [u8; 96] = hex!(
        "8325fccd4ff01e6e0e73de4955d3cb2c6678c6a6abfc465c2991e375c5cf68841ac7847ac51c32a26bd99828bc99f2f6082c41986097e0f6e6711e57c5bd5b18fa6f8f44bf416617cf192a2ff6d4edf0890315d87e3c04f04f0d1611b64bbe0a"
    );
    const KEY_SINGLE: [u8; 48] = hex!(
        "a842801f14464ce36470737dc159cb13191e3ad8a49f4f3a38e6a94ea5594ff65753f74661fb7ec944b98fc673bb8230"
    );
    const SIG_AGGREGATE: [u8; 96] = hex!(
        "876ac46847e82a2f2887bbeb855916e05bd259086fda5553e4e5e5ee0dcda6869c10e2aa539e265b492015d1bd1b553815a42ea9daf6713b6a0002c6f1aacfa51e55b931745638c0552d7fab4a499bbd6ba71f9be36d35ffa527f77b2a6cebda"
    );
    const KEYS_AGGREGATE: [[u8; 48]; 3] = [
        hex!(
            "80223255a26d81a8e1cd94df746f45e87a91d28f408a037804062910b7db68a724cfd204b7f9337bcecac25de86d5515"
        ),
        hex!(
            "8bec004e938668c67aa0fab6f555282efdf213817e455d9eaa6a0897211eae5f79db5cdc626d1cd5759a0c1c10cf7aa0"
        ),
        hex!(
            "af952757f442d7240a4cec62de638973a24fde8eb0ad5217be61eea53211c19859c03a299125ea8520f015f6f8865076"
        ),
    ];

    fn input(msg: &[u8], sig: &[u8], keys: &[[u8; 48]]) -> Vec<u8> {
        [msg, sig].concat().into_iter().chain(keys.iter().flatten().copied()).collect()
    }

    /// Runs with ample gas and returns the gas spent and the outcome: `Some(output)` on success,
    /// `None` on revert.
    fn exec(input: &[u8]) -> (u64, Option<Bytes>) {
        let mut gas = GasTracker::new(1_000_000);
        let outcome = match run(input, &mut gas) {
            Ok(output) => Some(output.into_bytes()),
            Err(PrecompileError::Revert(output)) => {
                assert!(output.is_empty());
                None
            }
            Err(err) => panic!("unexpected error: {err:?}"),
        };
        (gas.spent(), outcome)
    }

    fn flip_first_byte<const N: usize>(mut bytes: [u8; N]) -> [u8; N] {
        bytes[0] ^= 0x90;
        bytes
    }

    #[test]
    fn single_key() {
        let valid = Some(Bytes::from_static(&[1]));
        assert_eq!(exec(&input(&MSG, &SIG_SINGLE, &[KEY_SINGLE])), (4_500, valid));
        let wrong_msg = flip_first_byte(MSG);
        assert_eq!(
            exec(&input(&wrong_msg, &SIG_SINGLE, &[KEY_SINGLE])),
            (4_500, Some(Bytes::new()))
        );
        // Malformed signature and key encodings revert.
        let bad_sig = flip_first_byte(SIG_SINGLE);
        assert_eq!(exec(&input(&MSG, &bad_sig, &[KEY_SINGLE])), (4_500, None));
        let bad_key = flip_first_byte(KEY_SINGLE);
        assert_eq!(exec(&input(&MSG, &SIG_SINGLE, &[bad_key])), (4_500, None));
    }

    #[test]
    fn aggregate_keys() {
        let valid = Some(Bytes::from_static(&[1]));
        assert_eq!(exec(&input(&MSG, &SIG_AGGREGATE, &KEYS_AGGREGATE)), (11_500, valid));
        let wrong_msg = flip_first_byte(MSG);
        assert_eq!(
            exec(&input(&wrong_msg, &SIG_AGGREGATE, &KEYS_AGGREGATE)),
            (11_500, Some(Bytes::new()))
        );
        // A key set that does not match the aggregate is invalid, not malformed.
        let [_, second, third] = KEYS_AGGREGATE;
        assert_eq!(
            exec(&input(&MSG, &SIG_AGGREGATE, &[second, second, third])),
            (11_500, Some(Bytes::new()))
        );
        // The point at infinity is not a valid public key.
        let mut infinity = [0; 48];
        infinity[0] = 0xc0;
        assert_eq!(exec(&input(&MSG, &SIG_AGGREGATE, &[infinity, second, third])), (11_500, None));
    }

    #[test]
    fn malformed_lengths_charge_base_gas() {
        assert_eq!(exec(&[]), (1_000, None));
        assert_eq!(exec(&input(&MSG, &SIG_SINGLE, &[])), (1_000, None));
        let mut short_key = input(&MSG, &SIG_SINGLE, &[KEY_SINGLE]);
        short_key.pop();
        assert_eq!(exec(&short_key), (1_000, None));
    }

    #[test]
    fn charges_before_verifying() {
        let mut gas = GasTracker::new(4_499);
        assert!(matches!(
            run(&input(&MSG, &SIG_SINGLE, &[KEY_SINGLE]), &mut gas),
            Err(PrecompileError::Halt(_))
        ));
    }
}
