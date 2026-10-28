//! Tendermint secp256k1 signature recovery precompile (`0x69`).
//!
//! Port of bsc's `secp256k1SignatureRecover` (`core/vm/contracts_lightclient.go`). Test vectors
//! come from reth-bsc (MIT).

use alloy_primitives::Bytes;
use evm2::{
    evm::precompile::PrecompileOutput,
    interpreter::GasTracker,
    precompiles::{PrecompileHalt, PrecompileResult, crypto},
};
use k256::ecdsa::{Signature, VerifyingKey, signature::hazmat::PrehashVerifier};

/// Gas of the Tendermint secp256k1 signature recovery precompile.
pub const TM_SECP256K1_SIGNATURE_RECOVER_GAS: u64 = 3_000;

const PUBKEY_LENGTH: usize = 33;
const SIGNATURE_LENGTH: usize = 64;
const MSG_HASH_LENGTH: usize = 32;

/// Verifies a secp256k1 signature and returns the signer's Tendermint address.
///
/// Input: `compressed pubkey (33) | r | s (64) | msg hash (32)`. Returns
/// `RIPEMD160(SHA256(pubkey))` (20 bytes). Halts on malformed input or an invalid signature,
/// including high-S signatures.
pub fn run(input: &[u8], gas: &mut GasTracker) -> PrecompileResult {
    gas.spend(TM_SECP256K1_SIGNATURE_RECOVER_GAS)?;
    if input.len() != PUBKEY_LENGTH + SIGNATURE_LENGTH + MSG_HASH_LENGTH {
        return Err(PrecompileHalt::Other("invalid input".into()).into());
    }
    let (pubkey, rest) = input.split_at(PUBKEY_LENGTH);
    let (signature, msg_hash) = rest.split_at(SIGNATURE_LENGTH);
    if !verify(pubkey, signature, msg_hash) {
        return Err(PrecompileHalt::Other("invalid signature".into()).into());
    }
    let address = crypto().ripemd160(&crypto().sha256(pubkey));
    Ok(PrecompileOutput::new(Bytes::copy_from_slice(&address[12..])))
}

/// Tendermint's `VerifyBytesWithMsgHash`: a compressed public key and a lower-S signature.
/// k256 rejects high-S signatures on secp256k1.
fn verify(pubkey: &[u8], signature: &[u8], msg_hash: &[u8]) -> bool {
    if !matches!(pubkey[0], 0x02 | 0x03) {
        return false;
    }
    let (Ok(pubkey), Ok(signature)) =
        (VerifyingKey::from_sec1_bytes(pubkey), Signature::from_slice(signature))
    else {
        return false;
    };
    pubkey.verify_prehash(msg_hash, &signature).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::hex;
    use evm2::precompiles::PrecompileError;

    fn input(pubkey: &[u8], signature: &[u8], msg_hash: &[u8]) -> Vec<u8> {
        [pubkey, signature, msg_hash].concat()
    }

    /// Returns the output, or the halt reason.
    fn exec(input: &[u8]) -> Result<Bytes, String> {
        let mut gas = GasTracker::new(TM_SECP256K1_SIGNATURE_RECOVER_GAS);
        let outcome = match run(input, &mut gas) {
            Ok(output) => Ok(output.into_bytes()),
            Err(PrecompileError::Halt(PrecompileHalt::Other(reason))) => Err(reason.into_owned()),
            Err(err) => panic!("unexpected error: {err:?}"),
        };
        assert_eq!(gas.remaining(), 0);
        outcome
    }

    const PUBKEY: [u8; 33] =
        hex!("0278caa4d6321aa856d6341dd3e8bcdfe0b55901548871c63c3f5cec43c2ae88a9");
    const SIGNATURE: [u8; 64] = hex!(
        "0cb78be0d8eaeab991907b06c61240c04f4ca83f54b7799ce77cf029b837988038c4b3b7f5df231695b0d14499b716e1fd6504860eb3c9244ecb4e569d44c062"
    );
    const MSG_HASH: [u8; 32] =
        hex!("b6ac827edff4bbbf23579720782dbef40b65780af292cc66849e7e5944f1230f");

    #[test]
    fn recovers_tendermint_address() {
        assert_eq!(
            exec(&input(&PUBKEY, &SIGNATURE, &MSG_HASH)),
            Ok(hex!("fa3B227adFf8EA1706098928715076D76959Ae6c").into())
        );
        // Ledger key.
        let input = input(
            &hex!("02d63ee39adb1779353b4393dd5ea9d6d2b6df63b71d168571803cc7b9a0a20e98"),
            &hex!(
                "66bdb5d381b2773c0f569858c7ee143959522d7c1f46dc656c325cb7353ec40c28ec22dff3650b34c096c5b12e702d7237d409f1ebaaa6dd1128a8f2d401fd5b"
            ),
            &hex!("c45e8f0dc7c054c31912beeffd6f10f1c585606d61e252e97968cd66661c2571"),
        );
        assert_eq!(exec(&input), Ok(hex!("65a284146b84210a01add088954bb52d88b230af").into()));
    }

    #[test]
    fn rejects_invalid_input() {
        let invalid = |reason: &str| Err(reason.to_owned());
        assert_eq!(exec(&[]), invalid("invalid input"));
        assert_eq!(exec(&input(&PUBKEY, &SIGNATURE, &MSG_HASH[1..])), invalid("invalid input"));

        let mut wrong_msg = MSG_HASH;
        wrong_msg[0] ^= 1;
        assert_eq!(exec(&input(&PUBKEY, &SIGNATURE, &wrong_msg)), invalid("invalid signature"));

        // The same signature with `s` replaced by `n - s` is valid ECDSA but high-S.
        let signature = Signature::from_slice(&SIGNATURE).unwrap();
        let (r, s) = signature.split_scalars();
        let high_s = Signature::from_scalars(r, -*s).unwrap();
        assert_ne!(high_s.normalize_s(), high_s);
        let high_s = high_s.to_bytes();
        assert_eq!(exec(&input(&PUBKEY, &high_s, &MSG_HASH)), invalid("invalid signature"));

        // Uncompressed-prefix and malformed keys.
        let mut bad_key = PUBKEY;
        bad_key[0] = 0x04;
        assert_eq!(exec(&input(&bad_key, &SIGNATURE, &MSG_HASH)), invalid("invalid signature"));
        bad_key[0] = 0x05;
        assert_eq!(exec(&input(&bad_key, &SIGNATURE, &MSG_HASH)), invalid("invalid signature"));
    }
}
