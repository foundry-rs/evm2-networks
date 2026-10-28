//! Double-sign evidence verification precompile (`0x68`).
//!
//! Port of bsc's `verifyDoubleSignEvidence` (`core/vm/contracts.go`). The RLP data model follows
//! reth-bsc (MIT), which matches bsc byte for byte:
//!
//! - `*big.Int` fields (chain ID, difficulty, number) accept any canonical big-endian integer
//!   (`RlpBigInt`).
//! - Headers carry bsc's `rlp:"optional"` tail, part of which is folded into the seal hash.
//! - Every decode rejects trailing bytes, like Go's `rlp.DecodeBytes`.

use alloc::vec::Vec;
use alloy_primitives::{B256, Bytes, keccak256};
use alloy_rlp::{
    Decodable, EMPTY_STRING_CODE, Encodable, Error as RlpError, Header as RlpHeader, RlpDecodable,
};
use evm2::{
    evm::precompile::PrecompileOutput,
    interpreter::GasTracker,
    precompiles::{PrecompileError, PrecompileHalt, PrecompileResult, crypto},
};

/// Gas of the double-sign evidence verification precompile.
pub const DOUBLE_SIGN_EVIDENCE_VERIFY_GAS: u64 = 10_000;

/// Length of the seal (signature) at the end of a header's extra data.
const EXTRA_SEAL_LENGTH: usize = 65;

/// Widest block number bsc accepts (`len(header.Number.Bytes()) > 32`).
const MAX_BLOCK_NUMBER_BYTES: usize = 32;

/// An RLP integer with Go `*big.Int` semantics, kept as its canonical big-endian bytes (empty for
/// zero). The precompile only compares, measures and re-encodes these values.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct RlpBigInt(Bytes);

impl Decodable for RlpBigInt {
    fn decode(buf: &mut &[u8]) -> alloy_rlp::Result<Self> {
        let payload = RlpHeader::decode_bytes(buf, false)?;
        // Go rejects leading zeros (`ErrCanonInt`). Non-canonical single bytes are already
        // rejected by `decode_bytes`.
        if payload.first() == Some(&0) {
            return Err(RlpError::LeadingZero);
        }
        Ok(Self(Bytes::copy_from_slice(payload)))
    }
}

impl Encodable for RlpBigInt {
    fn encode(&self, out: &mut dyn alloy_rlp::BufMut) {
        self.0.as_ref().encode(out);
    }

    fn length(&self) -> usize {
        self.0.as_ref().length()
    }
}

/// RLP-encoded double-sign evidence.
#[derive(Debug, RlpDecodable)]
#[cfg_attr(test, derive(alloy_rlp::RlpEncodable))]
struct DoubleSignEvidence {
    chain_id: RlpBigInt,
    header_bytes1: Bytes,
    header_bytes2: Bytes,
}

/// bsc's `types.Header`. The trailing optional fields are positional: a present field implies
/// that every field before it is present.
#[derive(Clone, Debug, PartialEq)]
struct Header {
    parent_hash: [u8; 32],
    uncle_hash: [u8; 32],
    coinbase: [u8; 20],
    root: [u8; 32],
    tx_hash: [u8; 32],
    receipt_hash: [u8; 32],
    bloom: [u8; 256],
    difficulty: RlpBigInt,
    number: RlpBigInt,
    gas_limit: u64,
    gas_used: u64,
    time: u64,
    extra: Bytes,
    mix_digest: [u8; 32],
    nonce: [u8; 8],
    base_fee: Option<RlpBigInt>,
    withdrawals_hash: Option<[u8; 32]>,
    blob_gas_used: Option<u64>,
    excess_blob_gas: Option<u64>,
    parent_beacon_root: Option<[u8; 32]>,
    requests_hash: Option<[u8; 32]>,
    block_access_list_hash: Option<[u8; 32]>,
    slot_number: Option<u64>,
}

/// Decodes the next optional field if any payload remains.
fn decode_optional<T: Decodable>(body: &mut &[u8]) -> alloy_rlp::Result<Option<T>> {
    if body.is_empty() { Ok(None) } else { T::decode(body).map(Some) }
}

impl Decodable for Header {
    fn decode(buf: &mut &[u8]) -> alloy_rlp::Result<Self> {
        let body = &mut RlpHeader::decode_bytes(buf, true)?;
        let header = Self {
            parent_hash: Decodable::decode(body)?,
            uncle_hash: Decodable::decode(body)?,
            coinbase: Decodable::decode(body)?,
            root: Decodable::decode(body)?,
            tx_hash: Decodable::decode(body)?,
            receipt_hash: Decodable::decode(body)?,
            bloom: Decodable::decode(body)?,
            difficulty: Decodable::decode(body)?,
            number: Decodable::decode(body)?,
            gas_limit: Decodable::decode(body)?,
            gas_used: Decodable::decode(body)?,
            time: Decodable::decode(body)?,
            extra: Decodable::decode(body)?,
            mix_digest: Decodable::decode(body)?,
            nonce: Decodable::decode(body)?,
            base_fee: decode_optional(body)?,
            withdrawals_hash: decode_optional(body)?,
            blob_gas_used: decode_optional(body)?,
            excess_blob_gas: decode_optional(body)?,
            parent_beacon_root: decode_optional(body)?,
            requests_hash: decode_optional(body)?,
            block_access_list_hash: decode_optional(body)?,
            slot_number: decode_optional(body)?,
        };
        // Go reports "too many elements".
        if !body.is_empty() {
            return Err(RlpError::UnexpectedLength);
        }
        Ok(header)
    }
}

/// Verifies that two headers at the same height were sealed by the same signer.
///
/// Input: RLP `[chain_id, header1, header2]`. Returns `signer (20) | number (32)`. Malformed RLP
/// and unrecoverable signatures revert; evidence that is well formed but invalid halts.
pub fn run(input: &[u8], gas: &mut GasTracker) -> PrecompileResult {
    gas.spend(DOUBLE_SIGN_EVIDENCE_VERIFY_GAS)?;

    let Ok(evidence) = alloy_rlp::decode_exact::<DoubleSignEvidence>(input) else {
        return revert();
    };
    let Ok(header1) = alloy_rlp::decode_exact::<Header>(&evidence.header_bytes1) else {
        return revert();
    };
    let Ok(header2) = alloy_rlp::decode_exact::<Header>(&evidence.header_bytes2) else {
        return revert();
    };

    if header1.number.0.len() > MAX_BLOCK_NUMBER_BYTES
        || header2.number.0.len() > MAX_BLOCK_NUMBER_BYTES
        // Canonical encodings are equal exactly when the integers are.
        || header1.number != header2.number
        || header1.parent_hash != header2.parent_hash
        || header1.extra.len() < EXTRA_SEAL_LENGTH
        || header2.extra.len() < EXTRA_SEAL_LENGTH
    {
        return invalid_evidence();
    }
    let seal1 = &header1.extra[header1.extra.len() - EXTRA_SEAL_LENGTH..];
    let seal2 = &header2.extra[header2.extra.len() - EXTRA_SEAL_LENGTH..];
    if seal1 == seal2 {
        return invalid_evidence();
    }
    let hash1 = seal_hash(&header1, &evidence.chain_id);
    let hash2 = seal_hash(&header2, &evidence.chain_id);
    if hash1 == hash2 {
        return invalid_evidence();
    }
    let Some(signer1) = recover(seal1, &hash1) else { return revert() };
    let Some(signer2) = recover(seal2, &hash2) else { return revert() };
    if signer1 != signer2 {
        return invalid_evidence();
    }

    let mut output = [0; 52];
    output[..20].copy_from_slice(&signer1[12..]);
    let number = &header1.number.0;
    output[52 - number.len()..].copy_from_slice(number);
    Ok(PrecompileOutput::new(Bytes::copy_from_slice(&output)))
}

fn revert() -> PrecompileResult {
    Err(PrecompileError::Revert(Bytes::new()))
}

fn invalid_evidence() -> PrecompileResult {
    Err(PrecompileHalt::Other("invalid double sign evidence".into()).into())
}

/// Recovers the signer of a 65-byte `r | s | v` seal as a left-padded 32-byte address.
///
/// Like libsecp256k1, this accepts recovery IDs 0 to 3 and high-S signatures.
fn recover(seal: &[u8], hash: &B256) -> Option<[u8; 32]> {
    let recid = seal[64];
    if recid > 3 {
        return None;
    }
    crypto().secp256k1_ecrecover(seal[..64].try_into().ok()?, recid, hash).ok()
}

/// bsc's `types.SealHash` (`EncodeSigHeader`): the header without the seal, prefixed with the
/// chain ID. The post-Cancun tail is included only when `parent_beacon_root` is present, and
/// `requests_hash` only on top of that.
fn seal_hash(header: &Header, chain_id: &RlpBigInt) -> B256 {
    let mut payload = Vec::new();
    chain_id.encode(&mut payload);
    header.parent_hash.encode(&mut payload);
    header.uncle_hash.encode(&mut payload);
    header.coinbase.encode(&mut payload);
    header.root.encode(&mut payload);
    header.tx_hash.encode(&mut payload);
    header.receipt_hash.encode(&mut payload);
    header.bloom.encode(&mut payload);
    header.difficulty.encode(&mut payload);
    header.number.encode(&mut payload);
    header.gas_limit.encode(&mut payload);
    header.gas_used.encode(&mut payload);
    header.time.encode(&mut payload);
    header.extra[..header.extra.len() - EXTRA_SEAL_LENGTH].encode(&mut payload);
    header.mix_digest.encode(&mut payload);
    header.nonce.encode(&mut payload);
    if let Some(parent_beacon_root) = header.parent_beacon_root {
        // Go encodes absent fields (nil pointers) as empty strings.
        encode_optional(header.base_fee.as_ref(), &mut payload);
        encode_optional(header.withdrawals_hash.as_ref(), &mut payload);
        encode_optional(header.blob_gas_used.as_ref(), &mut payload);
        encode_optional(header.excess_blob_gas.as_ref(), &mut payload);
        parent_beacon_root.encode(&mut payload);
        if let Some(requests_hash) = header.requests_hash {
            requests_hash.encode(&mut payload);
        }
    }

    let mut encoded = Vec::with_capacity(payload.len() + 9);
    RlpHeader { list: true, payload_length: payload.len() }.encode(&mut encoded);
    encoded.extend_from_slice(&payload);
    keccak256(&encoded)
}

fn encode_optional<T: Encodable>(value: Option<&T>, out: &mut Vec<u8>) {
    match value {
        Some(value) => value.encode(out),
        None => out.push(EMPTY_STRING_CODE),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::hex;
    use k256::ecdsa::SigningKey;

    /// Expected output for [`VALID_EVIDENCE`]: signer `0x15d3…6a65` at height 3295.
    const VALID_OUTPUT: [u8; 52] = hex!(
        "15d34aaf54267db7d7c367839aaf71a00a2c6a650000000000000000000000000000000000000000000000000000000000000cdf"
    );

    /// Valid evidence from bsc's and reth-bsc's tests.
    const VALID_EVIDENCE: &str = "f906278202cab9030ff9030ca01062d3d5015b9242bc193a9b0769f3d3780ecb55f97f40a752ae26d0b68cd0d8a0fae1a05fcb14bfd9b8a9f2b65007a9b6c2000de0627a73be644dd993d32342c494976ea74026e726554db657fa54763abd0c3a0aa9a0f385cc58ed297ff0d66eb5580b02853d3478ba418b1819ac659ee05df49b9794a0bf88464af369ed6b8cf02db00f0b9556ffa8d49cd491b00952a7f83431446638a00a6d0870e586a76278fbfdcedf76ef6679af18fc1f9137cfad495f434974ea81b901000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001820cdf830f4240830f4240846555fa64b90111d983010301846765746888676f312e32302e378664617277696e00007abd731ef8ae07b86091cb8836d58f5444b883422a18825d899035d3e6ea39ad1a50069bf0b86da8b5573dde1cb4a0a34f19ce94e0ef78ff7518c80265b8a3ca56e3c60167523590d4e8dcc324900559465fc0fa403774096614e135de280949b58a45cc96f2ba9e17f848820d41a08429d0d8b33ee72a84f750fefea846cbca54e487129c7961c680bb72309ca888820d42a08c9db14d938b19f9e2261bbeca2679945462be2b58103dfff73665d0d150fb8a804ae755e0fe64b59753f4db6308a1f679747bce186aa2c62b95fa6eeff3fbd08f3b0667e45428a54ade15bad19f49641c499b431b36f65803ea71b379e6b61de501a0232c9ba2d41b40d36ed794c306747bcbc49bf61a0f37409c18bfe2b5bef26a2d880000000000000000b9030ff9030ca01062d3d5015b9242bc193a9b0769f3d3780ecb55f97f40a752ae26d0b68cd0d8a0b2789a5357827ed838335283e15c4dcc42b9bebcbf2919a18613246787e2f96094976ea74026e726554db657fa54763abd0c3a0aa9a071ce4c09ee275206013f0063761bc19c93c13990582f918cc57333634c94ce89a00e095703e5c9b149f253fe89697230029e32484a410b4b1f2c61442d73c3095aa0d317ae19ede7c8a2d3ac9ef98735b049bcb7278d12f48c42b924538b60a25e12b901000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001820cdf830f4240830f4240846555fa64b90111d983010301846765746888676f312e32302e378664617277696e00007abd731ef8ae07b86091cb8836d58f5444b883422a18825d899035d3e6ea39ad1a50069bf0b86da8b5573dde1cb4a0a34f19ce94e0ef78ff7518c80265b8a3ca56e3c60167523590d4e8dcc324900559465fc0fa403774096614e135de280949b58a45cc96f2ba9e17f848820d41a08429d0d8b33ee72a84f750fefea846cbca54e487129c7961c680bb72309ca888820d42a08c9db14d938b19f9e2261bbeca2679945462be2b58103dfff73665d0d150fb8a80c0b17bfe88534296ff064cb7156548f6deba2d6310d5044ed6485f087dc6ef232e051c28e1909c2b50a3b4f29345d66681c319bef653e52e5d746480d5a3983b00a0b56228685be711834d0f154292d07826dea42a0fad3e4f56c31470b7fbfbea26880000000000000000";

    /// Outcome of a run: `Ok(output)`, `Err(true)` for a revert, `Err(false)` for invalid
    /// evidence.
    fn exec(input: &[u8]) -> Result<Vec<u8>, bool> {
        let mut gas = GasTracker::new(DOUBLE_SIGN_EVIDENCE_VERIFY_GAS);
        let outcome = match run(input, &mut gas) {
            Ok(output) => Ok(output.bytes().to_vec()),
            Err(PrecompileError::Revert(output)) => {
                assert!(output.is_empty());
                Err(true)
            }
            Err(PrecompileError::Halt(PrecompileHalt::Other(reason))) => {
                assert_eq!(reason, "invalid double sign evidence");
                Err(false)
            }
            Err(err) => panic!("unexpected error: {err:?}"),
        };
        assert_eq!(gas.remaining(), 0);
        outcome
    }

    impl Encodable for Header {
        fn encode(&self, out: &mut dyn alloy_rlp::BufMut) {
            let mut payload = Vec::new();
            self.parent_hash.encode(&mut payload);
            self.uncle_hash.encode(&mut payload);
            self.coinbase.encode(&mut payload);
            self.root.encode(&mut payload);
            self.tx_hash.encode(&mut payload);
            self.receipt_hash.encode(&mut payload);
            self.bloom.encode(&mut payload);
            self.difficulty.encode(&mut payload);
            self.number.encode(&mut payload);
            self.gas_limit.encode(&mut payload);
            self.gas_used.encode(&mut payload);
            self.time.encode(&mut payload);
            self.extra.encode(&mut payload);
            self.mix_digest.encode(&mut payload);
            self.nonce.encode(&mut payload);
            // Optional fields are written up to the last present one.
            let tail = [
                self.base_fee.as_ref().map(alloy_rlp::encode),
                self.withdrawals_hash.as_ref().map(alloy_rlp::encode),
                self.blob_gas_used.as_ref().map(alloy_rlp::encode),
                self.excess_blob_gas.as_ref().map(alloy_rlp::encode),
                self.parent_beacon_root.as_ref().map(alloy_rlp::encode),
                self.requests_hash.as_ref().map(alloy_rlp::encode),
                self.block_access_list_hash.as_ref().map(alloy_rlp::encode),
                self.slot_number.as_ref().map(alloy_rlp::encode),
            ];
            let present = tail.iter().rposition(Option::is_some).map_or(0, |last| last + 1);
            for field in &tail[..present] {
                payload.extend_from_slice(field.as_deref().unwrap_or(&[EMPTY_STRING_CODE]));
            }
            RlpHeader { list: true, payload_length: payload.len() }.encode(out);
            out.put_slice(&payload);
        }
    }

    fn big(bytes: &[u8]) -> RlpBigInt {
        RlpBigInt(Bytes::copy_from_slice(bytes))
    }

    /// Height 123,456.
    const HEIGHT: [u8; 3] = [0x01, 0xe2, 0x40];

    fn base_header() -> Header {
        Header {
            parent_hash: [0x11; 32],
            uncle_hash: [0x22; 32],
            coinbase: [0x33; 20],
            root: [0x44; 32],
            tx_hash: [0x55; 32],
            receipt_hash: [0x66; 32],
            bloom: [0; 256],
            difficulty: big(&[0x02]),
            number: big(&HEIGHT),
            gas_limit: 1_000_000,
            gas_used: 0,
            time: 0,
            // 32 bytes of vanity followed by the seal.
            extra: Bytes::from(vec![0; 32 + EXTRA_SEAL_LENGTH]),
            mix_digest: [0x77; 32],
            nonce: [0; 8],
            base_fee: None,
            withdrawals_hash: None,
            blob_gas_used: None,
            excess_blob_gas: None,
            parent_beacon_root: None,
            requests_hash: None,
            block_access_list_hash: None,
            slot_number: None,
        }
    }

    fn key(label: &[u8]) -> SigningKey {
        SigningKey::from_slice(keccak256(label).as_slice()).unwrap()
    }

    /// Writes a seal over the header's seal hash into the end of its extra data.
    fn sign(header: &mut Header, chain_id: &RlpBigInt, key: &SigningKey) {
        let (signature, recid) =
            key.sign_prehash_recoverable(seal_hash(header, chain_id).as_slice());
        let mut extra = header.extra.to_vec();
        let seal = extra.len() - EXTRA_SEAL_LENGTH;
        extra[seal..seal + 64].copy_from_slice(&signature.to_bytes());
        extra[seal + 64] = recid.to_byte();
        header.extra = extra.into();
    }

    fn encode_evidence(chain_id: RlpBigInt, header1: &Header, header2: &Header) -> Vec<u8> {
        alloy_rlp::encode(DoubleSignEvidence {
            chain_id,
            header_bytes1: alloy_rlp::encode(header1).into(),
            header_bytes2: alloy_rlp::encode(header2).into(),
        })
    }

    /// Two headers at the same height and parent with different state roots, both signed by
    /// `key2` (`key1` signs the first header when they differ), after `mutate`.
    fn evidence_with(
        chain_id: &[u8],
        key1: &[u8],
        key2: &[u8],
        mutate: impl Fn(&mut Header, &mut Header),
    ) -> Vec<u8> {
        let chain_id = big(chain_id);
        let (mut header1, mut header2) = (base_header(), base_header());
        header2.root = [0x99; 32];
        mutate(&mut header1, &mut header2);
        sign(&mut header1, &chain_id, &key(key1));
        sign(&mut header2, &chain_id, &key(key2));
        encode_evidence(chain_id, &header1, &header2)
    }

    fn evidence(mutate: impl Fn(&mut Header, &mut Header)) -> Vec<u8> {
        evidence_with(&[0x38], b"signer", b"signer", mutate)
    }

    fn expected_output(number: &[u8]) -> Vec<u8> {
        let mut output = vec![0; 52];
        let signer = k256::ecdsa::VerifyingKey::from(&key(b"signer"));
        let point = signer.to_sec1_point(false);
        output[..20].copy_from_slice(&keccak256(&point.as_bytes()[1..])[12..]);
        output[52 - number.len()..].copy_from_slice(number);
        output
    }

    #[test]
    fn bsc_vector() {
        assert_eq!(exec(&hex::decode(VALID_EVIDENCE).unwrap()), Ok(VALID_OUTPUT.to_vec()));
    }

    #[test]
    fn valid_evidence() {
        assert_eq!(exec(&evidence(|_, _| {})), Ok(expected_output(&HEIGHT)));
        // Chain IDs and numbers wider than 64 bits are accepted, like Go's `*big.Int`.
        let wide = [&[1][..], &[0; 8]].concat();
        let input = evidence_with(&wide, b"signer", b"signer", |_, _| {});
        assert_eq!(exec(&input), Ok(expected_output(&HEIGHT)));
        let input = evidence(|header1, header2| {
            header1.number = big(&wide);
            header2.number = big(&wide);
        });
        assert_eq!(exec(&input), Ok(expected_output(&wide)));
        // Post-Cancun headers with the optional tail.
        let input = evidence(|header1, header2| {
            for header in [header1, header2] {
                header.base_fee = Some(big(&[]));
                header.withdrawals_hash = Some([0xaa; 32]);
                header.blob_gas_used = Some(0);
                header.excess_blob_gas = Some(0);
                header.parent_beacon_root = Some([0; 32]);
                header.requests_hash = Some([0xbb; 32]);
            }
        });
        assert_eq!(exec(&input), Ok(expected_output(&HEIGHT)));
    }

    #[test]
    fn invalid_evidence_halts() {
        // Different signers.
        assert_eq!(exec(&evidence_with(&[0x38], b"signer", b"other", |_, _| {})), Err(false));
        // Different heights.
        assert_eq!(exec(&evidence(|_, header2| header2.number = big(&[0x07]))), Err(false));
        // Different parents.
        assert_eq!(exec(&evidence(|_, header2| header2.parent_hash = [0; 32])), Err(false));
        // Number wider than 32 bytes.
        let oversized = [&[1][..], &[0; 32]].concat();
        let input = evidence(|header1, header2| {
            header1.number = big(&oversized);
            header2.number = big(&oversized);
        });
        assert_eq!(exec(&input), Err(false));
        // Equal seals: two unsigned headers.
        let (header1, mut header2) = (base_header(), base_header());
        header2.root = [0x99; 32];
        assert_eq!(exec(&encode_evidence(big(&[0x38]), &header1, &header2)), Err(false));
        // Equal seal hashes: same header, different (both valid) seals.
        let chain_id = big(&[0x38]);
        let (mut header1, mut header2) = (base_header(), base_header());
        sign(&mut header1, &chain_id, &key(b"signer"));
        sign(&mut header2, &chain_id, &key(b"other"));
        assert_eq!(exec(&encode_evidence(chain_id, &header1, &header2)), Err(false));
        // Extra data shorter than a seal.
        let (mut header1, mut header2) = (base_header(), base_header());
        header2.root = [0x99; 32];
        header1.extra = vec![1; 64].into();
        header2.extra = vec![2; 64].into();
        assert_eq!(exec(&encode_evidence(big(&[0x38]), &header1, &header2)), Err(false));
    }

    #[test]
    fn malformed_input_reverts() {
        let valid = evidence(|_, _| {});
        assert_eq!(exec(&[]), Err(true));
        // Trailing bytes after the evidence or a header.
        assert_eq!(exec(&[valid.as_slice(), &[0]].concat()), Err(true));
        let chain_id = big(&[0x38]);
        let (mut header1, mut header2) = (base_header(), base_header());
        header2.root = [0x99; 32];
        sign(&mut header1, &chain_id, &key(b"signer"));
        sign(&mut header2, &chain_id, &key(b"signer"));
        let input = alloy_rlp::encode(DoubleSignEvidence {
            chain_id,
            header_bytes1: [alloy_rlp::encode(&header1), vec![0]].concat().into(),
            header_bytes2: alloy_rlp::encode(&header2).into(),
        });
        assert_eq!(exec(&input), Err(true));
        // Non-canonical integers.
        let input = evidence_with(&[0, 0x38], b"signer", b"signer", |_, _| {});
        assert_eq!(exec(&input), Err(true));
        // Unrecoverable seal: recovery ID out of range.
        let input = evidence(|_, _| {});
        let mut decoded = alloy_rlp::decode_exact::<DoubleSignEvidence>(&input).unwrap();
        let mut header2 = alloy_rlp::decode_exact::<Header>(&decoded.header_bytes2).unwrap();
        let mut extra = header2.extra.to_vec();
        *extra.last_mut().unwrap() = 4;
        header2.extra = extra.into();
        decoded.header_bytes2 = alloy_rlp::encode(&header2).into();
        assert_eq!(exec(&alloy_rlp::encode(decoded)), Err(true));
    }

    #[test]
    fn seal_hash_tail() {
        let chain_id = big(&[0x38]);
        let bare = base_header();
        // The tail is ignored without a parent beacon root.
        let mut base_fee_only = base_header();
        base_fee_only.base_fee = Some(big(&[0x07]));
        assert_eq!(seal_hash(&bare, &chain_id), seal_hash(&base_fee_only, &chain_id));
        // With one, the tail and the requests hash are sealed.
        let mut with_tail = base_fee_only;
        with_tail.withdrawals_hash = Some([0xaa; 32]);
        with_tail.blob_gas_used = Some(0);
        with_tail.excess_blob_gas = Some(0);
        with_tail.parent_beacon_root = Some([0; 32]);
        assert_ne!(seal_hash(&bare, &chain_id), seal_hash(&with_tail, &chain_id));
        let mut with_requests = with_tail.clone();
        with_requests.requests_hash = Some([0xbb; 32]);
        assert_ne!(seal_hash(&with_tail, &chain_id), seal_hash(&with_requests, &chain_id));
        // Fields after the requests hash are not sealed.
        let mut with_bal = with_requests.clone();
        with_bal.block_access_list_hash = Some([0xcc; 32]);
        assert_eq!(seal_hash(&with_requests, &chain_id), seal_hash(&with_bal, &chain_id));
    }
}
