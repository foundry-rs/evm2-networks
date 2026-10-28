//! BSC precompiles.
//!
//! Port of bsc's `activePrecompiledContracts` (`core/vm/contracts.go`):
//!
//! | Hardfork        | Set                                                                  |
//! |-----------------|----------------------------------------------------------------------|
//! | Istanbul–Euler  | Istanbul plus `0x64` and `0x65`                                      |
//! | Nano            | `0x64` and `0x65` deprecated                                         |
//! | Moran–Planck    | `0x64` and `0x65` restored                                           |
//! | Luban, Plato    | Adds BLS verification (`0x66`) and `0x67`                            |
//! | Berlin, London  | Ethereum's Berlin set, without BSC precompiles                       |
//! | Hertz           | Berlin plus `0x64`–`0x67`                                            |
//! | Feynman         | Adds double-sign evidence (`0x68`) and Tendermint recovery (`0x69`) |
//! | Cancun          | Adds KZG                                                             |
//! | Haber           | Adds RIP-7212 P256 (`0x100`, 3,450 gas)                              |
//! | Prague          | Adds BLS12-381 (`0x0b`-`0x11`)                                       |
//! | Osaka           | Osaka modexp and EIP-7951 P256 pricing (6,900 gas)                   |
//! | Pasteur         | `0x64` and `0x65` deprecated, `0x67` priced per input byte           |
//!
//! The light-client precompiles (`0x64` Tendermint header validation, `0x65` IAVL Merkle proof
//! validation and `0x67` CometBFT light block validation) are not ported: they charge their gas
//! and halt with [`UNSUPPORTED_LIGHT_CLIENT_PRECOMPILE`]. They served the retired BNB Beacon
//! Chain bridge.

use crate::{BscEvmTypes, BscHardfork};
use alloc::borrow::Cow;
use alloy_primitives::Address;
use evm2::{
    Evm, Precompiles,
    interpreter::{GasTracker, Message},
    precompiles::{
        P256VERIFY, Precompile, PrecompileHalt, PrecompileId, PrecompileMap, PrecompileResult,
    },
};

pub mod bls;
pub mod double_sign;
pub mod tm_secp256k1;

/// Tendermint header validation precompile address.
pub const TM_HEADER_VALIDATE_ADDRESS: Address = Address::with_last_byte(0x64);

/// IAVL Merkle proof validation precompile address.
pub const IAVL_MERKLE_PROOF_VALIDATE_ADDRESS: Address = Address::with_last_byte(0x65);

/// BLS signature verification precompile address.
pub const BLS_SIGNATURE_VERIFY_ADDRESS: Address = Address::with_last_byte(0x66);

/// CometBFT light block validation precompile address.
pub const COMETBFT_LIGHT_BLOCK_VALIDATE_ADDRESS: Address = Address::with_last_byte(0x67);

/// Double-sign evidence verification precompile address.
pub const DOUBLE_SIGN_EVIDENCE_VERIFY_ADDRESS: Address = Address::with_last_byte(0x68);

/// Tendermint secp256k1 signature recovery precompile address.
pub const TM_SECP256K1_SIGNATURE_RECOVER_ADDRESS: Address = Address::with_last_byte(0x69);

/// Gas of the light-client precompiles (`0x64`, `0x65`, `0x67`).
pub const LIGHT_CLIENT_GAS: u64 = 3_000;

/// Gas per input byte of the CometBFT light block validation precompile from Pasteur.
pub const COMETBFT_PASTEUR_PER_BYTE_GAS: u64 = 16;

/// Halt reason of the light-client precompiles, which are not ported.
///
/// evm2 reports every precompile halt as `InstrStop::PrecompileError` at the call frame, so the
/// reason is only visible when running the precompile directly.
pub const UNSUPPORTED_LIGHT_CLIENT_PRECOMPILE: &str = "BSC light-client precompile not supported";

/// Halt reason of the deprecated light-client precompiles.
pub const DEPRECATED_PRECOMPILE: &str = "deprecated";

fn halt(reason: &'static str) -> PrecompileResult {
    Err(PrecompileHalt::Other(reason.into()).into())
}

fn light_client(
    _evm: &mut Evm<'_, BscEvmTypes>,
    _message: &Message<BscEvmTypes>,
    gas: &mut GasTracker,
) -> PrecompileResult {
    gas.spend(LIGHT_CLIENT_GAS)?;
    halt(UNSUPPORTED_LIGHT_CLIENT_PRECOMPILE)
}

fn cometbft_pasteur(
    _evm: &mut Evm<'_, BscEvmTypes>,
    message: &Message<BscEvmTypes>,
    gas: &mut GasTracker,
) -> PrecompileResult {
    let per_byte = (message.input.len() as u64).saturating_mul(COMETBFT_PASTEUR_PER_BYTE_GAS);
    gas.spend(LIGHT_CLIENT_GAS.saturating_add(per_byte))?;
    halt(UNSUPPORTED_LIGHT_CLIENT_PRECOMPILE)
}

fn deprecated(
    _evm: &mut Evm<'_, BscEvmTypes>,
    _message: &Message<BscEvmTypes>,
    gas: &mut GasTracker,
) -> PrecompileResult {
    gas.spend(LIGHT_CLIENT_GAS)?;
    halt(DEPRECATED_PRECOMPILE)
}

fn bls_signature_verify(
    _evm: &mut Evm<'_, BscEvmTypes>,
    message: &Message<BscEvmTypes>,
    gas: &mut GasTracker,
) -> PrecompileResult {
    bls::run(&message.input, gas)
}

fn double_sign_evidence_verify(
    _evm: &mut Evm<'_, BscEvmTypes>,
    message: &Message<BscEvmTypes>,
    gas: &mut GasTracker,
) -> PrecompileResult {
    double_sign::run(&message.input, gas)
}

fn tm_secp256k1_signature_recover(
    _evm: &mut Evm<'_, BscEvmTypes>,
    message: &Message<BscEvmTypes>,
    gas: &mut GasTracker,
) -> PrecompileResult {
    tm_secp256k1::run(&message.input, gas)
}

/// Returns the BSC precompile map for `spec`.
pub fn bsc_precompile_map(spec: BscHardfork) -> PrecompileMap<BscEvmTypes> {
    use BscHardfork::*;

    let mut map = Precompiles::<BscEvmTypes>::base(spec.into_eth_spec()).as_map().clone();
    // bsc falls back to Ethereum's Berlin set when Berlin is active without Hertz.
    if matches!(spec, Berlin | London) {
        return map;
    }

    let precompile = |address, id, f| Precompile::new(address, PrecompileId::custom(id), f);
    let (tm_header, iavl) = if matches!(spec, Nano) || spec.enables(Pasteur) {
        (
            precompile(TM_HEADER_VALIDATE_ADDRESS, "HEADER_VALIDATE_DEPRECATED", deprecated),
            precompile(
                IAVL_MERKLE_PROOF_VALIDATE_ADDRESS,
                "IAVL_MERKLE_PROOF_VALIDATE_DEPRECATED",
                deprecated,
            ),
        )
    } else {
        (
            precompile(TM_HEADER_VALIDATE_ADDRESS, "HEADER_VALIDATE", light_client),
            precompile(
                IAVL_MERKLE_PROOF_VALIDATE_ADDRESS,
                "IAVL_MERKLE_PROOF_VALIDATE",
                light_client,
            ),
        )
    };
    map.extend([tm_header, iavl]);
    if spec.enables(Luban) {
        let cometbft = if spec.enables(Pasteur) {
            precompile(
                COMETBFT_LIGHT_BLOCK_VALIDATE_ADDRESS,
                "COMET_BFT_LIGHT_BLOCK_VALIDATE_PASTEUR",
                cometbft_pasteur,
            )
        } else {
            precompile(
                COMETBFT_LIGHT_BLOCK_VALIDATE_ADDRESS,
                "COMET_BFT_LIGHT_BLOCK_VALIDATE",
                light_client,
            )
        };
        map.extend([
            precompile(BLS_SIGNATURE_VERIFY_ADDRESS, "BLS_SIGNATURE_VERIFY", bls_signature_verify),
            cometbft,
        ]);
    }
    if spec.enables(Feynman) {
        map.extend([
            precompile(
                DOUBLE_SIGN_EVIDENCE_VERIFY_ADDRESS,
                "VERIFY_DOUBLE_SIGN_EVIDENCE",
                double_sign_evidence_verify,
            ),
            precompile(
                TM_SECP256K1_SIGNATURE_RECOVER_ADDRESS,
                "SECP256K1_SIGNATURE_RECOVER",
                tm_secp256k1_signature_recover,
            ),
        ]);
    }
    // Ethereum's Osaka set already carries EIP-7951 P256.
    if spec.enables(Haber) && !spec.enables(Osaka) {
        map.insert(P256VERIFY());
    }
    map
}

/// Returns the BSC precompile provider for `spec`.
pub fn bsc_precompiles(spec: BscHardfork) -> Precompiles<BscEvmTypes> {
    Precompiles::new(Cow::Owned(bsc_precompile_map(spec)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use BscHardfork::*;
    use alloy_primitives::Bytes;
    use evm2::{
        env::BlockEnv,
        evm::{EmptyDB, precompile::PrecompileProvider},
        precompiles::PrecompileError,
    };

    /// Executes empty input at `address` with 1,000,000 gas. Returns `None` if `address` is not a
    /// precompile, otherwise the gas spent and the halt reason if it halted.
    fn probe(spec: BscHardfork, address: Address, input: &[u8]) -> Option<(u64, Option<String>)> {
        let mut precompiles = bsc_precompiles(spec);
        let mut evm = Evm::<BscEvmTypes>::new(
            spec,
            BlockEnv::<BscEvmTypes>::default(),
            crate::bsc_tx_registry(spec),
            EmptyDB::default(),
            bsc_precompiles(spec),
        );
        let message = Message::<BscEvmTypes> {
            input: Bytes::copy_from_slice(input),
            call_target: address,
            code_address: address,
            ..Default::default()
        };
        let mut gas = GasTracker::new(1_000_000);
        let reason = match precompiles.execute(&mut evm, &message, &mut gas)? {
            Ok(_) | Err(PrecompileError::Revert(_)) => None,
            Err(PrecompileError::Halt(PrecompileHalt::Other(reason))) => Some(reason.into_owned()),
            Err(err) => panic!("{spec}: precompile {address} failed: {err:?}"),
        };
        Some((gas.spent(), reason))
    }

    fn deprecated() -> Option<(u64, Option<String>)> {
        Some((3_000, Some(DEPRECATED_PRECOMPILE.into())))
    }

    fn unsupported(gas: u64) -> Option<(u64, Option<String>)> {
        Some((gas, Some(UNSUPPORTED_LIGHT_CLIENT_PRECOMPILE.into())))
    }

    /// Expected outcome of [`probe`] at `0x64`-`0x69` and `0x100` with empty input, from bsc's
    /// precompile tables.
    fn expected(spec: BscHardfork) -> [Option<(u64, Option<String>)>; 7] {
        if matches!(spec, Berlin | London) {
            return Default::default();
        }
        let tm_iavl =
            if spec == Nano || spec.enables(Pasteur) { deprecated() } else { unsupported(3_000) };
        // Malformed BLS input reverts with the base gas.
        let luban = |outcome| if spec.enables(Luban) { outcome } else { None };
        let feynman = |outcome| if spec.enables(Feynman) { outcome } else { None };
        let p256 = if spec.enables(Osaka) {
            Some((6_900, None))
        } else if spec.enables(Haber) {
            Some((3_450, None))
        } else {
            None
        };
        [
            tm_iavl.clone(),
            tm_iavl,
            luban(Some((1_000, None))),
            luban(unsupported(3_000)),
            feynman(Some((10_000, None))),
            feynman(Some((3_000, Some("invalid input".into())))),
            p256,
        ]
    }

    #[test]
    fn precompile_sets_match_bsc() {
        let addresses = [0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x100]
            .map(|address: u16| Address::left_padding_from(&address.to_be_bytes()));
        for spec in BscHardfork::ALL {
            let outcomes = addresses.map(|address| probe(spec, address, &[]));
            assert_eq!(outcomes, expected(spec), "{spec}");

            let map = bsc_precompile_map(spec);
            let eth = Precompiles::<BscEvmTypes>::base(spec.into_eth_spec());
            let extra = expected(spec).iter().filter(|outcome| outcome.is_some()).count();
            // Osaka's base set already includes P256.
            let p256_in_base = usize::from(spec.enables(Osaka));
            assert_eq!(map.len(), eth.as_map().len() + extra - p256_in_base, "{spec}");
            for address in eth.as_map().addresses() {
                assert!(map.contains(&address), "{spec}: missing {address}");
            }
        }
        // KZG from Cancun and BLS12-381 from Prague come from Ethereum's sets.
        let kzg = Address::with_last_byte(0x0a);
        let bls12_g1_add = Address::with_last_byte(0x0b);
        assert!(!bsc_precompile_map(FeynmanFix).contains(&kzg));
        assert!(bsc_precompile_map(Cancun).contains(&kzg));
        assert!(!bsc_precompile_map(Bohr).contains(&bls12_g1_add));
        assert!(bsc_precompile_map(Pascal).contains(&bls12_g1_add));
    }

    #[test]
    fn cometbft_priced_per_byte_from_pasteur() {
        let address = COMETBFT_LIGHT_BLOCK_VALIDATE_ADDRESS;
        assert_eq!(probe(Mendel, address, &[0; 10]), unsupported(3_000));
        assert_eq!(probe(Pasteur, address, &[0; 10]), unsupported(3_000 + 16 * 10));
    }
}
