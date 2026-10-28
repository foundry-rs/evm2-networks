//! Polygon precompiles.
//!
//! Port of Bor's `core/vm/contracts.go` precompile sets:
//!
//! | Hardfork            | Changes over the previous set                                   |
//! |---------------------|-----------------------------------------------------------------|
//! | Before Cancun       | Ethereum's set for the inherited spec                           |
//! | Cancun              | Berlin set plus RIP-7212 P256 (`0x100`, 3,450 gas); no KZG      |
//! | Bhilai              | Adds BLS12-381 (`0x0b`-`0x11`)                                  |
//! | Madhugiri           | Osaka modexp (EIP-7823/7883), adds KZG, drops P256              |
//! | MadhugiriPro        | Restores RIP-7212 P256                                          |
//! | Lisovo              | EIP-7951 P256 pricing (6,900 gas)                               |
//! | LisovoPro           | Drops KZG                                                       |
//! | Chicago             | PIP-88 repricing of BN254, BLAKE2F and BLS12-381                |

use crate::{PolygonEvmTypes, PolygonHardfork};
use alloc::borrow::Cow;
use alloy_primitives::Address;
use evm2::{
    Evm, Precompiles, SpecId,
    interpreter::{GasTracker, Message},
    precompiles::{
        BLS12_381_G1_ADD, BLS12_381_G1_MSM, BLS12_381_G2_ADD, BLS12_381_G2_MSM,
        BLS12_381_MAP_FP_TO_G1, BLS12_381_MAP_FP2_TO_G2, BLS12_381_PAIRING, KZG_POINT_EVALUATION,
        MODEXP_OSAKA, P256VERIFY, P256VERIFY_OSAKA, Precompile, PrecompileId, PrecompileMap,
        PrecompileResult, blake2, bls12_381, bn254,
    },
};

/// PIP-88 BN254 addition gas (150 × 3.6).
pub const PIP88_BN254_ADD_GAS: u64 = 540;

/// PIP-88 BN254 scalar multiplication gas (6,000 × 2.1).
pub const PIP88_BN254_MUL_GAS: u64 = 12_600;

/// PIP-88 BN254 pairing base gas (45,000 × 1.5).
pub const PIP88_BN254_PAIRING_BASE_GAS: u64 = 67_500;

/// PIP-88 BN254 pairing gas per point (34,000 × 1.5).
pub const PIP88_BN254_PAIRING_PER_POINT_GAS: u64 = 51_000;

/// PIP-88 BLAKE2F gas per round (`GFROUND` = 22).
pub const PIP88_BLAKE2F_ROUND_GAS: u64 = 22;

/// PIP-88 BLS12-381 G1 addition gas (375 × 2.8).
pub const PIP88_BLS12_G1_ADD_GAS: u64 = 1_050;

/// PIP-88 BLS12-381 G1 multiplication gas (12,000 × 6.1).
pub const PIP88_BLS12_G1_MUL_GAS: u64 = 73_200;

/// PIP-88 BLS12-381 G2 addition gas (600 × 2.7).
pub const PIP88_BLS12_G2_ADD_GAS: u64 = 1_620;

/// PIP-88 BLS12-381 G2 multiplication gas (22,500 × 6.4).
pub const PIP88_BLS12_G2_MUL_GAS: u64 = 144_000;

/// PIP-88 BLS12-381 pairing base gas (37,700 × 2.9).
pub const PIP88_BLS12_PAIRING_BASE_GAS: u64 = 109_330;

/// PIP-88 BLS12-381 pairing gas per pair (32,600 × 2.9).
pub const PIP88_BLS12_PAIRING_PER_PAIR_GAS: u64 = 94_540;

/// PIP-88 BLS12-381 map-to-G1 gas (5,500 × 2.8).
pub const PIP88_BLS12_MAP_FP_TO_G1_GAS: u64 = 15_400;

/// PIP-88 BLS12-381 map-to-G2 gas (23,800 × 2.8).
pub const PIP88_BLS12_MAP_FP2_TO_G2_GAS: u64 = 66_640;

const BLAKE2F_INPUT_LENGTH: usize = 213;
const BLS12_G1_MSM_PAIR_LENGTH: usize = 160;
const BLS12_G2_MSM_PAIR_LENGTH: usize = 288;
const BLS12_PAIRING_PAIR_LENGTH: usize = 384;

/// EIP-2537 G1 MSM discount table.
const BLS12_G1_MSM_DISCOUNT: [u16; 128] = [
    1000, 949, 848, 797, 764, 750, 738, 728, 719, 712, 705, 698, 692, 687, 682, 677, 673, 669, 665,
    661, 658, 654, 651, 648, 645, 642, 640, 637, 635, 632, 630, 627, 625, 623, 621, 619, 617, 615,
    613, 611, 609, 608, 606, 604, 603, 601, 599, 598, 596, 595, 593, 592, 591, 589, 588, 586, 585,
    584, 582, 581, 580, 579, 577, 576, 575, 574, 573, 572, 570, 569, 568, 567, 566, 565, 564, 563,
    562, 561, 560, 559, 558, 557, 556, 555, 554, 553, 552, 551, 550, 549, 548, 547, 547, 546, 545,
    544, 543, 542, 541, 540, 540, 539, 538, 537, 536, 536, 535, 534, 533, 532, 532, 531, 530, 529,
    528, 528, 527, 526, 525, 525, 524, 523, 522, 522, 521, 520, 520, 519,
];

/// EIP-2537 G2 MSM discount table.
const BLS12_G2_MSM_DISCOUNT: [u16; 128] = [
    1000, 1000, 923, 884, 855, 832, 812, 796, 782, 770, 759, 749, 740, 732, 724, 717, 711, 704,
    699, 693, 688, 683, 679, 674, 670, 666, 663, 659, 655, 652, 649, 646, 643, 640, 637, 634, 632,
    629, 627, 624, 622, 620, 618, 615, 613, 611, 609, 607, 606, 604, 602, 600, 598, 597, 595, 593,
    592, 590, 589, 587, 586, 584, 583, 582, 580, 579, 578, 576, 575, 574, 573, 571, 570, 569, 568,
    567, 566, 565, 563, 562, 561, 560, 559, 558, 557, 556, 555, 554, 553, 552, 552, 551, 550, 549,
    548, 547, 546, 545, 545, 544, 543, 542, 541, 541, 540, 539, 538, 537, 537, 536, 535, 535, 534,
    533, 532, 532, 531, 530, 530, 529, 528, 528, 527, 526, 526, 525, 524, 524,
];

/// Returns a tracker that does not limit the wrapped Ethereum implementation, for precompiles
/// whose PIP-88 price is charged up front.
const fn unmetered() -> GasTracker {
    GasTracker::new(u64::MAX)
}

/// MSM gas as Bor computes it: `k * mul_gas * discount(k) / 1000`, zero for empty input.
fn msm_gas(input_len: usize, pair_len: usize, mul_gas: u64, discount: &[u16; 128]) -> u64 {
    let k = input_len / pair_len;
    if k == 0 {
        return 0;
    }
    let discount = u64::from(discount[k.min(discount.len()) - 1]);
    (k as u64).saturating_mul(mul_gas).saturating_mul(discount) / 1000
}

/// PIP-88 BN254 addition.
pub fn pip88_bn254_add_run(input: &[u8], gas: &mut GasTracker) -> PrecompileResult {
    bn254::run_add(input, PIP88_BN254_ADD_GAS, gas)
}

/// PIP-88 BN254 scalar multiplication.
pub fn pip88_bn254_mul_run(input: &[u8], gas: &mut GasTracker) -> PrecompileResult {
    bn254::run_mul(input, PIP88_BN254_MUL_GAS, gas)
}

/// PIP-88 BN254 pairing.
pub fn pip88_bn254_pairing_run(input: &[u8], gas: &mut GasTracker) -> PrecompileResult {
    bn254::run_pair(input, PIP88_BN254_PAIRING_PER_POINT_GAS, PIP88_BN254_PAIRING_BASE_GAS, gas)
}

/// PIP-88 BLAKE2F.
pub fn pip88_blake2f_run(input: &[u8], gas: &mut GasTracker) -> PrecompileResult {
    // Bor prices malformed input at zero and lets the call fail.
    if input.len() == BLAKE2F_INPUT_LENGTH {
        let rounds = u32::from_be_bytes(input[..4].try_into().expect("4 bytes"));
        gas.spend(u64::from(rounds) * PIP88_BLAKE2F_ROUND_GAS)?;
    }
    blake2::run(input, &mut unmetered())
}

/// PIP-88 BLS12-381 G1 addition.
pub fn pip88_bls12_g1_add_run(input: &[u8], gas: &mut GasTracker) -> PrecompileResult {
    gas.spend(PIP88_BLS12_G1_ADD_GAS)?;
    bls12_381::g1_add::run(input, &mut unmetered())
}

/// PIP-88 BLS12-381 G1 MSM.
pub fn pip88_bls12_g1_msm_run(input: &[u8], gas: &mut GasTracker) -> PrecompileResult {
    gas.spend(msm_gas(
        input.len(),
        BLS12_G1_MSM_PAIR_LENGTH,
        PIP88_BLS12_G1_MUL_GAS,
        &BLS12_G1_MSM_DISCOUNT,
    ))?;
    bls12_381::g1_msm::run(input, &mut unmetered())
}

/// PIP-88 BLS12-381 G2 addition.
pub fn pip88_bls12_g2_add_run(input: &[u8], gas: &mut GasTracker) -> PrecompileResult {
    gas.spend(PIP88_BLS12_G2_ADD_GAS)?;
    bls12_381::g2_add::run(input, &mut unmetered())
}

/// PIP-88 BLS12-381 G2 MSM.
pub fn pip88_bls12_g2_msm_run(input: &[u8], gas: &mut GasTracker) -> PrecompileResult {
    gas.spend(msm_gas(
        input.len(),
        BLS12_G2_MSM_PAIR_LENGTH,
        PIP88_BLS12_G2_MUL_GAS,
        &BLS12_G2_MSM_DISCOUNT,
    ))?;
    bls12_381::g2_msm::run(input, &mut unmetered())
}

/// PIP-88 BLS12-381 pairing.
pub fn pip88_bls12_pairing_run(input: &[u8], gas: &mut GasTracker) -> PrecompileResult {
    let pairs = (input.len() / BLS12_PAIRING_PAIR_LENGTH) as u64;
    gas.spend(PIP88_BLS12_PAIRING_BASE_GAS + pairs * PIP88_BLS12_PAIRING_PER_PAIR_GAS)?;
    bls12_381::pairing::run(input, &mut unmetered())
}

/// PIP-88 BLS12-381 map-to-G1.
pub fn pip88_bls12_map_fp_to_g1_run(input: &[u8], gas: &mut GasTracker) -> PrecompileResult {
    gas.spend(PIP88_BLS12_MAP_FP_TO_G1_GAS)?;
    bls12_381::map_fp_to_g1::run(input, &mut unmetered())
}

/// PIP-88 BLS12-381 map-to-G2.
pub fn pip88_bls12_map_fp2_to_g2_run(input: &[u8], gas: &mut GasTracker) -> PrecompileResult {
    gas.spend(PIP88_BLS12_MAP_FP2_TO_G2_GAS)?;
    bls12_381::map_fp2_to_g2::run(input, &mut unmetered())
}

macro_rules! pip88_precompiles {
    ($($address:literal, $id:ident, $entry:ident => $run:path;)*) => {
        $(
            fn $entry(
                _evm: &mut Evm<'_, PolygonEvmTypes>,
                message: &Message<PolygonEvmTypes>,
                gas: &mut GasTracker,
            ) -> PrecompileResult {
                $run(message.input.as_ref(), gas)
            }
        )*

        /// PIP-88 precompiles, active from Chicago.
        fn pip88_precompiles() -> [Precompile<PolygonEvmTypes>; 11] {
            [$(Precompile::new(Address::with_last_byte($address), PrecompileId::$id, $entry),)*]
        }
    };
}

pip88_precompiles! {
    0x06, Bn254Add, bn254_add_entry => pip88_bn254_add_run;
    0x07, Bn254Mul, bn254_mul_entry => pip88_bn254_mul_run;
    0x08, Bn254Pairing, bn254_pairing_entry => pip88_bn254_pairing_run;
    0x09, Blake2F, blake2f_entry => pip88_blake2f_run;
    0x0b, Bls12G1Add, bls12_g1_add_entry => pip88_bls12_g1_add_run;
    0x0c, Bls12G1Msm, bls12_g1_msm_entry => pip88_bls12_g1_msm_run;
    0x0d, Bls12G2Add, bls12_g2_add_entry => pip88_bls12_g2_add_run;
    0x0e, Bls12G2Msm, bls12_g2_msm_entry => pip88_bls12_g2_msm_run;
    0x0f, Bls12Pairing, bls12_pairing_entry => pip88_bls12_pairing_run;
    0x10, Bls12MapFpToGp1, bls12_map_fp_to_g1_entry => pip88_bls12_map_fp_to_g1_run;
    0x11, Bls12MapFp2ToGp2, bls12_map_fp2_to_g2_entry => pip88_bls12_map_fp2_to_g2_run;
}

/// Returns the Polygon precompile map for `spec`.
pub fn polygon_precompile_map(spec: PolygonHardfork) -> PrecompileMap<PolygonEvmTypes> {
    use PolygonHardfork::*;

    if !spec.enables(Cancun) {
        return Precompiles::<PolygonEvmTypes>::base(spec.into_eth_spec()).as_map().clone();
    }

    // Bor replaces Ethereum's Cancun and Prague sets: no KZG, and P256 from Cancun on.
    let mut map = Precompiles::<PolygonEvmTypes>::base(SpecId::BERLIN).as_map().clone();
    if spec.enables(Bhilai) {
        map.extend([
            BLS12_381_G1_ADD(),
            BLS12_381_G1_MSM(),
            BLS12_381_G2_ADD(),
            BLS12_381_G2_MSM(),
            BLS12_381_PAIRING(),
            BLS12_381_MAP_FP_TO_G1(),
            BLS12_381_MAP_FP2_TO_G2(),
        ]);
    }
    if spec.enables(Madhugiri) {
        map.extend([MODEXP_OSAKA(), KZG_POINT_EVALUATION()]);
    }
    // Madhugiri dropped P256 and MadhugiriPro restored it.
    if spec.enables(Lisovo) {
        map.insert(P256VERIFY_OSAKA());
    } else if spec != Madhugiri {
        map.insert(P256VERIFY());
    }
    if spec.enables(LisovoPro) {
        map.remove(KZG_POINT_EVALUATION::<PolygonEvmTypes>().address());
    }
    if spec.enables(Chicago) {
        map.extend(pip88_precompiles());
    }
    map
}

/// Returns the Polygon precompile provider for `spec`.
pub fn polygon_precompiles(spec: PolygonHardfork) -> Precompiles<PolygonEvmTypes> {
    Precompiles::new(Cow::Owned(polygon_precompile_map(spec)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use PolygonHardfork::*;
    use alloy_primitives::Bytes;
    use evm2::{
        env::BlockEnv,
        ethereum::ethereum_tx_registry,
        evm::{EmptyDB, precompile::PrecompileProvider},
    };

    /// Executes `input` at precompile `address` with 1,000,000 gas and returns the gas spent, or
    /// `None` if `address` is not a precompile. Panics if the call fails.
    fn spent(spec: PolygonHardfork, address: u64, input: &[u8]) -> Option<u64> {
        let mut precompiles = polygon_precompiles(spec);
        let mut evm = Evm::<PolygonEvmTypes>::new(
            spec,
            BlockEnv::<PolygonEvmTypes>::default(),
            ethereum_tx_registry(spec.into()),
            EmptyDB::default(),
            polygon_precompiles(spec),
        );
        let code_address = Address::from_word(alloy_primitives::U256::from(address).into());
        let message = Message::<PolygonEvmTypes> {
            input: Bytes::copy_from_slice(input),
            code_address,
            call_target: code_address,
            ..Default::default()
        };
        let mut gas = GasTracker::new(1_000_000);
        let result = precompiles.execute(&mut evm, &message, &mut gas)?;
        result.unwrap_or_else(|err| panic!("{spec}: precompile {address:#x} failed: {err:?}"));
        Some(gas.spent())
    }

    fn blake2f_input() -> Vec<u8> {
        let mut input = vec![0; BLAKE2F_INPUT_LENGTH];
        input[3] = 12;
        input[212] = 1;
        input
    }

    /// Probe inputs: zero inputs encode the point at infinity, so every call succeeds.
    fn probes() -> Vec<(u64, Vec<u8>)> {
        vec![
            (0x01, vec![0; 128]),
            (0x02, vec![]),
            (0x03, vec![]),
            (0x04, vec![]),
            (0x05, vec![0; 96]),
            (0x06, vec![0; 128]),
            (0x07, vec![0; 96]),
            (0x08, vec![]),
            (0x09, blake2f_input()),
            (0x0b, vec![0; 256]),
            (0x0c, vec![0; 160]),
            (0x0d, vec![0; 512]),
            (0x0e, vec![0; 288]),
            (0x0f, vec![0; 384]),
            (0x10, vec![0; 64]),
            (0x11, vec![0; 128]),
            (0x100, vec![0; 160]),
        ]
    }

    /// Expected gas per probe from Bor's precompile tables, `None` for absent precompiles.
    fn expected(spec: PolygonHardfork) -> Vec<(u64, Option<u64>)> {
        let byzantium = !spec.enables(Istanbul);
        let pip88 = spec.enables(Chicago);
        let bls = spec.enables(Bhilai);
        let p256 = match spec {
            Madhugiri => None,
            _ if spec.enables(Lisovo) => Some(6_900),
            _ if spec.enables(Cancun) => Some(3_450),
            _ => None,
        };
        let pick = |eth: u64, pip88_gas: u64| Some(if pip88 { pip88_gas } else { eth });
        let bls_gas = |eth: u64, pip88_gas: u64| if bls { pick(eth, pip88_gas) } else { None };
        vec![
            (0x01, Some(3_000)),
            (0x02, Some(60)),
            (0x03, Some(600)),
            (0x04, Some(15)),
            (
                0x05,
                Some(if spec.enables(Madhugiri) {
                    500
                } else if spec.enables(Berlin) {
                    200
                } else {
                    0
                }),
            ),
            (0x06, if byzantium { Some(500) } else { pick(150, 540) }),
            (0x07, if byzantium { Some(40_000) } else { pick(6_000, 12_600) }),
            (0x08, if byzantium { Some(100_000) } else { pick(45_000, 67_500) }),
            (0x09, if byzantium { None } else { pick(12, 264) }),
            (0x0b, bls_gas(375, 1_050)),
            (0x0c, bls_gas(12_000, 73_200)),
            (0x0d, bls_gas(600, 1_620)),
            (0x0e, bls_gas(22_500, 144_000)),
            (0x0f, bls_gas(37_700 + 32_600, 109_330 + 94_540)),
            (0x10, bls_gas(5_500, 15_400)),
            (0x11, bls_gas(23_800, 66_640)),
            (0x100, p256),
        ]
    }

    #[test]
    fn precompile_sets_match_bor() {
        for spec in PolygonHardfork::ALL {
            let probes = probes();
            for ((address, input), (expected_address, gas)) in probes.iter().zip(expected(spec)) {
                assert_eq!(*address, expected_address);
                assert_eq!(spent(spec, *address, input), gas, "{spec}: precompile {address:#x}");
            }
            let kzg = spec.enables(Madhugiri) && !spec.enables(LisovoPro);
            assert_eq!(polygon_precompile_map(spec).contains(&Address::with_last_byte(0x0a)), kzg);
            // No precompile beyond the probed addresses and KZG.
            let count = expected(spec).iter().filter(|(_, gas)| gas.is_some()).count();
            assert_eq!(polygon_precompile_map(spec).len(), count + usize::from(kzg), "{spec}");
        }
    }

    #[test]
    fn pip88_variable_pricing() {
        // Two G1 pairs use the 949 discount, three G2 pairs the 923 discount.
        assert_eq!(spent(Chicago, 0x0c, &[0; 320]), Some(2 * 73_200 * 949 / 1000));
        assert_eq!(spent(Chicago, 0x0e, &[0; 864]), Some(3 * 144_000 * 923 / 1000));
        assert_eq!(spent(Chicago, 0x0f, &[0; 768]), Some(109_330 + 2 * 94_540));
        assert_eq!(spent(Chicago, 0x08, &[0; 384]), Some(67_500 + 2 * 51_000));
        let mut blake2f = blake2f_input();
        blake2f[3] = 0;
        blake2f[2] = 1;
        assert_eq!(spent(Chicago, 0x09, &blake2f), Some(256 * 22));
    }

    #[test]
    fn pip88_charges_before_running() {
        let mut gas = GasTracker::new(PIP88_BLS12_G1_ADD_GAS - 1);
        assert!(pip88_bls12_g1_add_run(&[0; 256], &mut gas).is_err());
        let mut gas = GasTracker::new(PIP88_BLS12_G1_ADD_GAS);
        assert!(pip88_bls12_g1_add_run(&[0; 256], &mut gas).is_ok());
        assert_eq!(gas.remaining(), 0);
    }
}
