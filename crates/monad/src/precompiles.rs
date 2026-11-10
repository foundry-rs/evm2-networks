//! Monad precompiles.
//!
//! Port of `monad-revm` `precompiles.rs`. Monad reprices several precompiles and adds the staking
//! and reserve-balance precompiles.
//!
//! | Precompile  | Address | Ethereum | Monad    | Notes                     |
//! |-------------|---------|----------|----------|---------------------------|
//! | ecRecover   | 0x01    | 3,000    | 6,000    | 2x                        |
//! | ecAdd       | 0x06    | 150      | 300      | 2x                        |
//! | ecMul       | 0x07    | 6,000    | 30,000   | 5x                        |
//! | ecPairing   | 0x08    | 45,000*  | 225,000* | 5x                        |
//! | blake2f     | 0x09    | rounds×1 | rounds×2 | 2x                        |
//! | point eval  | 0x0a    | 50,000   | 200,000  | 4x                        |
//! | P256VERIFY  | 0x0100  | 6,900    | 6,900    | Enabled in MonadEight+    |
//! | staking     | 0x1000  | N/A      | varies   | Monad-only                |
//! | reserve     | 0x1001  | N/A      | 100      | Monad-only, MonadNine+    |
//!
//! *Base cost per operation.

use crate::{
    MonadEvmTypes, MonadHardfork,
    reserve_balance::{RESERVE_BALANCE_ADDRESS, run_reserve_balance_precompile},
    staking::{STAKING_ADDRESS, run_staking_precompile},
};
use alloc::borrow::Cow;
use alloy_primitives::{Address, B256, B512, Bytes};
use evm2::{
    Evm, Precompiles, crypto,
    evm::precompile::{PrecompileOutput, PrecompileProvider},
    interpreter::{GasTracker, Message},
    precompiles::{
        MovePrecompileError, P256VERIFY_OSAKA, Precompile, PrecompileHalt, PrecompileId,
        PrecompileMap, PrecompileResult, bn254,
    },
};

/// Monad ecRecover gas cost (2x Ethereum's 3000).
pub const MONAD_ECRECOVER_GAS: u64 = 6_000;

/// Monad ecAdd gas cost (2x Ethereum's 150).
pub const MONAD_EC_ADD_GAS: u64 = 300;

/// Monad ecMul gas cost (5x Ethereum's 6000).
pub const MONAD_EC_MUL_GAS: u64 = 30_000;

/// Monad ecPairing base gas cost (5x Ethereum's 45000).
pub const MONAD_EC_PAIRING_BASE_GAS: u64 = 225_000;

/// Monad ecPairing per-point gas cost (5x Ethereum's 34000).
pub const MONAD_EC_PAIRING_PER_POINT_GAS: u64 = 170_000;

/// Monad blake2f gas per round (2x Ethereum's 1).
pub const MONAD_BLAKE2F_ROUND_GAS: u64 = 2;

/// Monad KZG point evaluation gas cost (4x Ethereum's 50000).
pub const MONAD_POINT_EVALUATION_GAS: u64 = 200_000;

/// Identifier of the native staking precompile.
pub const MONAD_STAKING_ID: &str = "MonadStaking";

/// Identifier of the native reserve-balance precompile.
pub const MONAD_RESERVE_BALANCE_ID: &str = "MonadReserveBalance";

const fn u64_to_address(x: u64) -> Address {
    let x = x.to_be_bytes();
    Address::new([
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, x[0], x[1], x[2], x[3], x[4], x[5], x[6], x[7],
    ])
}

fn right_pad<const N: usize>(input: &[u8]) -> [u8; N] {
    let mut padded = [0u8; N];
    let len = input.len().min(N);
    padded[..len].copy_from_slice(&input[..len]);
    padded
}

/// Monad ecRecover precompile.
pub fn monad_ecrecover_run(input: &[u8], gas: &mut GasTracker) -> PrecompileResult {
    gas.spend(MONAD_ECRECOVER_GAS)?;

    let input = right_pad::<128>(input);

    // `v` must be a 32-byte big-endian integer equal to 27 or 28.
    if !(input[32..63].iter().all(|&b| b == 0) && matches!(input[63], 27 | 28)) {
        return Ok(PrecompileOutput::new(Bytes::new()));
    }

    let msg = <&B256>::try_from(&input[0..32]).expect("32 bytes");
    let recid = input[63] - 27;
    let sig = <&B512>::try_from(&input[64..128]).expect("64 bytes");

    let res = crypto().secp256k1_ecrecover(&sig.0, recid, &msg.0).ok();
    let out = res.map(|o| o.to_vec().into()).unwrap_or_default();
    Ok(PrecompileOutput::new(out))
}

/// Monad ecAdd precompile.
pub fn monad_ec_add_run(input: &[u8], gas: &mut GasTracker) -> PrecompileResult {
    bn254::run_add(input, MONAD_EC_ADD_GAS, gas)
}

/// Monad ecMul precompile.
pub fn monad_ec_mul_run(input: &[u8], gas: &mut GasTracker) -> PrecompileResult {
    bn254::run_mul(input, MONAD_EC_MUL_GAS, gas)
}

/// Monad ecPairing precompile.
pub fn monad_ec_pairing_run(input: &[u8], gas: &mut GasTracker) -> PrecompileResult {
    bn254::run_pair(input, MONAD_EC_PAIRING_PER_POINT_GAS, MONAD_EC_PAIRING_BASE_GAS, gas)
}

/// Monad blake2f precompile.
pub fn monad_blake2f_run(input: &[u8], gas: &mut GasTracker) -> PrecompileResult {
    const INPUT_LENGTH: usize = 213;

    if input.len() != INPUT_LENGTH {
        return Err(PrecompileHalt::Blake2WrongLength.into());
    }

    let rounds = u32::from_be_bytes(input[..4].try_into().expect("4 bytes"));
    gas.spend(u64::from(rounds) * MONAD_BLAKE2F_ROUND_GAS)?;

    let f = match input[212] {
        0 => false,
        1 => true,
        _ => return Err(PrecompileHalt::Blake2WrongFinalIndicatorFlag.into()),
    };

    let mut h = [0u64; 8];
    for (i, chunk) in input[4..68].as_chunks::<8>().0.iter().enumerate() {
        h[i] = u64::from_le_bytes(*chunk);
    }
    let mut m = [0u64; 16];
    for (i, chunk) in input[68..196].as_chunks::<8>().0.iter().enumerate() {
        m[i] = u64::from_le_bytes(*chunk);
    }
    let t_0 = u64::from_le_bytes(input[196..204].try_into().expect("8 bytes"));
    let t_1 = u64::from_le_bytes(input[204..212].try_into().expect("8 bytes"));

    crypto().blake2_compress(rounds, &mut h, &m, &[t_0, t_1], f);

    let mut out = [0u8; 64];
    for (i, h) in (0..64).step_by(8).zip(h.iter()) {
        out[i..i + 8].copy_from_slice(&h.to_le_bytes());
    }
    Ok(PrecompileOutput::new(out.into()))
}

/// `U256(FIELD_ELEMENTS_PER_BLOB).to_be_bytes() ++ BLS_MODULUS.to_bytes32()`.
const POINT_EVALUATION_RETURN_VALUE: [u8; 64] = alloy_primitives::hex!(
    "0000000000000000000000000000000000000000000000000000000000001000"
    "73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001"
);

/// Monad KZG point evaluation precompile.
pub fn monad_point_evaluation_run(input: &[u8], gas: &mut GasTracker) -> PrecompileResult {
    gas.spend(MONAD_POINT_EVALUATION_GAS)?;

    if input.len() != 192 {
        return Err(PrecompileHalt::BlobInvalidInputLength.into());
    }

    // Verify the commitment matches the versioned hash.
    let versioned_hash = &input[..32];
    let commitment = &input[96..144];
    let mut expected = crypto().sha256(commitment);
    expected[0] = 0x01;
    if expected[..] != versioned_hash[..] {
        return Err(PrecompileHalt::BlobMismatchedVersion.into());
    }

    let commitment: &[u8; 48] = commitment.try_into().expect("48 bytes");
    let z = input[32..64].try_into().expect("32 bytes");
    let y = input[64..96].try_into().expect("32 bytes");
    let proof = input[144..192].try_into().expect("48 bytes");
    crypto().verify_kzg_proof(z, y, commitment, proof)?;

    Ok(PrecompileOutput::new(Bytes::from_static(&POINT_EVALUATION_RETURN_VALUE)))
}

macro_rules! input_precompile {
    ($name:ident => $f:path) => {
        fn $name(
            evm: &mut Evm<'_, MonadEvmTypes>,
            message: &Message<MonadEvmTypes>,
            gas: &mut GasTracker,
        ) -> PrecompileResult {
            $f(evm.message_input(message), gas)
        }
    };
}

input_precompile!(ecrecover_entry => monad_ecrecover_run);
input_precompile!(ec_add_entry => monad_ec_add_run);
input_precompile!(ec_mul_entry => monad_ec_mul_run);
input_precompile!(ec_pairing_entry => monad_ec_pairing_run);
input_precompile!(blake2f_entry => monad_blake2f_run);
input_precompile!(point_evaluation_entry => monad_point_evaluation_run);

/// Returns the Monad precompile map for `spec`.
pub fn monad_precompile_map(spec: MonadHardfork) -> PrecompileMap<MonadEvmTypes> {
    let mut map = Precompiles::<MonadEvmTypes>::base(spec.into_eth_spec()).as_map().clone();
    map.extend([
        Precompile::new(u64_to_address(0x01), PrecompileId::EcRec, ecrecover_entry),
        Precompile::new(u64_to_address(0x06), PrecompileId::Bn254Add, ec_add_entry),
        Precompile::new(u64_to_address(0x07), PrecompileId::Bn254Mul, ec_mul_entry),
        Precompile::new(u64_to_address(0x08), PrecompileId::Bn254Pairing, ec_pairing_entry),
        Precompile::new(u64_to_address(0x09), PrecompileId::Blake2F, blake2f_entry),
        Precompile::new(
            u64_to_address(0x0a),
            PrecompileId::KzgPointEvaluation,
            point_evaluation_entry,
        ),
        // P256VERIFY (RIP-7212 / EIP-7951) with Osaka pricing in every Monad hardfork.
        P256VERIFY_OSAKA(),
        Precompile::new(
            STAKING_ADDRESS,
            PrecompileId::custom(MONAD_STAKING_ID),
            run_staking_precompile,
        ),
    ]);
    if MonadHardfork::MonadNine.is_enabled_in(spec) {
        map.insert(Precompile::new(
            RESERVE_BALANCE_ADDRESS,
            PrecompileId::custom(MONAD_RESERVE_BALANCE_ID),
            run_reserve_balance_precompile,
        ));
    }
    map
}

/// Monad precompile provider.
#[derive(Clone, Debug)]
pub struct MonadPrecompiles {
    spec: MonadHardfork,
    inner: Precompiles<MonadEvmTypes>,
}

impl MonadPrecompiles {
    /// Creates the precompile provider for `spec`.
    pub fn new(spec: MonadHardfork) -> Self {
        Self { spec, inner: Precompiles::new(Cow::Owned(monad_precompile_map(spec))) }
    }

    /// Returns the hardfork this provider was built for.
    pub const fn spec(&self) -> MonadHardfork {
        self.spec
    }

    /// Returns the underlying precompile map.
    pub fn as_map(&self) -> &PrecompileMap<MonadEvmTypes> {
        self.inner.as_map()
    }

    /// Returns the underlying precompile map mutably.
    pub fn as_map_mut(&mut self) -> &mut PrecompileMap<MonadEvmTypes> {
        self.inner.as_map_mut()
    }
}

impl Default for MonadPrecompiles {
    fn default() -> Self {
        Self::new(MonadHardfork::default())
    }
}

impl PrecompileProvider<MonadEvmTypes> for MonadPrecompiles {
    fn addresses(&self) -> Vec<Address> {
        self.inner.addresses()
    }

    fn precompile_ids(&self) -> Vec<(Address, PrecompileId)> {
        self.inner.precompile_ids()
    }

    fn contains(&self, address: &Address) -> bool {
        self.inner.contains(address)
    }

    /// Relocates precompiles. The native staking and reserve-balance precompiles are bound to
    /// their protocol addresses and cannot be moved.
    fn move_precompiles(
        &mut self,
        moves: &[(Address, Address)],
    ) -> Result<(), MovePrecompileError> {
        if let Some((source, _)) = moves.iter().find(|(source, dest)| {
            source != dest && (*source == STAKING_ADDRESS || *source == RESERVE_BALANCE_ADDRESS)
        }) {
            return Err(MovePrecompileError::NotAPrecompile(*source));
        }
        self.inner.move_precompiles(moves)
    }

    fn execute(
        &mut self,
        evm: &mut Evm<'_, MonadEvmTypes>,
        message: &Message<MonadEvmTypes>,
        gas: &mut GasTracker,
    ) -> Option<PrecompileResult> {
        self.inner.execute(evm, message, gas)
    }
}
