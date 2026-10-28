//! Celo precompiles: the OP precompile sets plus the CELO transfer precompile.

use crate::{CELO_TOKEN_ADDRESS, CeloEvm, CeloEvmTypes};
use alloy_primitives::{Address, U256};
use evm2::{
    Precompiles, SpecId,
    evm::precompile::PrecompileOutput,
    interpreter::{GasTracker, Message, MessageKind},
    precompiles::{
        MODEXP_OSAKA, P256VERIFY, P256VERIFY_OSAKA, Precompile, PrecompileHalt, PrecompileId,
        PrecompileMap, PrecompileResult, define_precompiles,
    },
};
use op_evm2::{
    OpSpecId,
    precompiles::{bls12, bn254_pair},
};
use std::borrow::Cow;

/// Address of the transfer precompile.
pub const CELO_TRANSFER_ADDRESS: Address = Address::with_last_byte(0xfd);

/// Gas cost of the transfer precompile.
pub const CELO_TRANSFER_GAS: u64 = 9_000;

/// Identifier of the transfer precompile.
pub const CELO_TRANSFER_ID: &str = "CeloTransfer";

define_precompiles! {
    const BN254_PAIR_GRANITE = (Address::with_last_byte(0x08), PrecompileId::Bn254Pairing) => bn254_pair::run_pair_granite;
    const BN254_PAIR_JOVIAN = (Address::with_last_byte(0x08), PrecompileId::Bn254Pairing) => bn254_pair::run_pair_jovian;
    const BN254_PAIR_KARST = (Address::with_last_byte(0x08), PrecompileId::Bn254Pairing) => bn254_pair::run_pair_karst;
    const G1_MSM_ISTHMUS = (Address::with_last_byte(0x0c), PrecompileId::Bls12G1Msm) => bls12::run_g1_msm_isthmus;
    const G1_MSM_JOVIAN = (Address::with_last_byte(0x0c), PrecompileId::Bls12G1Msm) => bls12::run_g1_msm_jovian;
    const G2_MSM_ISTHMUS = (Address::with_last_byte(0x0e), PrecompileId::Bls12G2Msm) => bls12::run_g2_msm_isthmus;
    const G2_MSM_JOVIAN = (Address::with_last_byte(0x0e), PrecompileId::Bls12G2Msm) => bls12::run_g2_msm_jovian;
    const BLS12_PAIRING_ISTHMUS = (Address::with_last_byte(0x0f), PrecompileId::Bls12Pairing) => bls12::run_pair_isthmus;
    const BLS12_PAIRING_JOVIAN = (Address::with_last_byte(0x0f), PrecompileId::Bls12Pairing) => bls12::run_pair_jovian;
}

/// Returns the OP precompile map for `spec`, like op-evm2's `op_precompile_map`.
fn op_precompile_map(spec: OpSpecId) -> PrecompileMap<CeloEvmTypes> {
    let base = |spec: SpecId| Precompiles::<CeloEvmTypes>::base(spec).as_map().clone();
    match spec {
        OpSpecId::BEDROCK | OpSpecId::REGOLITH | OpSpecId::CANYON | OpSpecId::ECOTONE => {
            base(spec.into_eth_spec())
        }
        OpSpecId::FJORD => base(SpecId::CANCUN).with_extended_precompiles([P256VERIFY()]),
        OpSpecId::GRANITE | OpSpecId::HOLOCENE => {
            op_precompile_map(OpSpecId::FJORD).with_extended_precompiles([BN254_PAIR_GRANITE()])
        }
        OpSpecId::ISTHMUS => {
            let prague = base(SpecId::PRAGUE);
            let prague_bls = [0x0bu8, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11]
                .map(|byte| prague.get(&Address::with_last_byte(byte)).expect("prague bls12"));
            op_precompile_map(OpSpecId::GRANITE)
                .with_extended_precompiles(prague_bls)
                .with_extended_precompiles([
                    G1_MSM_ISTHMUS(),
                    G2_MSM_ISTHMUS(),
                    BLS12_PAIRING_ISTHMUS(),
                ])
        }
        OpSpecId::JOVIAN => op_precompile_map(OpSpecId::ISTHMUS).with_extended_precompiles([
            BN254_PAIR_JOVIAN(),
            G1_MSM_JOVIAN(),
            G2_MSM_JOVIAN(),
            BLS12_PAIRING_JOVIAN(),
        ]),
        OpSpecId::KARST | OpSpecId::LAGOON => op_precompile_map(OpSpecId::JOVIAN)
            .with_extended_precompiles([MODEXP_OSAKA(), P256VERIFY_OSAKA(), BN254_PAIR_KARST()]),
    }
}

/// Returns the Celo precompiles for `spec`: the OP set plus the transfer precompile.
pub fn celo_precompiles(spec: OpSpecId) -> Precompiles<CeloEvmTypes> {
    let map = op_precompile_map(spec).with_extended_precompiles([Precompile::new(
        CELO_TRANSFER_ADDRESS,
        PrecompileId::custom(CELO_TRANSFER_ID),
        celo_transfer_run,
    )]);
    Precompiles::new(Cow::Owned(map))
}

/// The transfer precompile, which moves native CELO for the CELO token.
///
/// Input is `from | to | value`, 32 bytes each. It costs [`CELO_TRANSFER_GAS`] and halts in a
/// static context, when the caller is not the CELO token, on malformed input, or when `from`
/// cannot afford `value`. Before Jovian the transfer leaves the warmth of `from` and `to`
/// unchanged; from Jovian it warms them.
pub fn celo_transfer_run(
    evm: &mut CeloEvm<'_>,
    message: &Message<CeloEvmTypes>,
    gas: &mut GasTracker,
) -> PrecompileResult {
    let halt = |reason| Err(PrecompileHalt::Other(Cow::Borrowed(reason)).into());
    if message.kind == MessageKind::StaticCall || message.caller_is_static {
        return halt("transfer precompile cannot be called in static context");
    }
    if message.gas_limit < CELO_TRANSFER_GAS {
        return Err(PrecompileHalt::OutOfGas.into());
    }
    if message.caller != CELO_TOKEN_ADDRESS {
        return halt("invalid caller for transfer precompile");
    }
    let input = message.input.as_ref();
    if input.len() != 96 {
        return halt("invalid input length");
    }
    let from = Address::from_slice(&input[12..32]);
    let to = Address::from_slice(&input[44..64]);
    let value = U256::from_be_slice(&input[64..96]);

    if !evm.state_mut().transfer(&from, &to, &value)? {
        return halt("transfer error occurred: insufficient balance");
    }
    if evm.config_spec_id().is_enabled_in(OpSpecId::JOVIAN) {
        // celo-revm's transfer loads both accounts, which warms them.
        evm.state_mut().account(&from)?.warm();
        evm.state_mut().account(&to)?.warm();
    }
    gas.spend(CELO_TRANSFER_GAS)?;
    Ok(PrecompileOutput::new(Default::default()))
}
