//! OP Stack precompiles.
//!
//! Port of `op-revm/src/precompiles.rs`, built on evm2's [`PrecompileMap`].

use crate::{OpEvmTypes, OpSpecId};
use alloy_primitives::Address;
use evm2::{
    Evm, PrecompileError, PrecompileHalt, Precompiles, SpecId,
    evm::precompile::{PrecompileOutput, PrecompileProvider},
    interpreter::{GasTracker, Message},
    precompiles::{
        MODEXP_OSAKA, MovePrecompileError, P256VERIFY, P256VERIFY_OSAKA, Precompile, PrecompileId,
        PrecompileMap, PrecompileResult, bls12_381, bn254,
    },
};
use std::{borrow::Cow, sync::OnceLock, vec::Vec};

/// Address of the bn254 pairing precompile.
const BN254_PAIR_ADDRESS: Address = Address::with_last_byte(0x08);
/// Address of the BLS12-381 G1 MSM precompile.
const BLS12_G1_MSM_ADDRESS: Address = Address::with_last_byte(0x0c);
/// Address of the BLS12-381 G2 MSM precompile.
const BLS12_G2_MSM_ADDRESS: Address = Address::with_last_byte(0x0e);
/// Address of the BLS12-381 pairing precompile.
const BLS12_PAIRING_ADDRESS: Address = Address::with_last_byte(0x0f);

/// Defines an [`OpEvmTypes`] precompile descriptor from an input-and-gas function.
macro_rules! op_precompile {
    ($(#[$attr:meta])* $vis:vis fn $name:ident = ($address:expr, $id:expr) => $f:path;) => {
        $(#[$attr])*
        #[allow(non_snake_case)]
        $vis fn $name() -> Precompile<OpEvmTypes> {
            fn run(
                evm: &mut Evm<'_, OpEvmTypes>,
                message: &Message<OpEvmTypes>,
                gas: &mut GasTracker,
            ) -> PrecompileResult {
                $f(evm.message_input(message), gas)
            }
            Precompile::new($address, $id, run)
        }
    };
}

/// bn254 pairing precompile with OP input-size limits.
pub mod bn254_pair {
    use super::*;

    /// Max input size for the bn254 pairing precompile since Granite.
    pub const GRANITE_MAX_INPUT_SIZE: usize = 112687;
    /// Max input size for the bn254 pairing precompile since Jovian.
    pub const JOVIAN_MAX_INPUT_SIZE: usize = 81_984;
    /// Max input size for the bn254 pairing precompile since Karst.
    pub const KARST_MAX_INPUT_SIZE: usize = 57_600;

    fn run_capped(input: &[u8], max: usize, gas: &mut GasTracker) -> PrecompileResult {
        if input.len() > max {
            return Err(PrecompileHalt::Bn254PairLength.into());
        }
        bn254::pair::run_istanbul(input, gas)
    }

    /// Runs the bn254 pairing precompile with the Granite input limit.
    pub fn run_pair_granite(input: &[u8], gas: &mut GasTracker) -> PrecompileResult {
        run_capped(input, GRANITE_MAX_INPUT_SIZE, gas)
    }

    /// Runs the bn254 pairing precompile with the Jovian input limit.
    pub fn run_pair_jovian(input: &[u8], gas: &mut GasTracker) -> PrecompileResult {
        run_capped(input, JOVIAN_MAX_INPUT_SIZE, gas)
    }

    /// Runs the bn254 pairing precompile with the Karst input limit.
    pub fn run_pair_karst(input: &[u8], gas: &mut GasTracker) -> PrecompileResult {
        run_capped(input, KARST_MAX_INPUT_SIZE, gas)
    }

    op_precompile! {
        /// Granite bn254 pairing precompile.
        pub fn GRANITE = (BN254_PAIR_ADDRESS, PrecompileId::Bn254Pairing) => run_pair_granite;
    }
    op_precompile! {
        /// Jovian bn254 pairing precompile.
        pub fn JOVIAN = (BN254_PAIR_ADDRESS, PrecompileId::Bn254Pairing) => run_pair_jovian;
    }
    op_precompile! {
        /// Karst bn254 pairing precompile.
        pub fn KARST = (BN254_PAIR_ADDRESS, PrecompileId::Bn254Pairing) => run_pair_karst;
    }
}

/// BLS12-381 precompiles with OP input-size limits.
pub mod bls12 {
    use super::*;

    /// Max input size for the G1 MSM precompile since Isthmus.
    pub const ISTHMUS_G1_MSM_MAX_INPUT_SIZE: usize = 513760;
    /// Max input size for the G1 MSM precompile since Jovian.
    pub const JOVIAN_G1_MSM_MAX_INPUT_SIZE: usize = 288_960;
    /// Max input size for the G2 MSM precompile since Isthmus.
    pub const ISTHMUS_G2_MSM_MAX_INPUT_SIZE: usize = 488448;
    /// Max input size for the G2 MSM precompile since Jovian.
    pub const JOVIAN_G2_MSM_MAX_INPUT_SIZE: usize = 278_784;
    /// Max input size for the pairing precompile since Isthmus.
    pub const ISTHMUS_PAIRING_MAX_INPUT_SIZE: usize = 235008;
    /// Max input size for the pairing precompile since Jovian.
    pub const JOVIAN_PAIRING_MAX_INPUT_SIZE: usize = 156_672;

    fn too_long(message: &'static str) -> PrecompileError {
        PrecompileHalt::Other(Cow::Borrowed(message)).into()
    }

    /// Runs the G1 MSM precompile with the Isthmus input limit.
    pub fn run_g1_msm_isthmus(input: &[u8], gas: &mut GasTracker) -> PrecompileResult {
        if input.len() > ISTHMUS_G1_MSM_MAX_INPUT_SIZE {
            return Err(too_long(
                "G1MSM input length too long for OP Stack input size limitation after the Isthmus Hardfork",
            ));
        }
        bls12_381::g1_msm::run(input, gas)
    }

    /// Runs the G1 MSM precompile with the Jovian input limit.
    pub fn run_g1_msm_jovian(input: &[u8], gas: &mut GasTracker) -> PrecompileResult {
        if input.len() > JOVIAN_G1_MSM_MAX_INPUT_SIZE {
            return Err(too_long(
                "G1MSM input length too long for OP Stack input size limitation after the Jovian Hardfork",
            ));
        }
        bls12_381::g1_msm::run(input, gas)
    }

    /// Runs the G2 MSM precompile with the Isthmus input limit.
    pub fn run_g2_msm_isthmus(input: &[u8], gas: &mut GasTracker) -> PrecompileResult {
        if input.len() > ISTHMUS_G2_MSM_MAX_INPUT_SIZE {
            return Err(too_long("G2MSM input length too long for OP Stack input size limitation"));
        }
        bls12_381::g2_msm::run(input, gas)
    }

    /// Runs the G2 MSM precompile with the Jovian input limit.
    pub fn run_g2_msm_jovian(input: &[u8], gas: &mut GasTracker) -> PrecompileResult {
        if input.len() > JOVIAN_G2_MSM_MAX_INPUT_SIZE {
            return Err(too_long(
                "G2MSM input length too long for OP Stack input size limitation after the Jovian Hardfork",
            ));
        }
        bls12_381::g2_msm::run(input, gas)
    }

    /// Runs the pairing precompile with the Isthmus input limit.
    pub fn run_pair_isthmus(input: &[u8], gas: &mut GasTracker) -> PrecompileResult {
        if input.len() > ISTHMUS_PAIRING_MAX_INPUT_SIZE {
            return Err(too_long(
                "Pairing input length too long for OP Stack input size limitation",
            ));
        }
        bls12_381::pairing::run(input, gas)
    }

    /// Runs the pairing precompile with the Jovian input limit.
    pub fn run_pair_jovian(input: &[u8], gas: &mut GasTracker) -> PrecompileResult {
        if input.len() > JOVIAN_PAIRING_MAX_INPUT_SIZE {
            return Err(too_long(
                "Pairing input length too long for OP Stack input size limitation after the Jovian Hardfork",
            ));
        }
        bls12_381::pairing::run(input, gas)
    }

    op_precompile! {
        /// Isthmus G1 MSM precompile.
        pub fn ISTHMUS_G1_MSM = (BLS12_G1_MSM_ADDRESS, PrecompileId::Bls12G1Msm) => run_g1_msm_isthmus;
    }
    op_precompile! {
        /// Isthmus G2 MSM precompile.
        pub fn ISTHMUS_G2_MSM = (BLS12_G2_MSM_ADDRESS, PrecompileId::Bls12G2Msm) => run_g2_msm_isthmus;
    }
    op_precompile! {
        /// Isthmus pairing precompile.
        pub fn ISTHMUS_PAIRING = (BLS12_PAIRING_ADDRESS, PrecompileId::Bls12Pairing) => run_pair_isthmus;
    }
    op_precompile! {
        /// Jovian G1 MSM precompile.
        pub fn JOVIAN_G1_MSM = (BLS12_G1_MSM_ADDRESS, PrecompileId::Bls12G1Msm) => run_g1_msm_jovian;
    }
    op_precompile! {
        /// Jovian G2 MSM precompile.
        pub fn JOVIAN_G2_MSM = (BLS12_G2_MSM_ADDRESS, PrecompileId::Bls12G2Msm) => run_g2_msm_jovian;
    }
    op_precompile! {
        /// Jovian pairing precompile.
        pub fn JOVIAN_PAIRING = (BLS12_PAIRING_ADDRESS, PrecompileId::Bls12Pairing) => run_pair_jovian;
    }
}

/// Returns the precompile map for `spec`, built exactly like op-revm's per-fork sets.
pub fn op_precompile_map(spec: OpSpecId) -> PrecompileMap<OpEvmTypes> {
    let base = |spec: SpecId| Precompiles::<OpEvmTypes>::base(spec).as_map().clone();
    match spec {
        OpSpecId::BEDROCK | OpSpecId::REGOLITH | OpSpecId::CANYON | OpSpecId::ECOTONE => {
            base(spec.into_eth_spec())
        }
        OpSpecId::FJORD => {
            // RIP-7212 secp256r1 P256VERIFY on top of Cancun.
            base(SpecId::CANCUN).with_extended_precompiles([P256VERIFY()])
        }
        OpSpecId::GRANITE | OpSpecId::HOLOCENE => {
            op_precompile_map(OpSpecId::FJORD).with_extended_precompiles([bn254_pair::GRANITE()])
        }
        OpSpecId::ISTHMUS => {
            // Prague BLS12-381 precompiles, with OP input limits on the variable-input ones.
            let prague = base(SpecId::PRAGUE);
            let prague_bls = [0x0bu8, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11]
                .map(|byte| prague.get(&Address::with_last_byte(byte)).expect("prague bls12"));
            op_precompile_map(OpSpecId::GRANITE)
                .with_extended_precompiles(prague_bls)
                .with_extended_precompiles([
                    bls12::ISTHMUS_G1_MSM(),
                    bls12::ISTHMUS_G2_MSM(),
                    bls12::ISTHMUS_PAIRING(),
                ])
        }
        OpSpecId::JOVIAN => op_precompile_map(OpSpecId::ISTHMUS).with_extended_precompiles([
            bn254_pair::JOVIAN(),
            bls12::JOVIAN_G1_MSM(),
            bls12::JOVIAN_G2_MSM(),
            bls12::JOVIAN_PAIRING(),
        ]),
        OpSpecId::KARST | OpSpecId::LAGOON => op_precompile_map(OpSpecId::JOVIAN)
            .with_extended_precompiles([MODEXP_OSAKA(), P256VERIFY_OSAKA(), bn254_pair::KARST()]),
    }
}

/// Returns a process-wide cached precompile map for `spec`.
fn cached_precompile_map(spec: OpSpecId) -> &'static PrecompileMap<OpEvmTypes> {
    static CACHE: [OnceLock<PrecompileMap<OpEvmTypes>>; OpSpecId::ALL.len()] =
        [const { OnceLock::new() }; OpSpecId::ALL.len()];
    let index = (spec as u8 - OpSpecId::BEDROCK as u8) as usize;
    CACHE[index].get_or_init(|| op_precompile_map(spec))
}

/// OP precompile provider.
///
/// Wraps an evm2 [`Precompiles`] map selected per [`OpSpecId`].
#[derive(Clone, Debug)]
pub struct OpPrecompiles {
    inner: Precompiles<OpEvmTypes>,
    spec: OpSpecId,
}

impl OpPrecompiles {
    /// Creates the precompile provider for `spec`.
    pub fn new(spec: OpSpecId) -> Self {
        Self { inner: Precompiles::new(Cow::Borrowed(cached_precompile_map(spec))), spec }
    }

    /// Returns the hardfork these precompiles were selected for.
    pub const fn spec(&self) -> OpSpecId {
        self.spec
    }

    /// Returns the underlying precompile map.
    pub fn as_map(&self) -> &PrecompileMap<OpEvmTypes> {
        self.inner.as_map()
    }

    /// Returns the underlying precompile map mutably, cloning the shared map on first write.
    pub fn as_map_mut(&mut self) -> &mut PrecompileMap<OpEvmTypes> {
        self.inner.as_map_mut()
    }
}

impl Default for OpPrecompiles {
    fn default() -> Self {
        Self::new(OpSpecId::default())
    }
}

impl PrecompileProvider<OpEvmTypes> for OpPrecompiles {
    fn addresses(&self) -> Vec<Address> {
        self.inner.addresses()
    }

    fn precompile_ids(&self) -> Vec<(Address, PrecompileId)> {
        self.inner.precompile_ids()
    }

    fn contains(&self, address: &Address) -> bool {
        self.inner.contains(address)
    }

    fn move_precompiles(
        &mut self,
        moves: &[(Address, Address)],
    ) -> Result<(), MovePrecompileError> {
        self.inner.move_precompiles(moves)
    }

    fn execute(
        &mut self,
        evm: &mut Evm<'_, OpEvmTypes>,
        message: &Message<OpEvmTypes>,
        gas: &mut GasTracker,
    ) -> Option<Result<PrecompileOutput, PrecompileError>> {
        self.inner.execute(evm, message, gas)
    }
}

#[cfg(test)]
mod tests {
    //! Vectors from op-revm's `precompiles.rs` tests.

    use super::*;
    use alloy_primitives::{Bytes, hex};

    const BN254_PAIR_ELEMENT_LEN: usize = 192;

    /// EIP-197 pairing vector whose product is the identity.
    const BN254_PAIR_IDENTITY_INPUT: [u8; 384] = hex!(
        "2cf44499d5d27bb186308b7af7af02ac5bc9eeb6a3d147c186b21fb1b76e18da2c0f001f52110ccfe69108924926e45f0b0c868df0e7bde1fe16d3242dc715f61fb19bb476f6b9e44e2a32234da8212f61cd63919354bc06aef31e3cfaff3ebc22606845ff186793914e03e21df544c34ffe2f2f3504de8a79d9159eca2d98d92bd368e28381e8eccb5fa81fc26cf3f048eea9abfdd85d7ed3ab3698d63e4f902fe02e47887507adf0ff1743cbac6ba291e66f59be6bd763950bb16041a0a85e000000000000000000000000000000000000000000000000000000000000000130644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd451971ff0471b09fa93caaf13cbf443c1aede09cc4328f5a62aad45f40ec133eb4091058a3141822985733cbdddfed0fd8d6c104e9e9eff40bf5abfef9ab163bc72a23af9a5ce2ba2796c1f4e453a370eb0af8c212d9dc9acd8fc02c2e907baea223a8eb0b0996252cb548a4487da97b02422ebc0e834613f954de6c7e0afdc1fc"
    );

    fn is_halt(result: &PrecompileResult, expected: &PrecompileHalt) -> bool {
        matches!(result, Err(PrecompileError::Halt(halt)) if halt == expected)
    }

    fn is_too_long(result: &PrecompileResult) -> bool {
        matches!(
            result,
            Err(PrecompileError::Halt(PrecompileHalt::Other(msg))) if msg.contains("input length too long")
        )
    }

    #[test]
    fn bn254_pair_granite_limits() {
        let mut gas = GasTracker::new(260_000);
        let ok = bn254_pair::run_pair_granite(&BN254_PAIR_IDENTITY_INPUT, &mut gas).unwrap();
        assert_eq!(ok.bytes()[31], 1);

        // Within the cap but not enough gas.
        let input = vec![1u8; 586 * BN254_PAIR_ELEMENT_LEN];
        let res = bn254_pair::run_pair_granite(&input, &mut GasTracker::new(260_000));
        assert!(res.as_ref().is_err_and(PrecompileError::is_oog), "{res:?}");

        // Over the cap.
        let input = vec![1u8; 587 * BN254_PAIR_ELEMENT_LEN];
        let res = bn254_pair::run_pair_granite(&input, &mut GasTracker::new(260_000));
        assert!(is_halt(&res, &PrecompileHalt::Bn254PairLength));
    }

    /// Runs the precompile installed at `address` for `spec` through an OP EVM.
    fn run_installed(spec: OpSpecId, address: Address, input: &[u8]) -> PrecompileResult {
        let factory = crate::OpEvmFactory;
        let mut evm = factory.create_evm(
            spec,
            factory.version(spec, 10),
            Default::default(),
            evm2::evm::InMemoryDB::default(),
        );
        let precompile = op_precompile_map(spec).get(&address).expect("installed");
        let message = Message::<OpEvmTypes> {
            input: Bytes::copy_from_slice(input).into(),
            code_address: address,
            ..Default::default()
        };
        precompile.run()(&mut evm, &message, &mut GasTracker::new(u64::MAX))
    }

    #[test]
    fn spec_sets_select_capped_pairing() {
        let pair = |spec, len| run_installed(spec, BN254_PAIR_ADDRESS, &vec![0u8; len]);
        let length = PrecompileHalt::Bn254PairLength;
        let len = |max: usize| (max + 1).next_multiple_of(BN254_PAIR_ELEMENT_LEN);

        // Uncapped before Granite: an all-zero input of any multiple of 192 bytes is valid.
        assert!(pair(OpSpecId::FJORD, len(bn254_pair::GRANITE_MAX_INPUT_SIZE)).is_ok());
        for spec in [OpSpecId::GRANITE, OpSpecId::HOLOCENE, OpSpecId::ISTHMUS] {
            assert!(is_halt(&pair(spec, len(bn254_pair::GRANITE_MAX_INPUT_SIZE)), &length));
            assert!(pair(spec, len(bn254_pair::JOVIAN_MAX_INPUT_SIZE)).is_ok());
        }
        assert!(is_halt(&pair(OpSpecId::JOVIAN, len(bn254_pair::JOVIAN_MAX_INPUT_SIZE)), &length));
        assert!(pair(OpSpecId::JOVIAN, len(bn254_pair::KARST_MAX_INPUT_SIZE)).is_ok());
        for spec in [OpSpecId::KARST, OpSpecId::LAGOON] {
            assert!(is_halt(&pair(spec, len(bn254_pair::KARST_MAX_INPUT_SIZE)), &length));
            let ok = run_installed(spec, BN254_PAIR_ADDRESS, &BN254_PAIR_IDENTITY_INPUT);
            assert_eq!(ok.unwrap().bytes()[31], 1);
        }

        // BLS12-381 G1 MSM caps through the installed precompiles.
        let g1 = |spec, len| run_installed(spec, BLS12_G1_MSM_ADDRESS, &vec![0u8; len]);
        assert!(is_too_long(&g1(OpSpecId::ISTHMUS, bls12::ISTHMUS_G1_MSM_MAX_INPUT_SIZE + 160)));
        assert!(!is_too_long(&g1(OpSpecId::ISTHMUS, bls12::JOVIAN_G1_MSM_MAX_INPUT_SIZE + 160)));
        assert!(is_too_long(&g1(OpSpecId::JOVIAN, bls12::JOVIAN_G1_MSM_MAX_INPUT_SIZE + 160)));
    }

    #[test]
    fn bls12_limits() {
        let gas = || GasTracker::new(u64::MAX);
        assert!(is_too_long(&bls12::run_g1_msm_isthmus(
            &vec![0u8; bls12::ISTHMUS_G1_MSM_MAX_INPUT_SIZE + 1],
            &mut gas()
        )));
        assert!(is_too_long(&bls12::run_g1_msm_jovian(
            &vec![0u8; bls12::JOVIAN_G1_MSM_MAX_INPUT_SIZE + 1],
            &mut gas()
        )));
        assert!(is_too_long(&bls12::run_g2_msm_isthmus(
            &vec![0u8; bls12::ISTHMUS_G2_MSM_MAX_INPUT_SIZE + 1],
            &mut gas()
        )));
        assert!(is_too_long(&bls12::run_g2_msm_jovian(
            &vec![0u8; bls12::JOVIAN_G2_MSM_MAX_INPUT_SIZE + 1],
            &mut gas()
        )));
        assert!(is_too_long(&bls12::run_pair_isthmus(
            &vec![0u8; bls12::ISTHMUS_PAIRING_MAX_INPUT_SIZE + 1],
            &mut gas()
        )));
        assert!(is_too_long(&bls12::run_pair_jovian(
            &vec![0u8; bls12::JOVIAN_PAIRING_MAX_INPUT_SIZE + 1],
            &mut gas()
        )));
        // A Jovian-oversized input that fits the Isthmus cap is not rejected by the length check.
        let res = bls12::run_g1_msm_isthmus(
            &vec![0u8; bls12::JOVIAN_G1_MSM_MAX_INPUT_SIZE + 160],
            &mut gas(),
        );
        assert!(!is_too_long(&res));
    }

    #[test]
    fn precompile_sets_per_fork() {
        let addrs = |spec| {
            let mut v: Vec<_> = op_precompile_map(spec).addresses().collect();
            v.sort();
            v
        };
        let base = |spec| {
            let mut v: Vec<_> =
                Precompiles::<OpEvmTypes>::base(spec).as_map().addresses().collect();
            v.sort();
            v
        };
        let p256 = P256VERIFY::<OpEvmTypes>().address();

        assert_eq!(addrs(OpSpecId::BEDROCK), base(SpecId::MERGE));
        assert_eq!(addrs(OpSpecId::ECOTONE), base(SpecId::CANCUN));
        // Fjord = Cancun + P256VERIFY.
        let mut fjord = base(SpecId::CANCUN);
        fjord.push(p256);
        fjord.sort();
        assert_eq!(addrs(OpSpecId::FJORD), fjord);
        assert_eq!(addrs(OpSpecId::GRANITE), fjord);
        // Isthmus = Prague + P256VERIFY, Karst = Osaka.
        let mut isthmus = base(SpecId::PRAGUE);
        isthmus.push(p256);
        isthmus.sort();
        assert_eq!(addrs(OpSpecId::ISTHMUS), isthmus);
        assert_eq!(addrs(OpSpecId::JOVIAN), isthmus);
        assert_eq!(addrs(OpSpecId::KARST), base(SpecId::OSAKA));
        assert_eq!(OpPrecompiles::new(OpSpecId::KARST).spec(), OpSpecId::KARST);
    }
}
