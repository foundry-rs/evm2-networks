//! Base precompiles.

use alloy_primitives::{Address, address};
use base_common_eip8130::NonceManagerSlots;
use base_common_genesis::BaseUpgrade;
use evm2::{
    Evm, Precompiles,
    evm::precompile::{PrecompileOutput, PrecompileProvider},
    interpreter::{GasTracker, Message},
    precompiles::{
        MovePrecompileError, P256VERIFY, Precompile, PrecompileError, PrecompileHalt, PrecompileId,
        PrecompileResult, bls12_381, bn254,
    },
};

use crate::{
    BaseEvmTypes, BaseSpecId,
    activation::{ACTIVATION_REGISTRY_ID, run_activation_registry},
    beryl::{
        B20_FACTORY_ID, POLICY_REGISTRY_ID, b20_token_variant, run_b20_factory, run_b20_token,
        run_policy_registry,
    },
    eip8130::run_root,
    nonce::run_nonce_manager,
    tx_context::run_tx_context,
};

/// The bn254 pairing precompile address.
pub const BN254_PAIR_ADDRESS: Address = address!("0x0000000000000000000000000000000000000008");
/// The BLS12-381 G1 MSM precompile address.
pub const BLS12_G1_MSM_ADDRESS: Address = address!("0x000000000000000000000000000000000000000c");
/// The BLS12-381 G2 MSM precompile address.
pub const BLS12_G2_MSM_ADDRESS: Address = address!("0x000000000000000000000000000000000000000e");
/// The BLS12-381 pairing precompile address.
pub const BLS12_PAIRING_ADDRESS: Address = address!("0x000000000000000000000000000000000000000f");

/// Granite bn254 pairing input cap, in bytes.
pub const BN254_PAIR_GRANITE_MAX_INPUT_SIZE: usize = 112_687;
/// Jovian bn254 pairing input cap, in bytes.
pub const BN254_PAIR_JOVIAN_MAX_INPUT_SIZE: usize = 81_984;
/// Isthmus BLS12-381 G1 MSM input cap, in bytes.
pub const BLS12_G1_MSM_ISTHMUS_MAX_INPUT_SIZE: usize = 513_760;
/// Jovian BLS12-381 G1 MSM input cap, in bytes.
pub const BLS12_G1_MSM_JOVIAN_MAX_INPUT_SIZE: usize = 288_960;
/// Isthmus BLS12-381 G2 MSM input cap, in bytes.
pub const BLS12_G2_MSM_ISTHMUS_MAX_INPUT_SIZE: usize = 488_448;
/// Jovian BLS12-381 G2 MSM input cap, in bytes.
pub const BLS12_G2_MSM_JOVIAN_MAX_INPUT_SIZE: usize = 278_784;
/// Isthmus BLS12-381 pairing input cap, in bytes.
pub const BLS12_PAIRING_ISTHMUS_MAX_INPUT_SIZE: usize = 235_008;
/// Jovian BLS12-381 pairing input cap, in bytes.
pub const BLS12_PAIRING_JOVIAN_MAX_INPUT_SIZE: usize = 156_672;

/// The Beryl activation registry precompile address.
pub const ACTIVATION_REGISTRY_ADDRESS: Address =
    address!("0x8453000000000000000000000000000000000001");
/// The Beryl policy registry precompile address.
pub const POLICY_REGISTRY_ADDRESS: Address = address!("0x8453000000000000000000000000000000000002");
/// The Beryl B-20 factory precompile address.
pub const B20_FACTORY_ADDRESS: Address = address!("0xB20F000000000000000000000000000000000000");
/// Address of the synthetic trace root of inspected EIP-8130 transactions.
///
/// Base's reference executor opens one inspector frame around an EIP-8130 transaction's calls.
/// evm2 only fires call hooks around messages it dispatches, so an inspected transaction
/// dispatches a root message to this address, which [`BasePrecompiles`] claims from Zenith on and
/// which runs the calls as child frames. Outside an EIP-8130 root, calls to it succeed with empty
/// output, like calls to an empty account. The address is neither listed nor prewarmed.
pub const EIP8130_ROOT_ADDRESS: Address = address!("0x63779fdd96a819d4348ca621f0f539d68347ace2");

/// The Cobalt transaction-context precompile address.
pub const TX_CONTEXT_ADDRESS: Address = address!("0x813000000000000000000000000000000000aa02");
/// The Cobalt nonce-manager precompile address.
pub const NONCE_MANAGER_ADDRESS: Address = NonceManagerSlots::ADDRESS;

/// Base Mainnet activation registry admin used by Beryl before Cobalt state-backed admin storage.
pub const MAINNET_BERYL_ACTIVATION_ADMIN_ADDRESS: Address =
    address!("0xcE3a3bEE7E72E2A24079f3c0Cb3b97740ED425A9");
/// Base Sepolia activation registry admin used by Beryl before Cobalt state-backed admin storage.
pub const SEPOLIA_BERYL_ACTIVATION_ADMIN_ADDRESS: Address =
    address!("0x5F43072722f59964d886CBb507F6a85ca0759D42");
/// Base Zeronet activation registry admin used by Beryl before Cobalt state-backed admin storage.
pub const ZERONET_BERYL_ACTIVATION_ADMIN_ADDRESS: Address =
    address!("0xF5969A85a555671EeD766C4ff0C61426AA626b11");
/// Local devnet activation registry admin used by Beryl before Cobalt state-backed admin storage.
pub const DEVNET_BERYL_ACTIVATION_ADMIN_ADDRESS: Address =
    address!("0x9965507D1a55bcC2695C58ba16FB37d819B0A4dc");

/// Returns the activation registry admin seeded for `upgrade` on the built-in chain `chain_id`.
///
/// Mirrors `base_common_chains::ChainConfig::activation_admin_address_for_upgrade_by_chain_id`,
/// duplicated because `base-common-chains` pulls in revm.
pub const fn activation_admin_address_for_upgrade_by_chain_id(
    chain_id: u64,
    upgrade: BaseUpgrade,
) -> Option<Address> {
    match upgrade {
        BaseUpgrade::Beryl | BaseUpgrade::Cobalt => match chain_id {
            8453 => Some(MAINNET_BERYL_ACTIVATION_ADMIN_ADDRESS),
            84532 => Some(SEPOLIA_BERYL_ACTIVATION_ADMIN_ADDRESS),
            763360 => Some(ZERONET_BERYL_ACTIVATION_ADMIN_ADDRESS),
            84538453 => Some(DEVNET_BERYL_ACTIVATION_ADMIN_ADDRESS),
            _ => None,
        },
        _ => None,
    }
}

/// Activation admin source for the activation registry precompile.
///
/// Mirrors `base_common_precompiles::ActivationAdminConfig`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ActivationAdminConfig {
    /// Static chain-config activation admin, used for Beryl replay and as the Cobalt fallback.
    pub fallback: Option<Address>,
    /// Whether the activation registry consults its admin storage slot (Cobalt onwards).
    pub state_enabled: bool,
}

impl ActivationAdminConfig {
    /// Creates an activation admin configuration.
    pub const fn new(fallback: Option<Address>, state_enabled: bool) -> Self {
        Self { fallback, state_enabled }
    }

    /// Returns the configuration `base_common_precompiles::BasePrecompiles::install` derives for
    /// `upgrade`: the given fallback, with state-backed admin storage from Cobalt on.
    pub const fn for_upgrade(fallback: Option<Address>, upgrade: BaseUpgrade) -> Self {
        Self::new(fallback, upgrade as u8 >= BaseUpgrade::Cobalt as u8)
    }
}

/// Defines an input-capped precompile that halts when the input exceeds `$max` and otherwise
/// delegates to the stock evm2 precompile `$inner`, mirroring the `base-common-precompiles`
/// Granite, Isthmus, and Jovian variants.
macro_rules! capped_precompile {
    ($(#[$attr:meta])* $name:ident, $max:expr, $halt:ident, $inner:path) => {
        $(#[$attr])*
        pub fn $name(
            _evm: &mut Evm<'_, BaseEvmTypes>,
            message: &Message<BaseEvmTypes>,
            gas: &mut GasTracker,
        ) -> PrecompileResult {
            let input = &*message.input;
            if input.len() > $max {
                return Err(PrecompileHalt::$halt.into());
            }
            $inner(input, gas)
        }
    };
}

capped_precompile!(
    /// bn254 pairing with the Granite input cap.
    run_bn254_pair_granite,
    BN254_PAIR_GRANITE_MAX_INPUT_SIZE,
    Bn254PairLength,
    bn254::pair::run_istanbul
);
capped_precompile!(
    /// bn254 pairing with the Jovian input cap.
    run_bn254_pair_jovian,
    BN254_PAIR_JOVIAN_MAX_INPUT_SIZE,
    Bn254PairLength,
    bn254::pair::run_istanbul
);
capped_precompile!(
    /// BLS12-381 G1 MSM with the Isthmus input cap.
    run_bls12_g1_msm_isthmus,
    BLS12_G1_MSM_ISTHMUS_MAX_INPUT_SIZE,
    Bls12381G1MsmInputLength,
    bls12_381::g1_msm::run
);
capped_precompile!(
    /// BLS12-381 G1 MSM with the Jovian input cap.
    run_bls12_g1_msm_jovian,
    BLS12_G1_MSM_JOVIAN_MAX_INPUT_SIZE,
    Bls12381G1MsmInputLength,
    bls12_381::g1_msm::run
);
capped_precompile!(
    /// BLS12-381 G2 MSM with the Isthmus input cap.
    run_bls12_g2_msm_isthmus,
    BLS12_G2_MSM_ISTHMUS_MAX_INPUT_SIZE,
    Bls12381G2MsmInputLength,
    bls12_381::g2_msm::run
);
capped_precompile!(
    /// BLS12-381 G2 MSM with the Jovian input cap.
    run_bls12_g2_msm_jovian,
    BLS12_G2_MSM_JOVIAN_MAX_INPUT_SIZE,
    Bls12381G2MsmInputLength,
    bls12_381::g2_msm::run
);
capped_precompile!(
    /// BLS12-381 pairing with the Isthmus input cap.
    run_bls12_pairing_isthmus,
    BLS12_PAIRING_ISTHMUS_MAX_INPUT_SIZE,
    Bls12381PairingInputLength,
    bls12_381::pairing::run
);
capped_precompile!(
    /// BLS12-381 pairing with the Jovian input cap.
    run_bls12_pairing_jovian,
    BLS12_PAIRING_JOVIAN_MAX_INPUT_SIZE,
    Bls12381PairingInputLength,
    bls12_381::pairing::run
);

/// Table entry for the Beryl activation registry, B-20 factory, and policy registry.
/// [`BasePrecompiles`] dispatches these itself, since they need its upgrade and activation admin
/// configuration, so this only runs if the table is used outside of [`BasePrecompiles`].
fn base_precompiles_placeholder(
    _evm: &mut Evm<'_, BaseEvmTypes>,
    _message: &Message<BaseEvmTypes>,
    _gas: &mut GasTracker,
) -> PrecompileResult {
    Err(PrecompileError::Fatal("Beryl registries must run through BasePrecompiles".into()))
}

/// The Base precompile set for a spec.
///
/// Implements [`PrecompileProvider`] for [`BaseEvmTypes`]. Starts from the stock evm2 set of the
/// Ethereum spec the upgrade maps to and layers on the Base differences, matching
/// `base_common_precompiles::BasePrecompiles`:
///
/// - Fjord adds RIP-7212 `P256VERIFY` (`0x100`). From Azul (Osaka) the Osaka-priced variant from
///   the stock set is used, together with the Osaka `MODEXP`.
/// - Granite caps the bn254 pairing (`0x08`) input; Jovian tightens the cap.
/// - Isthmus caps the BLS12-381 G1 MSM, G2 MSM, and pairing (`0x0c`, `0x0e`, `0x0f`) inputs; Jovian
///   tightens the caps.
///
/// From Beryl it also installs the activation registry (`0x8453…0001`), driven by the activation
/// admin configuration, the policy registry (`0x8453…0002`), and the B-20 factory (`0xB20F…`).
/// B-20 tokens are resolved dynamically by address prefix, like the reference `BerylLookup`: any
/// address encoding a supported B-20 variant is a token precompile, without being listed in
/// [`PrecompileProvider::addresses`] (so it is not prewarmed). Entries of the fixed table,
/// including custom precompiles and relocations, take precedence over the prefix lookup. Cobalt
/// adds the nonce-manager getter (`0x8130…aa01`) and transaction-context getters (`0x8130…aa02`).
#[derive(Clone, Debug)]
pub struct BasePrecompiles {
    precompiles: Precompiles<BaseEvmTypes>,
    spec: BaseSpecId,
    activation_admin: ActivationAdminConfig,
}

impl BasePrecompiles {
    /// Builds the precompile set for `spec`, with no activation admin.
    pub fn new(spec: BaseSpecId) -> Self {
        let upgrade = spec.upgrade();
        let at = |fork: BaseUpgrade| spec.is_enabled_in(fork);
        let mut precompiles = Precompiles::base(spec.into());
        let map = precompiles.as_map_mut();

        if at(BaseUpgrade::Fjord) && !at(BaseUpgrade::Azul) {
            map.insert(P256VERIFY());
        }

        if at(BaseUpgrade::Jovian) {
            map.insert(Precompile::new(
                BN254_PAIR_ADDRESS,
                PrecompileId::Bn254Pairing,
                run_bn254_pair_jovian,
            ));
            map.insert(Precompile::new(
                BLS12_G1_MSM_ADDRESS,
                PrecompileId::Bls12G1Msm,
                run_bls12_g1_msm_jovian,
            ));
            map.insert(Precompile::new(
                BLS12_G2_MSM_ADDRESS,
                PrecompileId::Bls12G2Msm,
                run_bls12_g2_msm_jovian,
            ));
            map.insert(Precompile::new(
                BLS12_PAIRING_ADDRESS,
                PrecompileId::Bls12Pairing,
                run_bls12_pairing_jovian,
            ));
        } else {
            if at(BaseUpgrade::Granite) {
                map.insert(Precompile::new(
                    BN254_PAIR_ADDRESS,
                    PrecompileId::Bn254Pairing,
                    run_bn254_pair_granite,
                ));
            }
            if at(BaseUpgrade::Isthmus) {
                map.insert(Precompile::new(
                    BLS12_G1_MSM_ADDRESS,
                    PrecompileId::Bls12G1Msm,
                    run_bls12_g1_msm_isthmus,
                ));
                map.insert(Precompile::new(
                    BLS12_G2_MSM_ADDRESS,
                    PrecompileId::Bls12G2Msm,
                    run_bls12_g2_msm_isthmus,
                ));
                map.insert(Precompile::new(
                    BLS12_PAIRING_ADDRESS,
                    PrecompileId::Bls12Pairing,
                    run_bls12_pairing_isthmus,
                ));
            }
        }

        if at(BaseUpgrade::Beryl) {
            map.insert(Precompile::new(
                B20_FACTORY_ADDRESS,
                PrecompileId::custom(B20_FACTORY_ID),
                base_precompiles_placeholder,
            ));
            map.insert(Precompile::new(
                POLICY_REGISTRY_ADDRESS,
                PrecompileId::custom(POLICY_REGISTRY_ID),
                base_precompiles_placeholder,
            ));
            map.insert(Precompile::new(
                ACTIVATION_REGISTRY_ADDRESS,
                PrecompileId::custom(ACTIVATION_REGISTRY_ID),
                base_precompiles_placeholder,
            ));
        }
        if at(BaseUpgrade::Cobalt) {
            map.insert(Precompile::new(
                NONCE_MANAGER_ADDRESS,
                PrecompileId::custom("NonceManager"),
                run_nonce_manager,
            ));
            map.insert(Precompile::new(
                TX_CONTEXT_ADDRESS,
                PrecompileId::custom("TxContext"),
                run_tx_context,
            ));
        }

        Self {
            precompiles,
            spec,
            activation_admin: ActivationAdminConfig::for_upgrade(None, upgrade),
        }
    }

    /// Builds the precompile set for `spec` with the activation registry admin `admin`, as
    /// `base_common_precompiles::BasePrecompiles::with_activation_admin_address` does.
    pub fn with_activation_admin_address(mut self, admin: Option<Address>) -> Self {
        self.activation_admin = ActivationAdminConfig::for_upgrade(admin, self.spec.upgrade());
        self
    }

    /// Replaces the activation admin configuration.
    pub const fn with_activation_admin(mut self, config: ActivationAdminConfig) -> Self {
        self.activation_admin = config;
        self
    }

    /// Returns the spec this set was built for.
    pub const fn spec(&self) -> BaseSpecId {
        self.spec
    }

    /// Returns the activation admin configuration.
    pub const fn activation_admin(&self) -> ActivationAdminConfig {
        self.activation_admin
    }

    /// Returns the activation registry admin address.
    pub const fn activation_admin_address(&self) -> Option<Address> {
        self.activation_admin.fallback
    }

    /// Returns the underlying precompile table.
    pub const fn precompiles(&self) -> &Precompiles<BaseEvmTypes> {
        &self.precompiles
    }

    /// Returns the underlying precompile table mutably, for installing custom precompiles.
    pub const fn precompiles_mut(&mut self) -> &mut Precompiles<BaseEvmTypes> {
        &mut self.precompiles
    }
}

impl PrecompileProvider<BaseEvmTypes> for BasePrecompiles {
    fn addresses(&self) -> Vec<Address> {
        self.precompiles.addresses()
    }

    fn precompile_ids(&self) -> Vec<(Address, PrecompileId)> {
        self.precompiles.precompile_ids()
    }

    fn contains(&self, address: &Address) -> bool {
        PrecompileProvider::contains(&self.precompiles, address)
            || (self.spec.is_enabled_in(BaseUpgrade::Beryl) && b20_token_variant(address).is_some())
            || (*address == EIP8130_ROOT_ADDRESS && self.spec.is_enabled_in(BaseUpgrade::Zenith))
    }

    fn move_precompiles(
        &mut self,
        moves: &[(Address, Address)],
    ) -> Result<(), MovePrecompileError> {
        self.precompiles.move_precompiles(moves)
    }

    fn execute(
        &mut self,
        evm: &mut Evm<'_, BaseEvmTypes>,
        message: &Message<BaseEvmTypes>,
        gas: &mut GasTracker,
    ) -> Option<Result<PrecompileOutput, PrecompileError>> {
        let upgrade = self.spec.upgrade();
        if message.code_address == EIP8130_ROOT_ADDRESS
            && self.spec.is_enabled_in(BaseUpgrade::Zenith)
        {
            return Some(run_root(evm, message, gas));
        }
        let Some(precompile) = self.precompiles.as_map().get(&message.code_address) else {
            // Dynamic B-20 token lookup, after the fixed table like the reference `BerylLookup`.
            if !self.spec.is_enabled_in(BaseUpgrade::Beryl) {
                return None;
            }
            let variant = b20_token_variant(&message.code_address)?;
            return Some(run_b20_token(evm, message, gas, upgrade, variant));
        };
        match precompile.id().name() {
            ACTIVATION_REGISTRY_ID => {
                Some(run_activation_registry(evm, message, gas, self.activation_admin, upgrade))
            }
            B20_FACTORY_ID => Some(run_b20_factory(evm, message, gas, upgrade)),
            POLICY_REGISTRY_ID => Some(run_policy_registry(evm, message, gas, upgrade)),
            _ => self.precompiles.execute(evm, message, gas),
        }
    }
}
