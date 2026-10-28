//! Monad gas parameters and runtime configuration.
//!
//! Port of `monad-revm` `cfg.rs` (code size, initcode size, transaction gas limit cap and memory
//! limit) and `monad_gas_params` from `instructions.rs`, expressed as an evm2 [`Version`].

use crate::MonadHardfork;
use evm2::{
    Version,
    version::{GasId, GasParams},
};

/// Monad transaction gas limit cap (30M gas), applied to every Monad hardfork.
pub const MONAD_TX_GAS_LIMIT_CAP: u64 = 30_000_000;

/// MIP-3 maximum memory per transaction (8 MiB), pooled across the call stack.
///
/// Enforced for MonadNine and later.
pub const MONAD_MEMORY_LIMIT: u64 = 8 * 1024 * 1024;

/// Monad maximum contract code size (128 KiB).
pub const MONAD_MAX_CODE_SIZE: usize = 0x20000;

/// Monad maximum initcode size (256 KiB).
pub const MONAD_MAX_INITCODE_SIZE: usize = MONAD_MAX_CODE_SIZE * 2;

/// Monad cold storage access cost (SLOAD, SSTORE). Ethereum uses 2100.
pub const COLD_SLOAD_COST: u64 = 8100;

/// Monad cold account access cost (BALANCE, EXTCODE*, CALL*, SELFDESTRUCT). Ethereum uses 2600.
pub const COLD_ACCOUNT_ACCESS_COST: u64 = 10100;

/// Warm storage read cost, unchanged from Ethereum.
pub const WARM_STORAGE_READ_COST: u64 = 100;

/// Returns Monad's dynamic gas parameters for `spec`.
///
/// Monad raises cold access costs to account for the higher cost of state reads from disk; warm
/// access costs stay at 100 gas.
pub const fn monad_gas_params(spec: MonadHardfork) -> GasParams {
    let mut params = Version::base(spec.into_eth_spec()).gas_params;
    if MonadHardfork::MonadEight.is_enabled_in(spec) {
        // SSTORE uses the full cold storage cost.
        params.set(GasId::ColdStorageCost, COLD_SLOAD_COST as u32);
        // SLOAD uses the additional cost (cold - warm).
        params.set(
            GasId::ColdStorageAdditionalCost,
            (COLD_SLOAD_COST - WARM_STORAGE_READ_COST) as u32,
        );
        // Account access opcodes use the additional cost (cold - warm).
        params.set(
            GasId::ColdAccountAdditionalCost,
            (COLD_ACCOUNT_ACCESS_COST - WARM_STORAGE_READ_COST) as u32,
        );
    }
    params
}

/// Returns the Monad memory limit for `spec` given a configured limit.
///
/// MonadNine and later clamp the configured limit to [`MONAD_MEMORY_LIMIT`] while preserving a
/// stricter configured value. Earlier hardforks use the configured limit unchanged, so hardfork
/// transitions restore a larger pre-MIP-3 limit.
pub const fn monad_memory_limit(spec: MonadHardfork, configured: u64) -> u64 {
    if MonadHardfork::MonadNine.is_enabled_in(spec) && configured > MONAD_MEMORY_LIMIT {
        MONAD_MEMORY_LIMIT
    } else {
        configured
    }
}

/// Returns the evm2 runtime version for a Monad hardfork and chain ID.
///
/// The version carries Monad's gas parameters, the 30M transaction gas limit cap, the 128 KiB code
/// and 256 KiB initcode limits, and the MIP-3 pooled memory limit for MonadNine and later. All
/// standard [`evm2::EvmFeatures`] flags keep their Ethereum defaults for the inherited spec.
pub const fn monad_version(spec: MonadHardfork, chain_id: u64) -> Version {
    let mut version = Version::new(spec.into_eth_spec());
    version.gas_params = monad_gas_params(spec);
    version.chain_id = chain_id;
    version.tx_gas_limit_cap = MONAD_TX_GAS_LIMIT_CAP;
    version.memory_limit = monad_memory_limit(spec, version.memory_limit);
    version.max_code_size = MONAD_MAX_CODE_SIZE;
    version.max_initcode_size = MONAD_MAX_INITCODE_SIZE;
    version
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::str::FromStr;
    use monad_revm::MonadCfgEnv;
    use revm::{context::Cfg, context_interface::cfg::GasId as RevmGasId};

    fn theirs(spec: MonadHardfork) -> monad_revm::MonadHardfork {
        monad_revm::MonadHardfork::from_str(spec.into()).unwrap()
    }

    /// Every evm2 gas parameter that has a revm counterpart, paired with that counterpart.
    fn gas_id_pairs() -> [(GasId, RevmGasId); 34] {
        [
            (GasId::ExpByte, RevmGasId::exp_byte_gas()),
            (GasId::ExtcodecopyPerWord, RevmGasId::extcodecopy_per_word()),
            (GasId::CopyPerWord, RevmGasId::copy_per_word()),
            (GasId::Logdata, RevmGasId::logdata()),
            (GasId::Logtopic, RevmGasId::logtopic()),
            (GasId::McopyPerWord, RevmGasId::mcopy_per_word()),
            (GasId::Keccak256PerWord, RevmGasId::keccak256_per_word()),
            (GasId::MemoryLinearCost, RevmGasId::memory_linear_cost()),
            (GasId::MemoryQuadraticReduction, RevmGasId::memory_quadratic_reduction()),
            (GasId::InitcodePerWord, RevmGasId::initcode_per_word()),
            (GasId::Create, RevmGasId::create()),
            (GasId::CallStipendReduction, RevmGasId::call_stipend_reduction()),
            (GasId::TransferValueCost, RevmGasId::transfer_value_cost()),
            (GasId::ColdAccountAdditionalCost, RevmGasId::cold_account_additional_cost()),
            (GasId::NewAccountCost, RevmGasId::new_account_cost()),
            (GasId::WarmStorageReadCost, RevmGasId::warm_storage_read_cost()),
            (GasId::SstoreStatic, RevmGasId::sstore_static()),
            (GasId::SstoreSetWithoutLoadCost, RevmGasId::sstore_set_without_load_cost()),
            (
                GasId::SstoreResetWithoutColdLoadCost,
                RevmGasId::sstore_reset_without_cold_load_cost(),
            ),
            (GasId::SstoreClearingSlotRefund, RevmGasId::sstore_clearing_slot_refund()),
            (GasId::SelfdestructRefund, RevmGasId::selfdestruct_refund()),
            (GasId::CallStipend, RevmGasId::call_stipend()),
            (GasId::MaxRefundQuotient, RevmGasId::max_refund_quotient()),
            (GasId::ColdStorageAdditionalCost, RevmGasId::cold_storage_additional_cost()),
            (GasId::ColdStorageCost, RevmGasId::cold_storage_cost()),
            (GasId::NewAccountCostForSelfdestruct, RevmGasId::new_account_cost_for_selfdestruct()),
            (GasId::CodeDepositCost, RevmGasId::code_deposit_cost()),
            (GasId::TxTokenNonZeroByteMultiplier, RevmGasId::tx_token_non_zero_byte_multiplier()),
            (GasId::TxTokenCost, RevmGasId::tx_token_cost()),
            (GasId::TxFloorCostPerToken, RevmGasId::tx_floor_cost_per_token()),
            (GasId::TxFloorCostBase, RevmGasId::tx_floor_cost_base_gas()),
            (GasId::TxAccessListAddressCost, RevmGasId::tx_access_list_address_cost()),
            (GasId::TxAccessListStorageKeyCost, RevmGasId::tx_access_list_storage_key_cost()),
            (GasId::TxBaseStipend, RevmGasId::tx_base_stipend()),
        ]
    }

    #[test]
    fn gas_params_match_monad_revm() {
        for spec in MonadHardfork::ALL {
            let ours = monad_gas_params(spec);
            let expected = monad_revm::instructions::monad_gas_params(theirs(spec));
            for (id, revm_id) in gas_id_pairs() {
                assert_eq!(ours.get(id), expected.get(revm_id), "{spec} {id:?}");
            }
            for (id, revm_id) in [
                (GasId::TxCreateCost, RevmGasId::tx_create_cost()),
                (GasId::TxInitcodeCost, RevmGasId::tx_initcode_cost()),
                (GasId::TxEip7702PerEmptyAccountCost, RevmGasId::tx_eip7702_regular_gas()),
                (GasId::TxEip7702AuthRefund, RevmGasId::tx_eip7702_regular_refund()),
                (GasId::SstoreSetRefund, RevmGasId::sstore_set_refund()),
                (GasId::SstoreResetRefund, RevmGasId::sstore_reset_refund()),
            ] {
                assert_eq!(ours.get(id), expected.get(revm_id), "{spec} {id:?}");
            }
            assert_eq!(ours.selfdestruct_cold_cost(), expected.selfdestruct_cold_cost(), "{spec}");
        }
    }

    #[test]
    fn version_limits_match_monad_cfg() {
        for spec in MonadHardfork::ALL {
            let version = monad_version(spec, 143);
            let cfg = MonadCfgEnv::new_with_spec(theirs(spec)).with_chain_id(143);
            assert_eq!(version.chain_id, cfg.chain_id());
            assert_eq!(version.tx_gas_limit_cap, cfg.tx_gas_limit_cap(), "{spec}");
            assert_eq!(version.max_code_size, cfg.max_code_size(), "{spec}");
            assert_eq!(version.max_initcode_size, cfg.max_initcode_size(), "{spec}");
            assert_eq!(version.memory_limit, cfg.memory_limit(), "{spec}");
        }
    }

    #[test]
    fn memory_limit_follows_hardfork_transitions() {
        for configured in [16_000, 128 * 1024 * 1024, (1 << 32) - 1] {
            for spec in MonadHardfork::ALL {
                let mut cfg = MonadCfgEnv::new_with_spec(theirs(spec));
                cfg.0.memory_limit = configured;
                assert_eq!(
                    monad_memory_limit(spec, configured),
                    cfg.memory_limit(),
                    "{spec} {configured}"
                );
            }
        }
    }
}
