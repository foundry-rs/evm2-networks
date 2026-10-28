//! Polygon gas parameters and runtime configuration.
//!
//! Port of Bor's `params/protocol_params.go` limits and the PIP-88 storage repricing from
//! `core/vm/operations_acl.go`, expressed as an evm2 [`Version`].

use crate::PolygonHardfork;
use evm2::{
    Version,
    version::{GasId, GasParams},
};

/// Polygon EIP-7825 transaction gas limit cap (`1 << 25`), enforced from Madhugiri.
///
/// Bor uses 2^25 instead of Ethereum's 2^24.
pub const POLYGON_TX_GAS_LIMIT_CAP: u64 = 1 << 25;

/// Polygon maximum contract code size (32 KiB), enforced from Ahmedabad.
///
/// The initcode limit stays at Ethereum's 48 KiB.
pub const POLYGON_MAX_CODE_SIZE: usize = 32_768;

/// PIP-88 cold SLOAD cost (2,100 × 2.6), from Chicago.
pub const PIP88_COLD_SLOAD_COST: u64 = 5_460;

/// PIP-88 cold SSTORE cost (2,100 × 1.4), from Chicago.
pub const PIP88_COLD_SSTORE_COST: u64 = 2_940;

/// EIP-2929 warm storage read cost, unchanged by PIP-88.
pub(crate) const WARM_STORAGE_READ_COST: u64 = 100;

/// EIP-2200 `SSTORE_RESET_GAS`.
const SSTORE_RESET_GAS: u64 = 5_000;

/// EIP-2930 access list storage key cost.
const ACCESS_LIST_STORAGE_KEY_COST: u64 = 1_900;

/// Returns Polygon's dynamic gas parameters for `spec`.
///
/// Chicago applies PIP-88 to SSTORE: the cold surcharge becomes [`PIP88_COLD_SSTORE_COST`] and the
/// reset cost and refunds are recomputed against it. The cold SLOAD surcharge is charged by the
/// PIP-88 SLOAD instruction instead of [`GasId::ColdStorageAdditionalCost`], because evm2's SSTORE
/// also reads that parameter.
pub const fn polygon_gas_params(spec: PolygonHardfork) -> GasParams {
    let mut params = Version::base(spec.into_eth_spec()).gas_params;
    if spec.enables(PolygonHardfork::Chicago) {
        // evm2 charges `SstoreStatic` (the warm read cost) on top of these.
        let reset = SSTORE_RESET_GAS - PIP88_COLD_SSTORE_COST - WARM_STORAGE_READ_COST;
        params.set(GasId::ColdStorageCost, PIP88_COLD_SSTORE_COST as u32);
        params.set(GasId::SstoreResetWithoutColdLoadCost, reset as u32);
        params.set(GasId::SstoreResetRefund, reset as u32);
        params.set(
            GasId::SstoreClearingSlotRefund,
            (SSTORE_RESET_GAS - PIP88_COLD_SSTORE_COST + ACCESS_LIST_STORAGE_KEY_COST) as u32,
        );
    }
    params
}

/// Returns the evm2 runtime version for a Polygon hardfork and chain ID.
///
/// The version carries the PIP-88 gas parameters, the 32 KiB code size limit from Ahmedabad and
/// the 2^25 transaction gas limit cap from Madhugiri. All [`evm2::EvmFeatures`] flags keep their
/// Ethereum defaults for the inherited spec.
pub const fn polygon_version(spec: PolygonHardfork, chain_id: u64) -> Version {
    let mut version = Version::new(spec.into_eth_spec());
    version.gas_params = polygon_gas_params(spec);
    version.chain_id = chain_id;
    if spec.enables(PolygonHardfork::Ahmedabad) {
        version.max_code_size = POLYGON_MAX_CODE_SIZE;
    }
    if spec.enables(PolygonHardfork::Madhugiri) {
        version.tx_gas_limit_cap = POLYGON_TX_GAS_LIMIT_CAP;
    }
    version
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn limits_follow_activation() {
        let giugliano = polygon_version(PolygonHardfork::Giugliano, 137);
        assert_eq!(giugliano.chain_id, 137);
        assert_eq!(giugliano.max_code_size, POLYGON_MAX_CODE_SIZE);
        assert_eq!(giugliano.max_initcode_size, 49_152);
        assert_eq!(giugliano.tx_gas_limit_cap, 33_554_432);

        let cancun = polygon_version(PolygonHardfork::Cancun, 137);
        assert_eq!(cancun.max_code_size, 24_576);
        let ahmedabad = polygon_version(PolygonHardfork::Ahmedabad, 137);
        assert_eq!(ahmedabad.max_code_size, 32_768);

        let rio = polygon_version(PolygonHardfork::Rio, 137);
        assert_eq!(rio.tx_gas_limit_cap, u64::MAX);
        let madhugiri = polygon_version(PolygonHardfork::Madhugiri, 137);
        assert_eq!(madhugiri.tx_gas_limit_cap, 33_554_432);
    }

    #[test]
    fn pip88_sstore_params() {
        let giugliano = polygon_gas_params(PolygonHardfork::Giugliano);
        assert_eq!(giugliano.get(GasId::ColdStorageCost), 2_100);
        assert_eq!(giugliano.get(GasId::SstoreResetWithoutColdLoadCost), 2_800);
        assert_eq!(giugliano.get(GasId::SstoreResetRefund), 2_800);
        assert_eq!(giugliano.get(GasId::SstoreClearingSlotRefund), 4_800);

        let chicago = polygon_gas_params(PolygonHardfork::Chicago);
        assert_eq!(chicago.get(GasId::ColdStorageCost), 2_940);
        assert_eq!(chicago.get(GasId::SstoreResetWithoutColdLoadCost), 1_960);
        assert_eq!(chicago.get(GasId::SstoreResetRefund), 1_960);
        assert_eq!(chicago.get(GasId::SstoreClearingSlotRefund), 3_960);
        // The SLOAD surcharge stays Ethereum's: PIP-88 SLOAD pricing lives in the instruction.
        assert_eq!(chicago.get(GasId::ColdStorageAdditionalCost), 2_000);
        assert_eq!(chicago.get(GasId::SstoreSetWithoutLoadCost), 19_900);
    }
}
