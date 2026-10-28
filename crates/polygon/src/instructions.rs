//! Polygon opcode overlays.
//!
//! Port of Bor's `core/vm/jump_table.go` deviations from the inherited Prague table:
//!
//! - Lisovo and later enable EIP-7939 `CLZ` (Bor never adopted Osaka, so the stock evm2 table does
//!   not have it).
//! - Chicago and later replace `SLOAD` with the PIP-88 variant charging [`PIP88_COLD_SLOAD_COST`]
//!   for a cold slot.

use crate::{PIP88_COLD_SLOAD_COST, PolygonEvmTypes, version::WARM_STORAGE_READ_COST};
use evm2::interpreter::Host;
use evm2_macros::instruction;

/// PIP-88 additional SLOAD cost for a cold slot, on top of the warm read cost charged as static
/// gas.
pub const PIP88_SLOAD_COLD_ADDITIONAL_COST: u64 = PIP88_COLD_SLOAD_COST - WARM_STORAGE_READ_COST;

/// SLOAD with PIP-88 cold-slot pricing.
#[instruction(EvmTypes = PolygonEvmTypes, dynamic_gas)]
pub fn pip88_sload(cx: _, [key]: [Word]) -> Result<out> {
    // Like the stock SLOAD, avoid touching the database when the frame cannot afford the cold
    // surcharge.
    let skip_cold_load = cx.gas.remaining() < PIP88_SLOAD_COLD_ADDITIONAL_COST;
    let destination = cx.state.message().destination;
    let load = cx
        .state
        .host()
        .sload(&destination, key, skip_cold_load)
        .map_err(|error| cx.state.fail(error))?;
    if load.is_cold {
        cx.gas.spend(PIP88_SLOAD_COLD_ADDITIONAL_COST)?;
    }
    *out = load.value;
}
