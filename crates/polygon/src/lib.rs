//! evm2 execution type family for Polygon PoS.
//!
//! A port of Bor's execution rules onto evm2:
//!
//! - [`PolygonHardfork`] activation points for Polygon mainnet and Amoy, mapped onto evm2
//!   [`SpecId`](evm2::SpecId)s. Bor never adopted Osaka: every fork from Bhilai on runs on Prague
//!   with Polygon overlays.
//! - Polygon precompile sets per fork ([`polygon_precompiles`]): P256 from Cancun, Osaka modexp and
//!   KZG from Madhugiri, EIP-7951 P256 pricing from Lisovo, KZG removal at LisovoPro and PIP-88
//!   repricing from Chicago.
//! - Runtime limits and gas parameters ([`polygon_version`]): the 32 KiB code size limit from
//!   Ahmedabad, the 2^25 transaction gas limit cap from Madhugiri and PIP-88 SSTORE pricing from
//!   Chicago.
//! - Opcode overlays ([`PolygonConfig`]): `CLZ` from Lisovo and PIP-88 SLOAD pricing from Chicago.
//! - Fee settlement ([`PolygonHandlerHooks`]): from London the base fee is credited to the burnt
//!   contract ([`polygon_burnt_contract`]) and every transaction paying a tip emits Bor's fee
//!   transfer log.
//!
//! Not covered:
//!
//! - Bor's per-transfer `LogTransfer` logs ([`POLYGON_TRANSFER_LOG_TOPIC`]), which need an evm2
//!   value-transfer hook.
//! - State-sync transactions ([`POLYGON_STATE_SYNC_TX_TYPE`]), block-level system calls and Bor's
//!   irregular state changes (`BlockAlloc`), which belong to block execution.
//! - The pre-Rio coinbase, which is the block signer recovered from the header seal (see
//!   [`polygon_coinbase`]).

extern crate alloc;

mod chain;
pub use chain::*;

mod config;
pub use config::{
    PolygonBlockEnv, PolygonConfig, PolygonConfigSelector, PolygonEvm, PolygonEvmTypes,
    polygon_execution_config, polygon_opcode_config,
};

mod factory;
pub use factory::PolygonEvmFactory;

mod handler;
pub use handler::*;

pub mod instructions;

mod precompiles;
pub use precompiles::*;

mod spec;
pub use spec::*;

mod version;
pub use version::{
    PIP88_COLD_SLOAD_COST, PIP88_COLD_SSTORE_COST, POLYGON_MAX_CODE_SIZE, POLYGON_TX_GAS_LIMIT_CAP,
    polygon_gas_params, polygon_version,
};

#[cfg(test)]
mod tests;
