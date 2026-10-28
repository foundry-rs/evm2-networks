//! evm2 execution type family for BNB Smart Chain.
//!
//! A port of bsc's execution rules onto evm2:
//!
//! - [`BscHardfork`] activation points for BSC mainnet and Chapel, mapped onto evm2
//!   [`SpecId`](evm2::SpecId)s. At the EVM level BSC runs Ethereum's rules for the inherited spec;
//!   its own forks only change precompiles or consensus.
//! - BSC precompile sets per fork ([`bsc_precompiles`]): BLS signature verification (`0x66`),
//!   double-sign evidence verification (`0x68`), Tendermint secp256k1 recovery (`0x69`) and P256
//!   from Haber.
//! - Runtime limits ([`bsc_version`]): at most [`BSC_MAX_BLOBS_PER_TX`] blobs per transaction in
//!   every fork.
//! - Fee settlement ([`BscHandlerHooks`]): the fee above the base fee and the blob fee go to
//!   [`BSC_SYSTEM_ADDRESS`] instead of the coinbase.
//!
//! Callers building a block environment from a BSC header set `prevrandao` to the header's
//! difficulty, which is what bsc's `DIFFICULTY`/`PREVRANDAO` opcode returns.
//!
//! Not covered:
//!
//! - The light-client precompiles `0x64`, `0x65` and `0x67`, which charge their gas and halt (see
//!   [`UNSUPPORTED_LIGHT_CLIENT_PRECOMPILE`]).
//! - System transactions ([`is_bsc_system_transaction`]) and other Parlia block-level state
//!   changes, which belong to block execution.
//! - bsc's rejection of calls that execute code at the coinbase address (`ErrCoinbaseAsContract`),
//!   which needs an evm2 call frame hook.
//! - The Jenner hardfork, not yet scheduled on mainnet.

extern crate alloc;

mod chain;
pub use chain::*;

mod config;
pub use config::*;

mod factory;
pub use factory::BscEvmFactory;

mod handler;
pub use handler::*;

mod precompiles;
pub use precompiles::*;

mod spec;
pub use spec::*;

#[cfg(test)]
mod tests;
