#![doc = include_str!("../README.md")]

extern crate alloc;

mod chain;
pub use chain::*;

mod config;
pub use config::{
    ArcConfig, ArcConfigSelector, ArcEvm, ArcEvmTypes, arc_opcode_config, arc_version,
};

mod factory;
pub use factory::ArcEvmFactory;

mod handler;
pub use handler::{ArcTxError, ArcTxHandlerHooks, arc_tx_registry};

pub mod instructions;

pub mod precompiles;
pub use precompiles::{ArcPrecompiles, arc_precompiles};

mod spec;
pub use spec::{ArcHardfork, ArcSpecId, UnknownArcHardfork};

pub mod transfer;

#[cfg(test)]
mod tests;
