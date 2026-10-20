//! evm2 execution type family for Monad.
//!
//! A port of `monad-revm` 0.8.0 execution semantics onto evm2:
//!
//! - [`MonadHardfork`] spec ids mapped onto evm2 [`SpecId`](evm2::SpecId)s.
//! - Monad gas parameters, code size limits and the 30M transaction gas cap in [`monad_version`].
//! - Monad opcode overlays: delegated-account `CREATE` rejection, delegation-aware `CALL`
//!   precompile dispatch, MIP-3 linear memory with a pooled limit, and MIP-8 page-based storage.
//! - Monad transaction handlers: full gas-limit charging without refunds, fee-only admission,
//!   EIP-4844 rejection, and reserve-balance tracking.
//! - Monad precompiles: repriced Ethereum precompiles, staking (0x1000) and reserve balance
//!   (0x1001).
//! - Opt-in replay of canonical protocol system transactions in [`protocol`].

extern crate alloc;

mod cfg;
pub use cfg::*;

mod chain;
pub use chain::{MonadChainContext, default_max_reserve_balance};

mod config;
pub use config::{
    MonadBlockEnv, MonadBlockExt, MonadConfig, MonadConfigSelector, MonadEvm, MonadEvmExt,
    MonadEvmTypes, MonadTxEnvelope, MonadTxResultExt, monad_execution_config, monad_opcode_config,
};

mod factory;
pub use factory::MonadEvmFactory;

mod handler;
pub use handler::{MonadInvalidTransaction, MonadPreparedTx, monad_tx_registry};

pub mod instructions;
pub mod memory;
pub mod page;

mod precompiles;
pub use precompiles::*;

pub mod protocol;
pub use protocol::{ProtocolSystemCall, ProtocolSystemCallError, protocol_system_call};

pub mod reserve_balance;
pub use reserve_balance::tracker::{ReserveAccount, ReserveBalanceInit, ReserveBalanceTracker};

mod spec;
pub use spec::*;

pub mod staking;

pub mod system;
pub use system::*;

#[cfg(test)]
mod tests;
