//! evm2 execution type family for Arbitrum Nitro.
//!
//! A port of Nitro's execution rules for signed Ethereum transactions onto evm2:
//!
//! - [`ArbOsVersion`]s, Nitro's hardfork identifiers, mapped onto the evm2 [`SpecId`](evm2::SpecId)
//!   they inherit, and the chains running Nitro ([`is_arbitrum_chain`]), including the Robinhood
//!   Chain Orbit chains.
//! - Block metadata ([`ArbHeaderInfo`]) decoded from the header's `mixHash`: the L1 block number
//!   and the ArbOS version.
//! - Opcode overlays ([`ArbConfig`]): `NUMBER` and `BLOCKHASH` use L1 blocks, `GASPRICE` returns
//!   the price paid, `BLOBBASEFEE` fails, and Stylus programs abort the transaction.
//! - Runtime limits ([`arbitrum_version`]): no EIP-7825 transaction gas limit cap, since ArbOS caps
//!   execution gas itself.
//! - Gas charging and fee settlement ([`ArbHandlerHooks`]): the L1 poster gas
//!   ([`ArbTxEnvelope::poster_gas`]) charged before execution and excluded from refunds, the ArbOS
//!   gas cap, dropped tips, the opt-in EIP-7623 calldata floor, the network, infrastructure and
//!   poster fee distribution, and the L2 gas backlog.
//! - Precompile sets per ArbOS version ([`arbitrum_precompiles`]), with `ArbSys`, `ArbInfo` and the
//!   `ArbGasInfo` getters ported. The ArbOS state they read and settlement updates is kept in the
//!   storage of [`ARBOS_STATE_ADDRESS`], so it is read from the chain state ([`state`]).
//!
//! Callers replaying a block read the ArbOS version and the L1 block number from the header
//! ([`ArbHeaderInfo::from_mix_hash`]), set the block environment with `prevrandao` 1 and no blob
//! base fee, and take each transaction's poster gas from its receipt's `gasUsedForL1`. Nitro
//! blocks carry no parent beacon block root, even from Cancun.
//!
//! Not covered:
//!
//! - Nitro's own transaction types ([`is_arbitrum_tx_type`]): deposits, L1-to-L2 messages,
//!   retryable tickets and redeems, and the internal transactions starting each block and reporting
//!   batches. Block execution applies them; RPC block decoding needs to accept them.
//! - Computing the poster gas, which needs the brotli-compressed size of the signed transaction,
//!   and the calldata units it adds to the L1 pricing state (`AddToUnitsSinceUpdate`).
//! - Stylus (WASM) programs, which abort the transaction with
//!   [`StylusUnsupported`](instructions::StylusUnsupported). Deploying Stylus code fails under
//!   EIP-3541 as in plain Ethereum.
//! - The multi-dimensional gas model of ArbOS 60 and later: its constraint backlogs and the
//!   multi-gas refund. Arbitrum One uses the single-gas constraint model.
//! - The ArbOS precompiles other than `ArbSys`, `ArbInfo` and `ArbGasInfo`, and the `ArbSys`
//!   methods sending L2-to-L1 messages, which abort the transaction with
//!   [`ArbOsPrecompileUnsupported`].
//! - Nitro's hardcoded list of reverted transactions and the block-level system calls (EIP-4788,
//!   EIP-2935), which belong to block execution.

extern crate alloc;

mod chain;
pub use chain::*;

mod config;
pub use config::{
    ArbBlockEnv, ArbBlockEnvExt, ArbConfig, ArbConfigSelector, ArbEvm, ArbEvmExt, ArbEvmTypes,
    ArbTxResultExt, arbitrum_opcode_config, arbitrum_version,
};

mod factory;
pub use factory::ArbEvmFactory;

mod handler;
pub use handler::*;

pub mod instructions;

mod precompiles;
pub use precompiles::*;

mod spec;
pub use spec::*;

pub mod state;

mod transaction;
pub use transaction::*;

#[cfg(test)]
mod tests;
