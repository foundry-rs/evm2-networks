//! evm2 execution type family for Celo.
//!
//! A port of celo-revm's execution rules for Celo L2 onto evm2:
//!
//! - Celo runs the OP Stack hardforks ([`celo_spec`] maps mainnet and Sepolia timestamps to an
//!   [`OpSpecId`](op_evm2::OpSpecId)) with OP deposits and the L1 data and operator fees.
//!   Native-fee transactions pay the base fee to the `FeeHandler` ([`CeloHandlerHooks`]).
//! - CIP-64 transactions ([`TxCip64`], type `0x7b`) pay fees in a registered ERC-20 fee currency.
//!   The currencies of a block ([`FeeCurrencyContext`]) are read from the `FeeCurrencyDirectory`
//!   before its first transaction. Fees are debited from the token with `debitGasFees` before
//!   execution and settled with `creditGasFees` after it, and their logs surround the transaction's
//!   own logs. Like celo-revm, the debit and credit are skipped when the balance or base fee check
//!   is disabled, and the currency's intrinsic gas is then charged in full.
//! - The transfer precompile at `0xfd` ([`celo_transfer_run`]) and a 64 KiB contract code size
//!   limit ([`celo_version`]).
//!
//! Callers replaying a block from its middle can inject the block's fee currency context in
//! [`CeloEvmExt`]. The fee-currency calls run as handler-level system calls inside the
//! transaction, so an installed inspector observes them, including the directory reads that run
//! before validation. celo-revm does not inspect them, but evm2 has no uninspected handler-level
//! system call.
//!
//! Not covered: pre-L2 Celo history, and the block-building base fee rules.

mod chain;
pub use chain::*;

mod config;
pub use config::*;

mod deposit;

mod factory;
pub use factory::CeloEvmFactory;

mod fee_currency;
pub use fee_currency::{FeeCurrencyContext, FeeCurrencyInfo};

mod handler;
pub use handler::{CeloHandlerHooks, CeloTxError, celo_tx_registry};

mod precompiles;
pub use precompiles::*;

mod transaction;
pub use transaction::*;

#[cfg(test)]
mod tests;
