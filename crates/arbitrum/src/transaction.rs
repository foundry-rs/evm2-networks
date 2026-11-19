//! Arbitrum transaction envelope and Nitro transaction types.

use alloy_consensus::{EthereumTxEnvelope, TxEip4844};
use alloy_eips::eip2718::Typed2718;
use evm2::ethereum::TxEnvelope;

/// Nitro `ArbitrumDepositTx` type: an ETH deposit from L1.
pub const ARBITRUM_DEPOSIT_TX_TYPE: u8 = 0x64;
/// Nitro `ArbitrumUnsignedTx` type: an L1-to-L2 message from an EOA.
pub const ARBITRUM_UNSIGNED_TX_TYPE: u8 = 0x65;
/// Nitro `ArbitrumContractTx` type: an L1-to-L2 message from a contract.
pub const ARBITRUM_CONTRACT_TX_TYPE: u8 = 0x66;
/// Nitro `ArbitrumRetryTx` type: a retryable ticket redeem.
pub const ARBITRUM_RETRY_TX_TYPE: u8 = 0x68;
/// Nitro `ArbitrumSubmitRetryableTx` type: a retryable ticket submission.
pub const ARBITRUM_SUBMIT_RETRYABLE_TX_TYPE: u8 = 0x69;
/// Nitro `ArbitrumInternalTx` type: an ArbOS block-level update (`startBlock` at the start of
/// every block, and batch posting reports).
pub const ARBITRUM_INTERNAL_TX_TYPE: u8 = 0x6a;
/// Nitro `ArbitrumLegacyTx` type: a transaction imported from Arbitrum Classic.
pub const ARBITRUM_LEGACY_TX_TYPE: u8 = 0x78;

/// Returns whether `ty` is one of Nitro's Arbitrum-specific transaction types.
///
/// They are produced by ArbOS from L1 messages and block-level updates rather than signed by
/// users, and [`arbitrum_tx_registry`](crate::arbitrum_tx_registry) does not execute them.
pub const fn is_arbitrum_tx_type(ty: u8) -> bool {
    matches!(
        ty,
        ARBITRUM_DEPOSIT_TX_TYPE
            | ARBITRUM_UNSIGNED_TX_TYPE
            | ARBITRUM_CONTRACT_TX_TYPE
            | ARBITRUM_RETRY_TX_TYPE
            | ARBITRUM_SUBMIT_RETRYABLE_TX_TYPE
            | ARBITRUM_INTERNAL_TX_TYPE
            | ARBITRUM_LEGACY_TX_TYPE
    )
}

/// Arbitrum transaction: a signed Ethereum transaction and the L1 poster gas it is charged.
///
/// Nitro charges the cost of posting a sequenced transaction's calldata to L1 as extra gas before
/// execution, the "poster gas". It derives it from the brotli-compressed size of the signed
/// transaction and ArbOS's L1 price estimate, and reports it as the receipt's `gasUsedForL1`.
/// The poster gas is supplied by the caller: the receipt value to replay a transaction, or zero to
/// simulate one without L1 charges (as Nitro does for calls that skip L1 charging).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ArbTxEnvelope {
    /// The Ethereum transaction.
    pub tx: TxEnvelope,
    /// L1 poster gas charged before execution.
    pub poster_gas: u64,
}

impl From<TxEnvelope> for ArbTxEnvelope {
    fn from(tx: TxEnvelope) -> Self {
        Self { tx, poster_gas: 0 }
    }
}

impl From<EthereumTxEnvelope<TxEip4844>> for ArbTxEnvelope {
    fn from(tx: EthereumTxEnvelope<TxEip4844>) -> Self {
        TxEnvelope::from(tx).into()
    }
}

impl Typed2718 for ArbTxEnvelope {
    fn ty(&self) -> u8 {
        self.tx.ty()
    }
}
