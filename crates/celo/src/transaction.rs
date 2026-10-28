//! Celo transactions: the OP transaction types plus CIP-64 fee-currency transactions.

use alloy_consensus::{
    EthereumTxEnvelope, Signed, Transaction, TxEip1559, TxEip2930, TxEip4844, TxLegacy,
    transaction::{RlpEcdsaDecodableTx, RlpEcdsaEncodableTx},
};
use alloy_eips::{
    eip2718::{Encodable2718, Typed2718},
    eip2930::AccessList,
    eip7702::SignedAuthorization,
};
use alloy_primitives::{Address, B256, Bytes, ChainId, TxKind, U256};
use alloy_rlp::{BufMut, Decodable, Encodable};
use evm2::ethereum::LazyTxEip7702;
use op_evm2::{OpTypedTx, TxDeposit, UnsupportedEip4844};

/// CIP-64 transaction type.
pub const CIP64_TX_TYPE: u8 = 0x7b;

/// CIP-64 transaction: an EIP-1559 transaction whose fees are paid in an ERC-20 fee currency.
///
/// Fees are paid in native CELO when [`Self::fee_currency`] is `None`.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct TxCip64 {
    /// EIP-1559 fields. The fee fields are denominated in the fee currency.
    pub inner: TxEip1559,
    /// ERC-20 token used to pay fees, or `None` for native CELO.
    pub fee_currency: Option<Address>,
}

impl Typed2718 for TxCip64 {
    fn ty(&self) -> u8 {
        CIP64_TX_TYPE
    }
}

impl RlpEcdsaEncodableTx for TxCip64 {
    fn rlp_encoded_fields_length(&self) -> usize {
        self.inner.rlp_encoded_fields_length() + self.fee_currency.map_or(1, |a| a.length())
    }

    fn rlp_encode_fields(&self, out: &mut dyn BufMut) {
        self.inner.rlp_encode_fields(out);
        match self.fee_currency {
            Some(address) => address.encode(out),
            None => out.put_u8(alloy_rlp::EMPTY_STRING_CODE),
        }
    }
}

impl RlpEcdsaDecodableTx for TxCip64 {
    const DEFAULT_TX_TYPE: u8 = CIP64_TX_TYPE;

    fn rlp_decode_fields(buf: &mut &[u8]) -> alloy_rlp::Result<Self> {
        let inner = TxEip1559::rlp_decode_fields(buf)?;
        let fee_currency = if buf.first() == Some(&alloy_rlp::EMPTY_STRING_CODE) {
            *buf = &buf[1..];
            None
        } else {
            Some(Address::decode(buf)?)
        };
        Ok(Self { inner, fee_currency })
    }
}

/// Unsigned Celo transaction body.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CeloTypedTx {
    /// An OP transaction: legacy, EIP-2930, EIP-1559, EIP-7702 or deposit.
    Op(OpTypedTx),
    /// A CIP-64 transaction.
    Cip64(TxCip64),
}

impl<T: Into<OpTypedTx>> From<T> for CeloTypedTx {
    fn from(tx: T) -> Self {
        Self::Op(tx.into())
    }
}

impl From<TxCip64> for CeloTypedTx {
    fn from(tx: TxCip64) -> Self {
        Self::Cip64(tx)
    }
}

/// Celo transaction envelope used as [`EvmTypesHost::Tx`](evm2::EvmTypesHost::Tx).
///
/// Pairs the typed transaction with its EIP-2718 enveloped bytes, which every non-deposit
/// transaction needs for the L1 data fee and to match the historical transaction exceptions.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CeloTxEnvelope {
    /// The typed transaction.
    pub tx: CeloTypedTx,
    /// EIP-2718 encoding of the signed transaction.
    pub enveloped_tx: Option<Bytes>,
}

impl CeloTxEnvelope {
    /// Creates an envelope from a typed transaction and its enveloped bytes.
    pub fn new(tx: impl Into<CeloTypedTx>, enveloped_tx: Option<Bytes>) -> Self {
        Self { tx: tx.into(), enveloped_tx }
    }

    /// Creates an envelope from a signed transaction, computing its EIP-2718 encoding.
    pub fn from_signed<T>(signed: Signed<T>) -> Self
    where
        T: Into<CeloTypedTx>,
        Signed<T>: Encodable2718,
    {
        let enveloped = Bytes::from(signed.encoded_2718());
        Self::new(signed.strip_signature(), Some(enveloped))
    }

    /// Creates a deposit envelope. Deposits pay no L1 fee, so no enveloped bytes are needed.
    pub fn deposit(tx: TxDeposit) -> Self {
        Self::new(tx, None)
    }

    /// Returns the EIP-2718 enveloped bytes, if set.
    pub fn enveloped_tx(&self) -> Option<&Bytes> {
        self.enveloped_tx.as_ref()
    }

    /// Returns the contained legacy transaction, if this is legacy.
    pub const fn as_legacy(&self) -> Option<&TxLegacy> {
        match &self.tx {
            CeloTypedTx::Op(OpTypedTx::Legacy(tx)) => Some(tx),
            _ => None,
        }
    }

    /// Returns the contained EIP-2930 transaction, if this is EIP-2930.
    pub const fn as_eip2930(&self) -> Option<&TxEip2930> {
        match &self.tx {
            CeloTypedTx::Op(OpTypedTx::Eip2930(tx)) => Some(tx),
            _ => None,
        }
    }

    /// Returns the contained EIP-1559 transaction, if this is EIP-1559.
    pub const fn as_eip1559(&self) -> Option<&TxEip1559> {
        match &self.tx {
            CeloTypedTx::Op(OpTypedTx::Eip1559(tx)) => Some(tx),
            _ => None,
        }
    }

    /// Returns the contained EIP-7702 transaction, if this is EIP-7702.
    pub const fn as_eip7702(&self) -> Option<&LazyTxEip7702> {
        match &self.tx {
            CeloTypedTx::Op(OpTypedTx::Eip7702(tx)) => Some(tx),
            _ => None,
        }
    }

    /// Returns the contained deposit transaction, if this is a deposit.
    pub const fn as_deposit(&self) -> Option<&TxDeposit> {
        match &self.tx {
            CeloTypedTx::Op(OpTypedTx::Deposit(tx)) => Some(tx),
            _ => None,
        }
    }

    /// Returns the contained CIP-64 transaction, if this is CIP-64.
    pub const fn as_cip64(&self) -> Option<&TxCip64> {
        match &self.tx {
            CeloTypedTx::Cip64(tx) => Some(tx),
            _ => None,
        }
    }
}

impl From<TxDeposit> for CeloTxEnvelope {
    fn from(tx: TxDeposit) -> Self {
        Self::deposit(tx)
    }
}

impl TryFrom<EthereumTxEnvelope<TxEip4844>> for CeloTxEnvelope {
    type Error = UnsupportedEip4844;

    fn try_from(tx: EthereumTxEnvelope<TxEip4844>) -> Result<Self, Self::Error> {
        Ok(match tx {
            EthereumTxEnvelope::Legacy(tx) => Self::from_signed(tx),
            EthereumTxEnvelope::Eip2930(tx) => Self::from_signed(tx),
            EthereumTxEnvelope::Eip1559(tx) => Self::from_signed(tx),
            EthereumTxEnvelope::Eip7702(tx) => Self::from_signed(tx),
            EthereumTxEnvelope::Eip4844(_) => return Err(UnsupportedEip4844),
        })
    }
}

impl From<Signed<TxCip64>> for CeloTxEnvelope {
    fn from(tx: Signed<TxCip64>) -> Self {
        Self::from_signed(tx)
    }
}

/// Implements [`Transaction`] by forwarding every method through the `$forward` macro.
macro_rules! impl_transaction {
    ($ty:ty, $forward:ident) => {
        impl Transaction for $ty {
            fn chain_id(&self) -> Option<ChainId> {
                $forward!(self, chain_id)
            }

            fn nonce(&self) -> u64 {
                $forward!(self, nonce)
            }

            fn gas_limit(&self) -> u64 {
                $forward!(self, gas_limit)
            }

            fn gas_price(&self) -> Option<u128> {
                $forward!(self, gas_price)
            }

            fn max_fee_per_gas(&self) -> u128 {
                $forward!(self, max_fee_per_gas)
            }

            fn max_priority_fee_per_gas(&self) -> Option<u128> {
                $forward!(self, max_priority_fee_per_gas)
            }

            fn max_fee_per_blob_gas(&self) -> Option<u128> {
                $forward!(self, max_fee_per_blob_gas)
            }

            fn priority_fee_or_price(&self) -> u128 {
                $forward!(self, priority_fee_or_price)
            }

            fn effective_gas_price(&self, base_fee: Option<u64>) -> u128 {
                $forward!(self, effective_gas_price, base_fee)
            }

            fn is_dynamic_fee(&self) -> bool {
                $forward!(self, is_dynamic_fee)
            }

            fn kind(&self) -> TxKind {
                $forward!(self, kind)
            }

            fn is_create(&self) -> bool {
                $forward!(self, is_create)
            }

            fn value(&self) -> U256 {
                $forward!(self, value)
            }

            fn input(&self) -> &Bytes {
                $forward!(self, input)
            }

            fn access_list(&self) -> Option<&AccessList> {
                $forward!(self, access_list)
            }

            fn blob_versioned_hashes(&self) -> Option<&[B256]> {
                $forward!(self, blob_versioned_hashes)
            }

            fn authorization_list(&self) -> Option<&[SignedAuthorization]> {
                $forward!(self, authorization_list)
            }
        }
    };
}

macro_rules! to_eip1559 {
    ($this:expr, $method:ident $(, $arg:expr)*) => {
        $this.inner.$method($($arg),*)
    };
}

macro_rules! to_body {
    ($this:expr, $method:ident $(, $arg:expr)*) => {
        match $this {
            CeloTypedTx::Op(tx) => tx.$method($($arg),*),
            CeloTypedTx::Cip64(tx) => tx.$method($($arg),*),
        }
    };
}

macro_rules! to_typed {
    ($this:expr, $method:ident $(, $arg:expr)*) => {
        $this.tx.$method($($arg),*)
    };
}

impl_transaction!(TxCip64, to_eip1559);
impl_transaction!(CeloTypedTx, to_body);
impl_transaction!(CeloTxEnvelope, to_typed);

impl Typed2718 for CeloTypedTx {
    fn ty(&self) -> u8 {
        match self {
            Self::Op(tx) => tx.ty(),
            Self::Cip64(tx) => tx.ty(),
        }
    }
}

impl Typed2718 for CeloTxEnvelope {
    fn ty(&self) -> u8 {
        self.tx.ty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_eips::eip2718::Decodable2718;
    use alloy_primitives::{Signature, address};

    #[test]
    fn cip64_roundtrip() {
        for fee_currency in [None, Some(address!("0x765DE816845861e75A25fCA122bb6898B8B1282a"))] {
            let tx = TxCip64 {
                inner: TxEip1559 { chain_id: 42220, gas_limit: 21_000, ..Default::default() },
                fee_currency,
            };
            let signed = Signed::new_unhashed(tx.clone(), Signature::test_signature());
            let encoded = signed.encoded_2718();
            assert_eq!(encoded[0], CIP64_TX_TYPE);
            let decoded = Signed::<TxCip64>::decode_2718(&mut encoded.as_slice()).unwrap();
            assert_eq!(decoded.tx(), &tx);

            let envelope = CeloTxEnvelope::from(signed);
            assert_eq!(envelope.ty(), CIP64_TX_TYPE);
            assert_eq!(envelope.as_cip64(), Some(&tx));
            assert_eq!(envelope.gas_limit(), 21_000);
            assert_eq!(envelope.enveloped_tx().map(|b| b.to_vec()), Some(encoded));
        }
    }

    #[test]
    fn rejects_eip4844() {
        let signed = Signed::new_unhashed(TxEip4844::default(), Signature::test_signature());
        assert_eq!(
            CeloTxEnvelope::try_from(EthereumTxEnvelope::<TxEip4844>::Eip4844(signed)),
            Err(UnsupportedEip4844)
        );
    }
}
