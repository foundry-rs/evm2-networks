//! BSC system accounts and system transactions.
//!
//! Port of bsc's `consensus/parlia` system-contract set and `IsSystemTransaction`.

use alloy_consensus::Transaction;
use alloy_primitives::{Address, address};
use evm2::ethereum::TxEnvelope;

/// Address credited with every transaction fee (gas and blob fees). The Parlia engine
/// distributes it to validators in the block's system transactions.
pub const BSC_SYSTEM_ADDRESS: Address = address!("0xfffffffffffffffffffffffffffffffffffffffe");

/// System contracts that system transactions may call.
pub const BSC_SYSTEM_CONTRACTS: [Address; 14] = [
    // ValidatorContract
    address!("0x0000000000000000000000000000000000001000"),
    // SlashContract
    address!("0x0000000000000000000000000000000000001001"),
    // SystemRewardContract
    address!("0x0000000000000000000000000000000000001002"),
    // LightClientContract
    address!("0x0000000000000000000000000000000000001003"),
    // TokenHubContract
    address!("0x0000000000000000000000000000000000001004"),
    // RelayerIncentivizeContract
    address!("0x0000000000000000000000000000000000001005"),
    // RelayerHubContract
    address!("0x0000000000000000000000000000000000001006"),
    // GovHubContract
    address!("0x0000000000000000000000000000000000001007"),
    // CrossChainContract
    address!("0x0000000000000000000000000000000000002000"),
    // StakeHubContract
    address!("0x0000000000000000000000000000000000002002"),
    // GovernorContract
    address!("0x0000000000000000000000000000000000002004"),
    // GovTokenContract
    address!("0x0000000000000000000000000000000000002005"),
    // TimelockContract
    address!("0x0000000000000000000000000000000000002006"),
    // TokenRecoverPortalContract
    address!("0x0000000000000000000000000000000000003000"),
];

/// Returns `true` if `address` is a BSC system contract.
pub fn is_bsc_system_contract(address: &Address) -> bool {
    BSC_SYSTEM_CONTRACTS.contains(address)
}

/// Returns `true` if `tx`, sent by `sender` in a block with `coinbase`, is a BSC system
/// transaction.
///
/// System transactions are calls from the block's validator to a system contract at a zero
/// effective gas price (with a zero base fee). The Parlia engine applies them at the end of the
/// block with dedicated rules, so they are not executable through the transaction registry.
pub fn is_bsc_system_transaction(tx: &TxEnvelope, sender: Address, coinbase: Address) -> bool {
    sender == coinbase
        && tx.to().is_some_and(|to| is_bsc_system_contract(&to))
        && tx.effective_gas_price(Some(0)) == 0
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_consensus::{TxEip1559, TxLegacy};
    use alloy_primitives::TxKind;

    #[test]
    fn system_transactions() {
        let coinbase = address!("0x5cf810ab8c718ac065b45f892a5badab2b2946b9");
        let validator_contract = TxKind::Call(BSC_SYSTEM_CONTRACTS[0]);
        let legacy =
            |to, gas_price| TxEnvelope::Legacy(TxLegacy { to, gas_price, ..Default::default() });

        assert!(is_bsc_system_transaction(&legacy(validator_contract, 0), coinbase, coinbase));
        assert!(!is_bsc_system_transaction(&legacy(validator_contract, 1), coinbase, coinbase));
        assert!(!is_bsc_system_transaction(
            &legacy(validator_contract, 0),
            Address::ZERO,
            coinbase
        ));
        // StakingContract (0x2001) is not in Parlia's system-contract set.
        let staking = TxKind::Call(address!("0x0000000000000000000000000000000000002001"));
        assert!(!is_bsc_system_transaction(&legacy(staking, 0), coinbase, coinbase));
        assert!(!is_bsc_system_transaction(&legacy(TxKind::Create, 0), coinbase, coinbase));

        // EIP-1559: the effective price at a zero base fee is the priority fee.
        let eip1559 = |max_priority_fee_per_gas| {
            TxEnvelope::Eip1559(TxEip1559 {
                to: validator_contract,
                max_fee_per_gas: 10,
                max_priority_fee_per_gas,
                ..Default::default()
            })
        };
        assert!(is_bsc_system_transaction(&eip1559(0), coinbase, coinbase));
        assert!(!is_bsc_system_transaction(&eip1559(1), coinbase, coinbase));
    }
}
