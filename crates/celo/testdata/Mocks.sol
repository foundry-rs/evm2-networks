// SPDX-License-Identifier: MIT
// Test contracts for `src/tests.rs`. Rebuild the `.bin-runtime` files with solc 0.8.26:
// solc --evm-version cancun --optimize --bin-runtime -o testdata --overwrite testdata/Mocks.sol
pragma solidity ^0.8.26;

/// Storage: slot 0 currency, slot 1 numerator, slot 2 denominator, slot 3 intrinsic gas.
contract Directory {
    address currency;
    uint256 numerator;
    uint256 denominator;
    uint256 intrinsicGas;

    function getCurrencies() external view returns (address[] memory currencies) {
        currencies = new address[](1);
        currencies[0] = currency;
    }

    function getExchangeRate(address) external view returns (uint256, uint256) {
        return (numerator, denominator);
    }

    function getCurrencyConfig(address) external view returns (address, uint256) {
        return (address(0), intrinsicGas);
    }
}

/// Storage: slot 0 balances, slot 1 failure mode (1 debit fails, 2 credit fails).
contract FeeToken {
    mapping(address => uint256) public balanceOf;
    uint256 failure;

    event Debit(address from, uint256 value);
    event Credit(address from, address feeRecipient, address communityFund, uint256 refund, uint256 tip, uint256 baseFee);
    event Probe(uint256 transientValue, uint256 gasPrice);

    function debitGasFees(address from, uint256 value) external {
        require(msg.sender == address(0) && failure != 1);
        balanceOf[from] -= value;
        assembly {
            tstore(0, 1)
        }
        emit Debit(from, value);
    }

    function creditGasFees(
        address from,
        address feeRecipient,
        address,
        address communityFund,
        uint256 refund,
        uint256 tip,
        uint256,
        uint256 baseFee
    ) external {
        require(msg.sender == address(0) && failure != 2);
        balanceOf[from] += refund;
        balanceOf[feeRecipient] += tip;
        balanceOf[communityFund] += baseFee;
        emit Credit(from, feeRecipient, communityFund, refund, tip, baseFee);
    }

    function probe() external {
        uint256 value;
        assembly {
            value := tload(0)
        }
        emit Probe(value, tx.gasprice);
    }

    function boom() external pure {
        revert();
    }
}

/// Calls the transfer precompile like the CELO token, and reports the cost of `BALANCE(to)`
/// afterwards.
contract GoldToken {
    event BalanceCost(uint256 gas);

    function transfer(address to, uint256 value) external {
        (bool ok,) = address(0xfd).call(abi.encode(msg.sender, to, value));
        require(ok);
        uint256 before = gasleft();
        uint256 balance = to.balance;
        uint256 cost = before - gasleft();
        emit BalanceCost(cost + (balance & 0));
    }
}

/// Reports the cost of touching the directory, to check that loading the fee currency context
/// leaves no warmth behind.
contract Prober {
    event Costs(uint256 balance, uint256 call);

    function probe(address directory) external {
        uint256 before = gasleft();
        uint256 balance = directory.balance;
        uint256 middle = gasleft();
        (bool ok,) = directory.staticcall(abi.encodeWithSignature("getExchangeRate(address)", address(0)));
        uint256 after_ = gasleft();
        require(ok);
        emit Costs(before - middle + (balance & 0), middle - after_);
    }
}
