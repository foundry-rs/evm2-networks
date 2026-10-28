//! Arbitrum precompiles.
//!
//! Port of Nitro's precompile sets (`gethhook/geth-hook.go`) and of part of its ArbOS
//! precompiles (`precompiles/`):
//!
//! | ArbOS version | Ethereum precompiles                                          |
//! |---------------|---------------------------------------------------------------|
//! | Before 30     | Berlin set                                                    |
//! | 30 to 49      | Cancun set (with KZG) plus RIP-7212 P256 (`0x100`, 3,450 gas) |
//! | From 50       | Osaka set (BLS12-381, Osaka modexp, P256 at 6,900 gas)        |
//!
//! The ArbOS precompiles live at `0x64`-`0x74`, `0xff` and `0xa4b05`. Each is installed from the
//! ArbOS version that introduced it, so it is warm and its address has no code, as on Nitro.
//! [`ArbSys`](ARB_SYS_ADDRESS), [`ArbInfo`](ARB_INFO_ADDRESS) and the getters of
//! [`ArbGasInfo`](ARB_GAS_INFO_ADDRESS) are ported, and `ArbDebug` fails as on chains without debug
//! mode. Calling any other ArbOS precompile or method aborts the transaction with a fatal
//! [`ArbOsPrecompileUnsupported`] error rather than diverging silently.
//!
//! The ported methods follow Nitro's precompile framework (`precompiles/precompile.go`):
//!
//! - A call with an unknown or inactive selector, malformed arguments, value sent to a non-payable
//!   method, or a `view` method called through `DELEGATECALL` or `CALLCODE` reverts and consumes
//!   all gas.
//! - Methods that read the ArbOS state pay 800 gas to open it, and 800 gas per storage read.
//! - Arguments and results cost 3 gas per 32-byte word.

use crate::{
    ARBOS_ADDRESS, ArbEvm, ArbEvmTypes, ArbOsVersion,
    state::{ArbOsStorage, l1_pricing, l2_pricing},
};
use alloc::{borrow::Cow, vec::Vec};
use alloy_primitives::{Address, Bytes, U256, address, uint};
use alloy_sol_types::{SolError, SolInterface, SolValue, sol};
use core::{error::Error, fmt};
use evm2::{
    Precompiles, SpecId,
    evm::precompile::PrecompileOutput,
    interpreter::{GasTracker, Host, Message, MessageKind},
    precompiles::{
        P256VERIFY, Precompile, PrecompileError, PrecompileHalt, PrecompileId, PrecompileResult,
    },
};

/// `ArbSys` precompile address: L2 block and chain information.
pub const ARB_SYS_ADDRESS: Address = address!("0x0000000000000000000000000000000000000064");
/// `ArbInfo` precompile address: account balance and code lookups.
pub const ARB_INFO_ADDRESS: Address = address!("0x0000000000000000000000000000000000000065");
/// `ArbGasInfo` precompile address: gas pricing information.
pub const ARB_GAS_INFO_ADDRESS: Address = address!("0x000000000000000000000000000000000000006c");
/// `ArbDebug` precompile address, only enabled on debug chains.
pub const ARB_DEBUG_ADDRESS: Address = address!("0x00000000000000000000000000000000000000ff");

/// ArbOS precompiles that are not ported, with the ArbOS version introducing them.
const UNSUPPORTED_PRECOMPILES: [(&str, Address, ArbOsVersion); 14] = [
    ("ArbAddressTable", address!("0x0000000000000000000000000000000000000066"), ArbOsVersion::V1),
    ("ArbBLS", address!("0x0000000000000000000000000000000000000067"), ArbOsVersion::V1),
    ("ArbFunctionTable", address!("0x0000000000000000000000000000000000000068"), ArbOsVersion::V1),
    ("ArbosTest", address!("0x0000000000000000000000000000000000000069"), ArbOsVersion::V1),
    ("ArbOwnerPublic", address!("0x000000000000000000000000000000000000006b"), ArbOsVersion::V1),
    ("ArbAggregator", address!("0x000000000000000000000000000000000000006d"), ArbOsVersion::V1),
    ("ArbRetryableTx", address!("0x000000000000000000000000000000000000006e"), ArbOsVersion::V1),
    ("ArbStatistics", address!("0x000000000000000000000000000000000000006f"), ArbOsVersion::V1),
    ("ArbOwner", address!("0x0000000000000000000000000000000000000070"), ArbOsVersion::V1),
    ("ArbWasm", address!("0x0000000000000000000000000000000000000071"), ArbOsVersion::V30),
    ("ArbWasmCache", address!("0x0000000000000000000000000000000000000072"), ArbOsVersion::V30),
    (
        "ArbNativeTokenManager",
        address!("0x0000000000000000000000000000000000000073"),
        ArbOsVersion::V41,
    ),
    (
        "ArbFilteredTransactionsManager",
        address!("0x0000000000000000000000000000000000000074"),
        ArbOsVersion::V60,
    ),
    ("ArbosActs", ARBOS_ADDRESS, ArbOsVersion::V1),
];

/// Offset added to L1 contract addresses to alias them on L2.
const ADDRESS_ALIAS_OFFSET: U256 = uint!(0x1111000000000000000000000000000000001111_U256);
/// Gas per storage read (`storage.StorageReadCost`).
const STORAGE_READ_GAS: u64 = 800;
/// Gas per 32-byte word of arguments and results (`params.CopyGas`).
const COPY_GAS: u64 = 3;
/// Gas cost of an L2 storage write assumed by `ArbGasInfo` (`storage.StorageWriteCost`).
const STORAGE_WRITE_GAS: u64 = 20_000;
/// Transaction size assumed by `ArbGasInfo` price estimates (`AssumedSimpleTxSize`).
const ASSUMED_SIMPLE_TX_SIZE: u64 = 140;
/// Gas per non-zero calldata byte (EIP-2028).
const TX_DATA_NON_ZERO_GAS: u64 = 16;

/// Error aborting a transaction that calls an ArbOS precompile method this crate does not port.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ArbOsPrecompileUnsupported {
    /// Precompile name.
    pub precompile: &'static str,
    /// Method name, or `None` when the whole precompile is unsupported.
    pub method: Option<&'static str>,
}

impl fmt::Display for ArbOsPrecompileUnsupported {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.method {
            Some(method) => {
                write!(f, "ArbOS precompile method {}.{method} is not supported", self.precompile)
            }
            None => write!(f, "ArbOS precompile {} is not supported", self.precompile),
        }
    }
}

impl Error for ArbOsPrecompileUnsupported {}

sol! {
    /// Ported and known methods of `ArbSys`.
    #[allow(missing_docs)]
    interface IArbSys {
        function arbBlockNumber() external view returns (uint256);
        function arbBlockHash(uint256 arbBlockNum) external view returns (bytes32);
        function arbChainID() external view returns (uint256);
        function arbOSVersion() external view returns (uint256);
        function getStorageGasAvailable() external view returns (uint256);
        function isTopLevelCall() external view returns (bool);
        function mapL1SenderContractAddressToL2Alias(address sender, address unused) external pure returns (address);
        function wasMyCallersAddressAliased() external view returns (bool);
        function myCallersAddressWithoutAliasing() external view returns (address);
        function withdrawEth(address destination) external payable returns (uint256);
        function sendTxToL1(address destination, bytes calldata data) external payable returns (uint256);
        function sendMerkleTreeState() external view returns (uint256, bytes32, bytes32[] memory);

        error InvalidBlockNumber(uint256 requested, uint256 current);
    }

    /// Methods of `ArbInfo`.
    #[allow(missing_docs)]
    interface IArbInfo {
        function getBalance(address account) external view returns (uint256);
        function getCode(address account) external view returns (bytes memory);
    }

    /// Methods of `ArbGasInfo`.
    #[allow(missing_docs)]
    interface IArbGasInfo {
        function getPricesInWeiWithAggregator(address aggregator) external view returns (uint256, uint256, uint256, uint256, uint256, uint256);
        function getPricesInWei() external view returns (uint256, uint256, uint256, uint256, uint256, uint256);
        function getPricesInArbGasWithAggregator(address aggregator) external view returns (uint256, uint256, uint256);
        function getPricesInArbGas() external view returns (uint256, uint256, uint256);
        function getGasAccountingParams() external view returns (uint256, uint256, uint256);
        function getMaxTxGasLimit() external view returns (uint256);
        function getMinimumGasPrice() external view returns (uint256);
        function getL1BaseFeeEstimate() external view returns (uint256);
        function getL1BaseFeeEstimateInertia() external view returns (uint64);
        function getL1RewardRate() external view returns (uint64);
        function getL1RewardRecipient() external view returns (address);
        function getL1GasPriceEstimate() external view returns (uint256);
        function getCurrentTxL1GasFees() external view returns (uint256);
        function getGasBacklog() external view returns (uint64);
        function getPricingInertia() external view returns (uint64);
        function getGasBacklogTolerance() external view returns (uint64);
        function getL1PricingSurplus() external view returns (int256);
        function getPerBatchGasCharge() external view returns (int64);
        function getAmortizedCostCapBips() external view returns (uint64);
        function getL1FeesAvailable() external view returns (uint256);
        function getL1PricingEquilibrationUnits() external view returns (uint256);
        function getLastL1PricingUpdateTime() external view returns (uint64);
        function getL1PricingFundsDueForRewards() external view returns (uint256);
        function getL1PricingUnitsSinceUpdate() external view returns (uint64);
        function getLastL1PricingSurplus() external view returns (int256);
        function getMaxBlockGasLimit() external view returns (uint64);
        function getGasPricingConstraints() external view returns (uint64[3][] memory);
        function getMultiGasPricingConstraints() external view;
        function getMultiGasBaseFee() external view returns (uint256[] memory);
    }
}

/// State mutability of an ArbOS precompile method.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum Purity {
    Pure,
    View,
    Payable,
}

/// Runs the framework checks and charges preceding a method (`Precompile.Call`).
///
/// An inactive method, a `view` method called through `DELEGATECALL` or `CALLCODE`, or value sent
/// to a non-payable method reverts and consumes all gas. Non-pure methods then pay to open the
/// ArbOS state, and every method pays for its argument words.
fn enter(
    message: &Message<ArbEvmTypes>,
    gas: &mut GasTracker,
    address: Address,
    purity: Purity,
    active: bool,
) -> Result<(), PrecompileError> {
    if !active
        || (purity >= Purity::View && message.destination != address)
        || (purity < Purity::Payable && !message.value.is_zero())
    {
        return Err(revert_all(gas));
    }
    if purity != Purity::Pure {
        gas.spend(STORAGE_READ_GAS).map_err(|_| PrecompileHalt::OutOfGas)?;
    }
    let args_words = (message.input.len().saturating_sub(4) as u64).div_ceil(32);
    if gas.spend(COPY_GAS * args_words).is_err() {
        return Err(revert_all(gas));
    }
    Ok(())
}

/// Reverts consuming all gas, as Nitro does for calls its framework rejects.
fn revert_all(gas: &mut GasTracker) -> PrecompileError {
    gas.spend_all();
    PrecompileError::Revert(Bytes::new())
}

/// Reads an ArbOS state value, paying for the storage read.
fn read(
    evm: &mut ArbEvm<'_>,
    gas: &mut GasTracker,
    storage: ArbOsStorage,
    offset: u64,
) -> Result<U256, PrecompileError> {
    gas.spend(STORAGE_READ_GAS).map_err(|_| PrecompileHalt::OutOfGas)?;
    Ok(storage.get(evm.state_mut(), offset)?)
}

/// Charges the result words and returns the output.
fn finish(gas: &mut GasTracker, output: Vec<u8>) -> PrecompileResult {
    let words = (output.len() as u64).div_ceil(32);
    if gas.spend(COPY_GAS * words).is_err() {
        return Err(revert_all(gas));
    }
    Ok(PrecompileOutput::new(output.into()))
}

/// Executes `ArbSys` (port of `precompiles/ArbSys.go`).
fn arb_sys(
    evm: &mut ArbEvm<'_>,
    message: &Message<ArbEvmTypes>,
    gas: &mut GasTracker,
) -> PrecompileResult {
    use IArbSys::IArbSysCalls as C;
    let Ok(call) = C::abi_decode(&message.input) else { return Err(revert_all(gas)) };
    let purity = match call {
        C::mapL1SenderContractAddressToL2Alias(_) => Purity::Pure,
        C::withdrawEth(_) | C::sendTxToL1(_) => Purity::Payable,
        _ => Purity::View,
    };
    if purity == Purity::Payable
        && (message.caller_is_static || message.kind == MessageKind::StaticCall)
    {
        return Err(revert_all(gas));
    }
    enter(message, gas, ARB_SYS_ADDRESS, purity, true)?;
    let version = evm.config_spec_id();
    // Call depth relative to the transaction's top-level frame (Nitro's `evm.Depth() - 1` inside
    // a precompile).
    let depth = message.depth.saturating_sub(evm.version().initial_call_depth);
    let unsupported = |method| {
        PrecompileError::fatal(ArbOsPrecompileUnsupported {
            precompile: "ArbSys",
            method: Some(method),
        })
    };
    let output = match call {
        C::arbBlockNumber(_) => evm.block().number.abi_encode(),
        C::arbBlockHash(IArbSys::arbBlockHashCall { arbBlockNum: requested }) => {
            let current = evm.block().number;
            if requested >= current || requested.saturating_add(U256::from(256)) < current {
                if !version.enables(ArbOsVersion::V11) {
                    return Err(PrecompileHalt::Other(Cow::Borrowed("invalid block number")).into());
                }
                let data = IArbSys::InvalidBlockNumber { requested, current }.abi_encode();
                gas.spend(COPY_GAS * (data.len() as u64).div_ceil(32))
                    .map_err(|_| PrecompileHalt::OutOfGas)?;
                return Err(PrecompileError::Revert(data.into()));
            }
            Host::block_hash(evm, &requested)?.abi_encode()
        }
        C::arbChainID(_) => U256::from(evm.version().chain_id).abi_encode(),
        C::arbOSVersion(_) => U256::from(55 + version as u64).abi_encode(),
        C::getStorageGasAvailable(_) => U256::ZERO.abi_encode(),
        C::isTopLevelCall(_) => (depth <= 1).abi_encode(),
        C::mapL1SenderContractAddressToL2Alias(call) => {
            let aliased = call.sender.into_word().into();
            Address::from_word(U256::wrapping_add(aliased, ADDRESS_ALIAS_OFFSET).into())
                .abi_encode()
        }
        // Only Nitro's L1-to-L2 transaction types alias their sender.
        C::wasMyCallersAddressAliased(_) => false.abi_encode(),
        // The caller of the frame calling the precompile: none for a transaction calling `ArbSys`
        // directly, the sender for the top-level frame.
        C::myCallersAddressWithoutAliasing(_) => match depth {
            0 => Address::ZERO.abi_encode(),
            1 => evm.ext().sender.abi_encode(),
            _ => return Err(unsupported("myCallersAddressWithoutAliasing")),
        },
        C::withdrawEth(_) => return Err(unsupported("withdrawEth")),
        C::sendTxToL1(_) => return Err(unsupported("sendTxToL1")),
        C::sendMerkleTreeState(_) => return Err(unsupported("sendMerkleTreeState")),
    };
    finish(gas, output)
}

/// Executes `ArbInfo` (port of `precompiles/ArbInfo.go`).
fn arb_info(
    evm: &mut ArbEvm<'_>,
    message: &Message<ArbEvmTypes>,
    gas: &mut GasTracker,
) -> PrecompileResult {
    use IArbInfo::IArbInfoCalls as C;
    let Ok(call) = C::abi_decode(&message.input) else { return Err(revert_all(gas)) };
    enter(message, gas, ARB_INFO_ADDRESS, Purity::View, true)?;
    let output = match call {
        C::getBalance(call) => {
            gas.spend(700).map_err(|_| PrecompileHalt::OutOfGas)?;
            evm.state_mut().account(&call.account)?.balance().abi_encode()
        }
        C::getCode(call) => {
            gas.spend(2_100).map_err(|_| PrecompileHalt::OutOfGas)?;
            let code = evm.state_mut().account(&call.account)?.load_code()?.original_bytes();
            gas.spend(COPY_GAS * (code.len() as u64).div_ceil(32))
                .map_err(|_| PrecompileHalt::OutOfGas)?;
            code.abi_encode()
        }
    };
    finish(gas, output)
}

/// Executes `ArbGasInfo` (port of the getters of `precompiles/ArbGasInfo.go`).
///
/// `uint64`, `uint256` and `int256` values are returned as stored, which is their ABI encoding.
fn arb_gas_info(
    evm: &mut ArbEvm<'_>,
    message: &Message<ArbEvmTypes>,
    gas: &mut GasTracker,
) -> PrecompileResult {
    use IArbGasInfo::IArbGasInfoCalls as C;
    let Ok(call) = C::abi_decode(&message.input) else { return Err(revert_all(gas)) };
    let version = evm.config_spec_id();
    let since = match call {
        C::getL1FeesAvailable(_) => ArbOsVersion::V10,
        C::getL1RewardRate(_) | C::getL1RewardRecipient(_) => ArbOsVersion::V11,
        C::getL1PricingEquilibrationUnits(_)
        | C::getLastL1PricingUpdateTime(_)
        | C::getL1PricingFundsDueForRewards(_)
        | C::getL1PricingUnitsSinceUpdate(_)
        | C::getLastL1PricingSurplus(_) => ArbOsVersion::V20,
        C::getMaxTxGasLimit(_) | C::getMaxBlockGasLimit(_) | C::getGasPricingConstraints(_) => {
            ArbOsVersion::V50
        }
        C::getMultiGasPricingConstraints(_) | C::getMultiGasBaseFee(_) => ArbOsVersion::V60,
        _ => ArbOsVersion::V1,
    };
    enter(message, gas, ARB_GAS_INFO_ADDRESS, Purity::View, version.enables(since))?;
    let (l1, l2) = (ArbOsStorage::L1_PRICING, ArbOsStorage::L2_PRICING);
    let basefee = evm.block().basefee;
    let stored = match call {
        C::getMaxTxGasLimit(_) => Some((l2, l2_pricing::PER_TX_GAS_LIMIT)),
        C::getMinimumGasPrice(_) => Some((l2, l2_pricing::MIN_BASE_FEE_WEI)),
        C::getL1BaseFeeEstimate(_) | C::getL1GasPriceEstimate(_) => {
            Some((l1, l1_pricing::PRICE_PER_UNIT))
        }
        C::getL1BaseFeeEstimateInertia(_) => Some((l1, l1_pricing::INERTIA)),
        C::getL1RewardRate(_) => Some((l1, l1_pricing::PER_UNIT_REWARD)),
        C::getGasBacklog(_) => Some((l2, l2_pricing::GAS_BACKLOG)),
        C::getPricingInertia(_) => Some((l2, l2_pricing::PRICING_INERTIA)),
        C::getGasBacklogTolerance(_) => Some((l2, l2_pricing::BACKLOG_TOLERANCE)),
        C::getAmortizedCostCapBips(_) => Some((l1, l1_pricing::AMORTIZED_COST_CAP_BIPS)),
        C::getL1FeesAvailable(_) => Some((l1, l1_pricing::L1_FEES_AVAILABLE)),
        C::getL1PricingEquilibrationUnits(_) => Some((l1, l1_pricing::EQUILIBRATION_UNITS)),
        C::getLastL1PricingUpdateTime(_) => Some((l1, l1_pricing::LAST_UPDATE_TIME)),
        C::getL1PricingFundsDueForRewards(_) => Some((l1, l1_pricing::FUNDS_DUE_FOR_REWARDS)),
        C::getL1PricingUnitsSinceUpdate(_) => Some((l1, l1_pricing::UNITS_SINCE_UPDATE)),
        C::getLastL1PricingSurplus(_) => Some((l1, l1_pricing::LAST_SURPLUS)),
        C::getMaxBlockGasLimit(_) => Some((l2, l2_pricing::PER_BLOCK_GAS_LIMIT)),
        _ => None,
    };
    if let Some((storage, offset)) = stored {
        let output = read(evm, gas, storage, offset)?.abi_encode();
        return finish(gas, output);
    }
    let unsupported = |method| {
        PrecompileError::fatal(ArbOsPrecompileUnsupported {
            precompile: "ArbGasInfo",
            method: Some(method),
        })
    };
    let output = match call {
        C::getPricesInWeiWithAggregator(_) | C::getPricesInWei(_) => {
            let wei_for_l1_calldata =
                read(evm, gas, l1, l1_pricing::PRICE_PER_UNIT)? * U256::from(TX_DATA_NON_ZERO_GAS);
            let per_l2_tx = wei_for_l1_calldata * U256::from(ASSUMED_SIMPLE_TX_SIZE);
            let wei_for_l2_storage = basefee * U256::from(STORAGE_WRITE_GAS);
            let base = if version.enables(ArbOsVersion::V4) {
                read(evm, gas, l2, l2_pricing::MIN_BASE_FEE_WEI)?.min(basefee)
            } else {
                basefee
            };
            (per_l2_tx, wei_for_l1_calldata, wei_for_l2_storage, base, basefee - base, basefee)
                .abi_encode_params()
        }
        C::getPricesInArbGasWithAggregator(_) | C::getPricesInArbGas(_) => {
            let wei_for_l1_calldata =
                read(evm, gas, l1, l1_pricing::PRICE_PER_UNIT)? * U256::from(TX_DATA_NON_ZERO_GAS);
            let gas_per_l2_tx = if version.enables(ArbOsVersion::V4) {
                (wei_for_l1_calldata * U256::from(ASSUMED_SIMPLE_TX_SIZE))
                    .checked_div(basefee)
                    .unwrap_or_default()
            } else {
                U256::from(ASSUMED_SIMPLE_TX_SIZE)
            };
            let gas_for_l1_calldata = wei_for_l1_calldata.checked_div(basefee).unwrap_or_default();
            (gas_per_l2_tx, gas_for_l1_calldata, U256::from(STORAGE_WRITE_GAS)).abi_encode_params()
        }
        C::getGasAccountingParams(_) => {
            let speed_limit = read(evm, gas, l2, l2_pricing::SPEED_LIMIT_PER_SECOND)?;
            let block_gas_limit = read(evm, gas, l2, l2_pricing::PER_BLOCK_GAS_LIMIT)?;
            (speed_limit, block_gas_limit, block_gas_limit).abi_encode_params()
        }
        C::getL1RewardRecipient(_) => {
            let recipient = read(evm, gas, l1, l1_pricing::PAY_REWARDS_TO)?;
            Address::from_word(recipient.into()).abi_encode()
        }
        C::getCurrentTxL1GasFees(_) => evm.ext().poster_fee.abi_encode(),
        // Nitro stores the per-batch gas cost as a signed 64-bit integer.
        C::getPerBatchGasCharge(_) => {
            let cost = read(evm, gas, l1, l1_pricing::PER_BATCH_GAS_COST)?;
            (cost.as_limbs()[0] as i64).abi_encode()
        }
        C::getGasPricingConstraints(_) => {
            let constraints = ArbOsStorage::GAS_CONSTRAINTS;
            let len = read(evm, gas, constraints, 0)?.saturating_to::<u64>();
            let mut values = Vec::with_capacity(len as usize);
            for index in 0..len {
                let constraint = constraints.open(&index.to_be_bytes());
                let mut value = [0u64; 3];
                for (offset, field) in (0..).zip(&mut value) {
                    *field = read(evm, gas, constraint, offset)?.saturating_to();
                }
                values.push(value);
            }
            values.abi_encode()
        }
        C::getL1PricingSurplus(_) => return Err(unsupported("getL1PricingSurplus")),
        C::getMultiGasPricingConstraints(_) => {
            return Err(unsupported("getMultiGasPricingConstraints"));
        }
        C::getMultiGasBaseFee(_) => return Err(unsupported("getMultiGasBaseFee")),
        _ => unreachable!("stored getters are handled above"),
    };
    finish(gas, output)
}

/// Executes `ArbDebug`, which takes all gas and fails on chains without debug mode.
fn arb_debug(
    _evm: &mut ArbEvm<'_>,
    _message: &Message<ArbEvmTypes>,
    _gas: &mut GasTracker,
) -> PrecompileResult {
    Err(PrecompileHalt::Other(Cow::Borrowed("debug precompiles are disabled")).into())
}

/// Executes an ArbOS precompile that is not ported, aborting the transaction.
fn arbos_unsupported(
    _evm: &mut ArbEvm<'_>,
    message: &Message<ArbEvmTypes>,
    _gas: &mut GasTracker,
) -> PrecompileResult {
    let (precompile, ..) = UNSUPPORTED_PRECOMPILES
        .into_iter()
        .find(|(_, address, _)| *address == message.call_target)
        .expect("registered unsupported precompile");
    Err(PrecompileError::fatal(ArbOsPrecompileUnsupported { precompile, method: None }))
}

/// Returns the Arbitrum precompiles for an ArbOS version.
pub fn arbitrum_precompiles(spec: ArbOsVersion) -> Precompiles<ArbEvmTypes> {
    let mut map = if spec.enables(ArbOsVersion::V50) {
        Precompiles::<ArbEvmTypes>::base(SpecId::OSAKA).as_map().clone()
    } else if spec.enables(ArbOsVersion::V30) {
        let mut map = Precompiles::<ArbEvmTypes>::base(SpecId::CANCUN).as_map().clone();
        map.insert(P256VERIFY());
        map
    } else {
        Precompiles::<ArbEvmTypes>::base(SpecId::BERLIN).as_map().clone()
    };
    map.extend([
        Precompile::new(ARB_SYS_ADDRESS, PrecompileId::custom("ArbSys"), arb_sys),
        Precompile::new(ARB_INFO_ADDRESS, PrecompileId::custom("ArbInfo"), arb_info),
        Precompile::new(ARB_GAS_INFO_ADDRESS, PrecompileId::custom("ArbGasInfo"), arb_gas_info),
        Precompile::new(ARB_DEBUG_ADDRESS, PrecompileId::custom("ArbDebug"), arb_debug),
    ]);
    map.extend(UNSUPPORTED_PRECOMPILES.into_iter().filter(|(.., since)| spec.enables(*since)).map(
        |(name, address, _)| {
            Precompile::new(address, PrecompileId::custom(name), arbos_unsupported)
        },
    ));
    Precompiles::new(Cow::Owned(map))
}
