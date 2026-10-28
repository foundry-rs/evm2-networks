//! Cobalt nonce-manager read ABI. Nonce mutation belongs to EIP-8130 transaction execution.

use alloy_primitives::{Bytes, U256};
use alloy_sol_types::{Panic, PanicKind, SolCall, SolError, SolInterface, sol};
use base_common_eip8130::NonceManagerSlots;
use evm2::{
    Evm, SpecId, Version,
    evm::precompile::PrecompileOutput,
    interpreter::{GasTracker, Host, Message},
    precompiles::{PrecompileError, PrecompileHalt, PrecompileResult},
    version::GasId,
};

use crate::{BaseEvmTypes, activation::DelegateCallNotAllowed};

sol! {
    /// The nonce manager's only externally callable method.
    #[allow(missing_docs)]
    interface INonceManager {
        error NonPayable();
        error ProtocolNonceNotSupported();

        function getNonce(address account, uint256 nonceKey) external view returns (uint64);
    }
}

use INonceManager::INonceManagerCalls as Call;

/// Executes the nonce-manager getter with Base's calldata and storage-read gas schedule.
pub(crate) fn run_nonce_manager(
    evm: &mut Evm<'_, BaseEvmTypes>,
    message: &Message<BaseEvmTypes>,
    gas: &mut GasTracker,
) -> PrecompileResult {
    if message.destination != message.code_address {
        return Err(PrecompileError::Revert(DelegateCallNotAllowed {}.abi_encode().into()));
    }
    if !message.value.is_zero() {
        return Err(PrecompileError::Revert(INonceManager::NonPayable {}.abi_encode().into()));
    }
    let words = (message.input.len() as u64).div_ceil(32);
    gas.spend(words.saturating_mul(6)).map_err(|_| PrecompileHalt::OutOfGas)?;

    let Some(selector) = message.input.get(..4) else {
        return Err(PrecompileError::Revert(Bytes::from_static(&[0; 4])));
    };
    let selector = <[u8; 4]>::try_from(selector).expect("four bytes");
    let call = match Call::abi_decode_validate(&message.input) {
        Ok(Call::getNonce(call)) => call,
        Err(error) => {
            let mut output = selector.to_vec();
            if Call::valid_selector(selector) {
                output.extend_from_slice(error.to_string().as_bytes());
            }
            return Err(PrecompileError::Revert(output.into()));
        }
    };
    let Some(slot) = NonceManagerSlots::nonce_slot(call.account, call.nonceKey) else {
        return Err(PrecompileError::Revert(
            INonceManager::ProtocolNonceNotSupported {}.abi_encode().into(),
        ));
    };

    // The reference reads the canonical system account even if the precompile is relocated.
    let load = evm.sload(&NonceManagerSlots::ADDRESS, &slot, false)?;
    let params = &Version::base(SpecId::OSAKA).gas_params;
    let mut cost = params.get(GasId::WarmStorageReadCost);
    if load.is_cold {
        cost += params.get(GasId::ColdStorageAdditionalCost);
    }
    gas.spend(cost).map_err(|_| PrecompileHalt::OutOfGas)?;

    let nonce = u64::try_from(load.value).map_err(|_| {
        PrecompileError::Revert(
            Panic { code: U256::from(PanicKind::UnderOverflow as u32) }.abi_encode().into(),
        )
    })?;
    Ok(PrecompileOutput::new(INonceManager::getNonceCall::abi_encode_returns(&nonce).into()))
}
