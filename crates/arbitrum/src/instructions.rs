//! Arbitrum opcode overlays.
//!
//! Port of Nitro's changes to the inherited instruction set:
//!
//! - `NUMBER` returns the L1 block number, and `BLOCKHASH` returns the hashes of the 256 L1 blocks
//!   before it, which ArbOS records in its state (`TxProcessor.L1BlockNumber` and `L1BlockHash`).
//! - `GASPRICE` returns the price the transaction pays from ArbOS 3, which is the base fee when the
//!   tip is dropped (`TxProcessor.GasPriceOp`).
//! - `BLOBBASEFEE` fails: Arbitrum has no blobs.
//! - Code with a Stylus program prefix runs on Nitro's WASM runtime from ArbOS 30. evm2 has no WASM
//!   runtime, so executing a Stylus program aborts the transaction with [`StylusUnsupported`]
//!   instead of diverging silently.

use crate::{ArbEvm, ArbEvmTypes, ArbOsVersion, state::ArbOsStorage};
use alloy_primitives::{U256, hex};
use core::{error::Error, fmt};
use evm2::{
    AnyError, DatabaseError, ExecutionError, HostError,
    interpreter::{InstrStop, Word},
};
use evm2_macros::instruction;

/// Prefix of classic Stylus programs.
pub const STYLUS_PROGRAM_PREFIX: [u8; 3] = hex!("eff000");

/// Prefix of Stylus root programs, deployable from ArbOS 60.
pub const STYLUS_ROOT_PROGRAM_PREFIX: [u8; 3] = hex!("eff002");

/// Error aborting a transaction that executes a Stylus (WASM) program.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StylusUnsupported;

impl fmt::Display for StylusUnsupported {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Stylus programs are not supported")
    }
}

impl Error for StylusUnsupported {}

/// Returns whether `code` is a Stylus program Nitro would run on its WASM runtime.
///
/// Port of `state.IsStylusDeployableProgramPrefix`.
pub fn is_stylus_program(code: &[u8], version: ArbOsVersion) -> bool {
    if !version.enables(ArbOsVersion::V30) || code.len() <= STYLUS_PROGRAM_PREFIX.len() {
        return false;
    }
    code.starts_with(&STYLUS_PROGRAM_PREFIX)
        || (version.enables(ArbOsVersion::V60) && code.starts_with(&STYLUS_ROOT_PROGRAM_PREFIX))
}

/// `NUMBER`: the L1 block number.
#[instruction(EvmTypes = ArbEvmTypes)]
pub fn l1_block_number(cx: _) -> Result<out> {
    let number = current_l1_block_number(cx.state.host()).map_err(|error| cx.state.fail(error))?;
    *out = U256::from(number);
}

/// `BLOCKHASH`: the hash of one of the 256 L1 blocks before the current one.
#[instruction(EvmTypes = ArbEvmTypes)]
pub fn l1_blockhash(cx: _, [number]: [Word]) -> Result<out> {
    let host = cx.state.host();
    let hash = current_l1_block_number(host).and_then(|current| match u64::try_from(*number) {
        Ok(number) if number < current && number.saturating_add(256) >= current => {
            ArbOsStorage::BLOCKHASHES.get(host.state_mut(), 1 + number % 256)
        }
        _ => Ok(Word::ZERO),
    });
    *out = hash.map_err(|error| cx.state.fail(error))?;
}

/// Returns the L1 block number from the block environment, or else from the ArbOS state.
fn current_l1_block_number(host: &mut ArbEvm<'_>) -> Result<u64, DatabaseError> {
    match host.block().ext.l1_block_number {
        Some(number) => Ok(number),
        None => ArbOsStorage::BLOCKHASHES.get(host.state_mut(), 0).map(|n| n.saturating_to()),
    }
}

/// `GASPRICE`: the gas price the transaction pays from ArbOS 3, and its effective gas price
/// before.
#[instruction(EvmTypes = ArbEvmTypes)]
pub fn paid_gasprice(cx: _) -> out {
    let host = cx.state.host();
    *out = if host.config_spec_id().enables(ArbOsVersion::V3) {
        host.ext().paid_gas_price
    } else {
        cx.state.tx().gas_price
    };
}

/// `BLOBBASEFEE`: not supported on Arbitrum. Nitro fails the opcode, which consumes all gas.
#[instruction(EvmTypes = ArbEvmTypes)]
pub fn blobbasefee() -> Result {
    Err(InstrStop::NotActivated)
}

/// Undefined opcode `0xEF`, which starts every Stylus program.
///
/// Nitro checks the code of every frame before running it and hands Stylus programs to its WASM
/// runtime. A Stylus program fails at its first opcode in evm2, so this aborts the transaction
/// there; any other `0xEF` stays an undefined opcode.
#[instruction(EvmTypes = ArbEvmTypes)]
pub fn stylus_or_invalid(cx: _) -> Result {
    let version = cx.state.host().config_spec_id();
    if is_stylus_program(cx.state.message().code.original_byte_slice(), version) {
        let error = ExecutionError::Fatal(AnyError::new(StylusUnsupported));
        return Err(cx.state.fail(HostError::Execution(error)));
    }
    Err(InstrStop::OpcodeNotFound)
}
