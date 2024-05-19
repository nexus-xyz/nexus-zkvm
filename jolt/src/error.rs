use nexus_riscv::{rv32::RV32, VMError};

use jolt_core::utils::errors::ProofVerifyError;

use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error(transparent)]
    VM(#[from] VMError),

    #[error("Instruction isn't supported: {0}")]
    Unsupported(RV32),

    #[error(transparent)]
    ProofVerify(#[from] ProofVerifyError),

    #[error("memory access")]
    Memory(#[from] nexus_vm::error::NexusVMError),
}
