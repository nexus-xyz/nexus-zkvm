use nexus_vm::{rv32::RV32, NexusVMError};

use jolt_core::utils::errors::ProofVerifyError;

use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error(transparent)]
    VM(#[from] NexusVMError),

    #[error("Instruction isn't supported: {0}")]
    Unsupported(RV32),

    #[error(transparent)]
    ProofVerify(#[from] ProofVerifyError),
}
