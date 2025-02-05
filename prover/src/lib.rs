pub mod chips;
pub mod components;
pub mod trace;

pub mod column;
pub mod traits;
pub mod virtual_column;

pub mod machine;

#[cfg(test)]
mod test_utils;

pub(crate) use nexus_vm::WORD_SIZE;

pub use machine::Proof;

pub use stwo_prover::core::prover::{ProvingError, VerificationError};

pub fn prove(
    trace: &impl nexus_vm::trace::Trace,
    view: &nexus_vm::emulator::View,
) -> Result<Proof, ProvingError> {
    machine::Machine::<machine::BaseComponents>::prove(trace, view)
}

pub fn verify(
    proof: Proof,
    program_info: &nexus_vm::emulator::ProgramInfo,
    init_memory: &[nexus_vm::emulator::MemoryInitializationEntry],
    exit_code: &[nexus_vm::emulator::PublicOutputEntry],
    output_memory: &[nexus_vm::emulator::PublicOutputEntry],
) -> Result<(), VerificationError> {
    machine::Machine::<machine::BaseComponents>::verify(
        proof,
        program_info,
        init_memory,
        exit_code,
        output_memory,
    )
}
