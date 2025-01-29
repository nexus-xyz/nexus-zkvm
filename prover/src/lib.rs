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

pub fn prove<I>(
    trace: &impl nexus_vm::trace::Trace,
    view: &nexus_vm::emulator::View,
    public_output_addresses: I,
) -> Result<Proof, ProvingError>
where
    I: IntoIterator<Item = u32>,
{
    machine::Machine::<machine::BaseComponents>::prove(trace, view, public_output_addresses)
}

pub fn verify(proof: Proof) -> Result<(), VerificationError> {
    machine::Machine::<machine::BaseComponents>::verify(proof)
}
