#![feature(portable_simd, iter_array_chunks)]
// Need this feature to use the `borrowing_sub` method
#![feature(bigint_helper_methods)]

pub mod chips;
pub mod components;
pub mod extensions;
pub mod trace;

pub use extensions::ExtensionComponent;

pub mod column;
pub mod traits;
pub mod virtual_column;

pub mod machine;

#[cfg(test)]
mod test_utils;

use nexus_vm::emulator::InternalView;
pub(crate) use nexus_vm::WORD_SIZE;

pub use machine::Proof;

pub use stwo::{core::verifier::VerificationError, prover::ProvingError};

pub fn prove(
    trace: &impl nexus_vm::trace::Trace,
    view: &nexus_vm::emulator::View,
) -> Result<Proof, ProvingError> {
    machine::Machine::<machine::BaseComponent>::prove(trace, view)
}

pub fn verify(proof: Proof, view: &nexus_vm::emulator::View) -> Result<(), VerificationError> {
    machine::Machine::<machine::BaseComponent>::verify(
        proof,
        view.get_program_memory(),
        view.view_associated_data().as_deref().unwrap_or_default(),
        &[
            // preprocessed trace is sensitive to this ordering
            view.get_ro_initial_memory(),
            view.get_rw_initial_memory(),
            view.get_public_input(),
        ]
        .concat(),
        view.get_exit_code(),
        view.get_public_output(),
    )
}

pub fn prove_with_extensions(
    extensions: &[ExtensionComponent],
    trace: &impl nexus_vm::trace::Trace,
    view: &nexus_vm::emulator::View,
) -> Result<Proof, ProvingError> {
    machine::Machine::<machine::BaseComponent>::prove_with_extensions(extensions, trace, view)
}

pub fn verify_with_extensions(
    extensions: &[ExtensionComponent],
    proof: Proof,
    view: &nexus_vm::emulator::View,
) -> Result<(), VerificationError> {
    machine::Machine::<machine::BaseComponent>::verify_with_extensions(
        extensions,
        proof,
        view.get_program_memory(),
        view.view_associated_data().as_deref().unwrap_or_default(),
        &[
            view.get_ro_initial_memory(),
            view.get_rw_initial_memory(),
            view.get_public_input(),
        ]
        .concat(),
        view.get_exit_code(),
        view.get_public_output(),
    )
}
