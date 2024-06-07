//! Default types and traits for use by zkVM + Jolt pipeline

pub use nexus_jolt::jolt_core::{
    self,
    jolt::vm::rv32i_vm::{RV32ISubtables, C, M, RV32I},
    poly::commitment::hyrax::HyraxScheme,
};

pub type F = ark_bn254::Fr;
pub type PCS = HyraxScheme<ark_bn254::G1Projective>;
pub type JoltPreprocessing = jolt_core::jolt::vm::JoltPreprocessing<F, PCS>;
pub type JoltProof = jolt_core::jolt::vm::JoltProof<C, M, F, PCS, RV32I, RV32ISubtables<F>>;
pub type JoltCommitments = jolt_core::jolt::vm::JoltCommitments<PCS>;
