use std::fmt::Display;

use nexus_common::cpu::{InstructionExecutor, InstructionState};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PrecompileMetadata {
    pub author: &'static str,
    pub name: &'static str,
    pub description: &'static str,

    pub version_major: u16,
    pub version_minor: u16,
    pub version_patch: u16,
}

impl Display for PrecompileMetadata {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{} v{}.{}.{} by {}: {}",
            self.name,
            self.version_major,
            self.version_minor,
            self.version_patch,
            self.author,
            self.description
        )
    }
}

/// Generic placeholder trait for circuits used by the prover but provided by a precompile author.
pub trait PrecompileCircuit {}

/// A precompile's implementation
///
/// The `Precompile` trait is a combination of the `InstructionExecutor` and `InstructionState`
/// traits, which ensures that
pub trait PrecompileInstruction: InstructionExecutor + InstructionState {
    fn metadata() -> PrecompileMetadata;

    fn circuit() -> impl PrecompileCircuit;

    /// Calls the precompile with the given arguments, executed on the native host. This is used for
    /// testing and debugging purposes.
    fn native_call(rs1: u32, rs2: u32) -> u32;
}
