/// The core crate is intended to provide a unified API for access to the zkvm that can be consumed as needed
/// by the various demand- and supply-side components, such as the network orchestrator, the SDK, and the CLI.

/// RISC-V processing
pub mod nvm {
    pub use nexus_vm::{
        elf::ElfFile,
        error::VMError,
        trace::{bb_trace, k_trace, BBTrace, UniformTrace},
    };
}
