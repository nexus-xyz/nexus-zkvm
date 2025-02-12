//! The core crate is intended to provide a unified API for access to the zkvm that can be consumed as needed
//! by the various demand- and supply-side components, such as the network orchestrator, the SDK, and the CLI.

/// RISC-V processing
pub mod nvm {
    pub use nexus_vm::{
        elf::{ElfError, ElfFile},
        emulator::View,
        error::VMError,
        trace::{bb_trace, k_trace, BBTrace, UniformTrace},
    };
    pub mod internals {
        pub use nexus_vm::emulator::{
            convert_instruction, elf_into_program_info, io_entries_into_vec, map_into_io_entries,
            slice_into_io_entries, LinearEmulator, LinearMemoryLayout, MemoryInitializationEntry,
            ProgramInfo, PublicOutputEntry,
        };
    }
}

/// Stwo proving
pub mod stwo {
    pub use nexus_vm_prover::{prove, verify, Proof, ProvingError, VerificationError};
}
