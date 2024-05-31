//! Nexus Virtual Machine Host API

#![doc = include_str!("../README.md")]

/// RISC-V processing
pub mod nvm {
    pub mod interactive {
        pub use nexus_vm::{eval, load_elf, parse_elf, trace::trace, trace::Trace};
    }
    pub use nexus_vm::{error::NexusVMError, eval::NexusVM, run_vm, trace_vm, VMOpts};
    pub mod memory {
        pub use nexus_vm::memory::{paged::Paged, path::Path, trie::MerkleTrie};
    }
}

pub mod config;
pub mod prover;
