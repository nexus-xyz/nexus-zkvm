//! Nexus Virtual Machine Host API

#![doc = include_str!("../README.md")]

/// Configurations
pub mod config {
    pub use nexus_config::{Config, MiscConfig};
    pub mod vm {
        pub use nexus_config::vm::*;
    }
    pub mod network {
        pub use nexus_config::network::*;
    }
}

/// RISC-V processing
pub mod nvm {
    pub mod interactive {
        pub use nexus_vm::{eval, load_elf, parse_elf, trace::trace, trace::Trace};
    }
    pub use nexus_vm::{error::NexusVMError, eval::NexusVM, run_vm, trace_vm, VMOpts};
    pub mod memory {
        pub use nexus_vm::memory::{Memory, paged::Paged, path::Path, trie::MerkleTrie};
    }
}

pub mod prover;
