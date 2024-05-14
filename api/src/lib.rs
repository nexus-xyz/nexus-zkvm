//! Nexus Virtual Machine Host API

#![doc = include_str!("../README.md")]

/// Configurations
pub mod config {
    pub mod vm {
        pub use nexus_config::vm::*;
    }
}

/// RISC-V processing
pub mod nvm {
    pub mod interactive {
        pub use nexus_vm::{eval, load_elf, parse_elf};
    }
    pub use nexus_vm::{error::NexusVMError, eval::NexusVM, run_vm, trace_vm, VMOpts};
    pub mod memory {
        pub use nexus_vm::memory::{paged::Paged, trie::MerkleTrie};
    }
}

/// Nova-based provers
pub mod prover {
    pub use nexus_prover::error::ProofError;
    pub mod setup {
        pub use nexus_prover::pp::{gen_or_load, gen_pp, gen_to_file, gen_vm_pp, load_pp, save_pp};
    }
    pub mod prove {
        pub use nexus_prover::{
            compress, load_proof, prove_par, prove_par_com, prove_seq, run, save_proof,
        };
    }
    pub mod verify {
        pub use nexus_prover::verify_compressed;
    }
}
