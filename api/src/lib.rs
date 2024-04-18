//! Nexus Virtual Machine Host API

#![doc = include_str!("../README.md")]

/// RISC-V processing
pub mod riscv {
    pub mod interactive {
        pub use nexus_riscv::{
            load_elf,
            parse_elf,
            load_vm,
            eval,
        };
    }
    pub use nexus_riscv::{
        VMOpts,
        run_vm,
        error,
    };
}

/// Nexus VM
pub mod nvm {
    pub mod interactive {
        pub use nexus_riscv::nvm::{
            translate_elf,
            load_nvm,
        };
        pub use nexus_vm::eval::{
            NexusVM,
            eval,
        };
    }
    pub use nexus_vm::{
        run_nvm,
        error,
        trace::trace,
    };
    pub mod memory {
        pub use nexus_vm::memory::{
            trie::MerkleTrie,
            paged::Paged,
        };
    }
}

/// Nova-based provers
pub mod prover {
    pub mod prove {
        pub use nexus_prover::{
            estimate_size,
            prove_seq,
            prove_par,
            prove_par_com,
            compress,
            save_proof,
            load_proof
        };
    }
    pub mod verify {
        pub use nexus_prover::{
            verify_compressed,
        };
    }
}
