//! Nexus Virtual Machine Host API

#![doc = include_str!("../README.md")]

/// Configurations
pub mod config {
    pub mod vm {
        pub use nexus_config::vm::*;
    }
}

/// RISC-V processing
pub mod riscv {
    pub mod interactive {
        pub use nexus_riscv::{
            load_elf,
            parse_elf,
            nvm::translate_elf,
            eval,
        };
    }
    pub use nexus_riscv::{
        VMOpts,
        run_vm,
        nvm::run_as_nvm,
        error::VMError,
    };
}

/// Nexus VM
pub mod nvm {
    pub mod interactive {
        pub use nexus_vm::{
            eval::eval,
            trace::trace,
        };
    }
    pub use nexus_vm::{
        eval::NexusVM,
        error::NexusVMError,
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
    pub use nexus_prover::error::ProofError;
    pub mod setup {
        pub use nexus_prover::pp::{
            gen_pp,
            gen_vm_pp,
            save_pp,
            load_pp,
            gen_to_file,
            gen_or_load,
        };
    }
    pub mod prove {
        pub use nexus_prover::{
            run,
            prove_seq,
            prove_par,
            prove_par_com,
            compress,
            save_proof,
            load_proof,
        };
    }
    pub mod verify {
        pub use nexus_prover::{
            verify_compressed,
        };
    }
}
