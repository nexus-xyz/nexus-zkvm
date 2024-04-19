//! Nexus Virtual Machine Host API

#![doc = include_str!("../README.md")]

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
        pub use nexus_vm::eval::{
            NexusVM,
            eval,
        };
    }
    pub use nexus_vm::error::NexusVMError;
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
    pub mod prove {
        pub use nexus_prover::{
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
