// An example of loading and running the NVM.

use nexus_api::{
    nvm::{
        self,
        memory::{MerkleTrie, Paged},
        NexusVM,
    },
    riscv::{self, run_as_nvm, VMOpts},
};
use std::path::PathBuf;

fn main() {
    // For this example we are using a built-in test VM.
    // To use an ELF file, set the `file` field.
    let opts = VMOpts {
        k: 1,
        machine: Some(String::from("nop10")),
        file: None,
    };

    run_as_nvm::<MerkleTrie>(&opts, true, true).expect("error running Nexus VM");

    // For this example we are using a built-in test VM, but using paged memory.
    run_as_nvm::<Paged>(&opts, true, true).expect("error running Nexus VM");
    let pb = PathBuf::from(r"../target/riscv32i-unknown-none-elf/debug/fib");

    // For this example we are using an ELF file, accessed through the single-entry interface.
    let opts = VMOpts {
        k: 1,
        machine: None,
        file: Some(pb.clone()),
    };

    run_as_nvm::<MerkleTrie>(&opts, true, true).expect("error running Nexus VM");

    // For this example we are using an ELF file, accessed through the interactive interface.
    let mut vm: NexusVM<MerkleTrie> =
        riscv::interactive::translate_elf(&pb).expect("error loading and translating RISC-V VM");
    nvm::interactive::eval(&mut vm, true).expect("error running Nexus VM");
}
