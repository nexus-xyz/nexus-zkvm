// An example of loading and running the NVM.

use nexus_api::nvm::{
    self,
    memory::{MerkleTrie, Paged},
    run_vm, NexusVM, VMOpts,
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

    run_vm::<MerkleTrie>(&opts, true).expect("error running Nexus VM");

    // For this example we are using a built-in test VM, but using paged memory.
    run_vm::<Paged>(&opts, true).expect("error running Nexus VM");

    // expects example programs (`nexus-zkvm/examples`) to have been built with `cargo build -r`
    let pb = PathBuf::from(r"../target/riscv32i-unknown-none-elf/release/fib");

    // For this example we are using an ELF file, accessed through the single-entry interface.
    let opts = VMOpts {
        k: 1,
        machine: None,
        file: Some(pb.clone()),
    };

    run_vm::<MerkleTrie>(&opts, true).expect("error running Nexus VM");

    // For this example we are using an ELF file, accessed through the interactive interface.
    let mut vm: NexusVM<MerkleTrie> =
        nvm::interactive::load_elf(&pb).expect("error loading and parsing RISC-V VM");
    nvm::interactive::eval(&mut vm, true).expect("error running Nexus VM");
}
