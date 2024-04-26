// An example of loading and running a RISC-V VM.

use nexus_api::riscv::{interactive, run_vm, VMOpts};
use std::path::PathBuf;

fn main() {
    // For this example we are using a built-in test VM.
    // To use an ELF file, set the `file` field.
    let opts = VMOpts {
        k: 1,
        machine: Some(String::from("nop10")),
        file: None,
    };

    run_vm(&opts, true).expect("error running RISC-V VM");
    let pb = PathBuf::from(r"../target/riscv32i-unknown-none-elf/debug/fib");

    // For this example we are using an ELF file, accessed through the single-entry interface.
    let opts = VMOpts {
        k: 1,
        machine: None,
        file: Some(pb.clone()),
    };

    run_vm(&opts, true).expect("error running RISC-V VM");

    // For this example we are using an ELF file, accessed through the interactive interface.
    let mut vm = interactive::load_elf(&pb).expect("error loading RISC-V VM");
    interactive::eval(&mut vm, true).expect("error running RISC-V VM");
}
