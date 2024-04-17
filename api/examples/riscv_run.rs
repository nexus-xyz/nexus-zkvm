// An example of loading and running a RISC-V VM.

use nexus_api::riscv::{VMOpts, run_vm};

fn main() {
    // For this example we are using a built-in test VM.
    // To use an ELF file, set the `file` field.
    let opts = VMOpts {
        k: 1,
        nop: Some(10),
        loopk: None,
        machine: None,
        file: None,
    };

    run_vm(&opts, true).expect("error running RISC-V VM");
}
