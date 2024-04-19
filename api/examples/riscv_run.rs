// An example of loading and running a RISC-V VM.

use nexus_api::riscv::{VMOpts, run_vm, interactive};

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

    // For this example we are using an ELF file, accessed through the single-entry interface.
    let opts = VMOpts {
        k: 1,
        nop: Some(10),
        loopk: None,
        machine: None,
        file: None,
    };

    run_vm(&opts, true).expect("error running RISC-V VM");

    // For this example we are using an ELF file, accessed through the interactive interface.
    let vm  = interactive::load_elf().expect("error loading RISC-V VM");
    let res = interactive::eval(vm, true).expect("error running RISC-V VM");
}
