// An example of loading and running the NVM.

use nexus_api::{
    riscv::VMOpts,
    nvm::{
        eval::{NexusVM, eval},
        memory::trie::MerkleTrie,
    },
};

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

    let mut vm: NexusVM<MerkleTrie> = load_nvm::<MerkleTrie>::(&opts).expect("error loading RISC-V");
    eval(&mut vm, true).expect("error running program");

    // For this example we are using an ELF file, accessed through the single-entry interface.
    let opts = VMOpts {
        k: 1,
        nop: Some(10),
        loopk: None,
        machine: None,
        file: None,
    };

    let mut vm: NexusVM<MerkleTrie> = load_nvm::<MerkleTrie>::(&opts).expect("error loading RISC-V");
    eval(&mut vm, true).expect("error running program");

    // For this example we are using an ELF file, accessed through the interactive interface.
    let vm  = interactive::translate_elf().expect("error loading RISC-V VM");
    let res = interactive::eval(vm, true).expect("error running RISC-V VM");
}
