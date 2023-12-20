// An example of loading and running a RISC-V VM.

use nexus_api::{
    riscv::{VMOpts, nvm::load_nvm},
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

    let mut vm: NexusVM<MerkleTrie> = load_nvm(&opts).expect("error loading RISC-V");
    eval(&mut vm, true).expect("error running program");
}

