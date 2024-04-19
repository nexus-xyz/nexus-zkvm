// An example of loading and running the NVM.

use std::path::PathBuf;
use nexus_api::{riscv::{self}, nvm::{self, NexusVM, memory::MerkleTrie}};

fn main() {
    let pb = PathBuf::from(r"../target/riscv32i-unknown-none-elf/debug/private_input");

    let mut vm: NexusVM<MerkleTrie> = riscv::interactive::translate_elf(&pb).expect("error loading and translating RISC-V VM");
    vm.syscalls.set_input(&[0x06]);

    //let trace = nvm::interactive::trace(&mut vm, 1, true).expect("error running Nexus VM")?;
}
