// An example of loading and running the NVM.

use nexus_api::{
    config::vm::{NovaImpl, VmConfig},
    nvm::{self, memory::MerkleTrie, NexusVM},
    prover::{self},
    riscv::{self},
};
use std::path::PathBuf;

const CONFIG: VmConfig = VmConfig { k: 1, nova_impl: NovaImpl::Sequential };

fn main() {
    let pb = PathBuf::from(r"../target/riscv32i-unknown-none-elf/debug/private_input");

    println!("Setting up public parameters...");
    let public_params =
        prover::setup::gen_vm_pp(CONFIG.k, &()).expect("error generating public parameters");

    println!("Reading and translating vm...");
    let mut vm: NexusVM<MerkleTrie> =
        riscv::interactive::translate_elf(&pb).expect("error loading and translating RISC-V VM");
    vm.syscalls.set_input(&[0x06]);

    println!("Generating execution trace of vm...");
    let trace = nvm::interactive::trace(
        &mut vm,
        CONFIG.k,
        matches!(CONFIG.nova_impl, NovaImpl::Parallel),
    )
    .expect("error generating execution trace");

    println!("Proving execution...");
    let proof = prover::prove::prove_seq(&public_params, trace).expect("error proving execution");

    println!("Verifying execution...");
    proof
        .verify(&public_params, proof.step_num() as _)
        .expect("error verifying execution")
}
