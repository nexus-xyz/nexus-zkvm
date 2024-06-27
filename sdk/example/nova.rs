use nexus_sdk::{Prover, Verifiable, nova::seq::Nova};

fn main() {

    // expects for this program to be run from root of crate
    // expects example programs (`nexus-zkvm/examples`) to have been built with `cargo build -r`
    let pb = PathBuf::from(r"../target/riscv32i-unknown-none-elf/release/private_input");

    // generate public parameters
    println!("Setting up Nova public parameters...");
    let pp = Nova::gen_pp();

    // defaults to local proving
    let initd_prover = Nova::new_from_file(&pb);

    println!("Generating execution trace of vm...");
    let tracd_prover = initd_prover.trace(&[0x06]);

    println!("Proving execution of vm...");
    let proof = prover.prover(&pp);

    print!("Verifying execution...");
    proof.verify(&pp)?;

    println!("  Succeeded!");

}
