use nexus_sdk::{Prover, Verifiable, nova::seq::Nova};

fn main() {

    // expects for this program to be run from root of crate
    // expects example programs (`nexus-zkvm/examples`) to have been built with `cargo build -r`
    let pb = PathBuf::from(r"../target/riscv32i-unknown-none-elf/release/private_input");

    // generate public parameters
    println!("Setting up Nova public parameters...");
    let pp = Nova::Params::generate();

    // defaults to local proving
    let mut prover = Nova::new_from_file(&pb);

    println!("Proving execution of vm...");
    let proof = prover.prove(&pp);

    print!("Verifying execution...");
    proof.verify(&pp)?;

    println!("  Succeeded!");

}
