use std::time::Instant;
use nexus_zkvm::error::*;
use nexus_zkvm::pp::*;

fn main() -> Result<(), ProofError> {
    println!("Generating public parameters for zkVM...");
    let t = Instant::now();
    let pp = gen_vm_pp()?;
    println!("Generation time: {:?}", t.elapsed());
    show_pp(&pp);
    Ok(())
}
