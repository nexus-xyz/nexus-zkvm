use std::time::Instant;
use nexus_prover::error::*;
use nexus_prover::pp::*;

fn main() -> Result<(), ProofError> {
    println!("Generating public parameters for zkVM...");
    let t = Instant::now();
    let pp = gen_vm_pp()?;
    println!("Generation time: {:?}", t.elapsed());
    println!(
        "Primary Circuit {} x {}",
        pp.shape.num_vars, pp.shape.num_constraints
    );
    println!(
        "Secondary Circuit {} x {}",
        pp.shape_secondary.num_vars, pp.shape_secondary.num_constraints
    );
    Ok(())
}
