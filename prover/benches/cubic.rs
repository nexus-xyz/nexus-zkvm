use std::time::Instant;

use nexus_prover::types::*;
use nexus_prover::error::*;
use nexus_prover::pp::*;

struct CubicCircuit;

impl StepCircuit<F1> for CubicCircuit {
    const ARITY: usize = 1;

    fn generate_constraints(
        &self,
        _cs: CS,
        _k: &FpVar<F1>,
        z: &[FpVar<F1>],
    ) -> Result<Vec<FpVar<F1>>, SynthesisError> {
        let x = &z[0];
        let x_square = x.square()?;
        let x_cube = x_square * x;
        let y = x + x_cube + &FpVar::Constant(5u64.into());
        Ok(vec![y])
    }
}

fn main() -> Result<(), ProofError> {
    let num_steps = 10;
    let circuit = &CubicCircuit;

    let t = Instant::now();
    let pp = gen_pp(circuit)?;
    println!("PP gen {:?}", t.elapsed());

    let z_0 = vec![F1::ONE];
    let mut proof = IVCProof::new(&pp, &z_0);

    for _ in 0..num_steps {
        let t = Instant::now();
        proof = IVCProof::prove_step(proof, circuit)?;
        println!("step {:?}", t.elapsed());
    }

    let t = Instant::now();
    proof.verify(num_steps)?;
    println!("verify {:?}", t.elapsed());

    Ok(())
}
