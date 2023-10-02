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
        z: &[FpVar<F1>],
    ) -> Result<Vec<FpVar<F1>>, SynthesisError> {
        let x = &z[0];

        let x_square = x.square()?;
        let x_cube = x_square * x;

        let y: FpVar<F1> = x + x_cube + &FpVar::Constant(5u64.into());

        Ok(vec![y])
    }
}

fn main() -> Result<(), ProofError> {
    let num_steps = 10;
    let circuit = &CubicCircuit;

    let t = Instant::now();
    let pp = gen_pp(circuit).unwrap();
    println!("PP gen {:?}", t.elapsed());

    let z_0 = vec![F1::ONE];
    let mut recursive_snark = RecursiveSNARK::new(&pp, &z_0);

    for _ in 0..num_steps {
        let t = Instant::now();
        recursive_snark = RecursiveSNARK::prove_step(recursive_snark, circuit).unwrap();
        println!("step {:?}", t.elapsed());
    }

    let t = Instant::now();
    recursive_snark.verify(num_steps).unwrap();
    println!("verify {:?}", t.elapsed());

    Ok(())
}
