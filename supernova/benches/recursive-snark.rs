use std::{marker::PhantomData, time::Duration};

use ark_crypto_primitives::sponge::poseidon::PoseidonSponge;
use ark_ff::PrimeField;
use ark_r1cs_std::fields::{fp::FpVar, FieldVar};
use ark_relations::r1cs::{ConstraintSystemRef, SynthesisError};

use criterion::*;
use supernova::{
    pedersen::PedersenCommitment, poseidon_config, PublicParams, RecursiveSNARK, StepCircuit,
};

type G1 = ark_pallas::PallasConfig;
type G2 = ark_vesta::VestaConfig;
type C1 = PedersenCommitment<ark_pallas::Projective>;
type C2 = PedersenCommitment<ark_vesta::Projective>;

type CF = ark_pallas::Fr;

criterion_group! {
  name = recursive_snark;
  config = Criterion::default().warm_up_time(Duration::from_millis(3000));
  targets = bench_recursive_snark,
}

criterion_main!(recursive_snark);

fn bench_recursive_snark(c: &mut Criterion) {
    let ro_config = poseidon_config();

    let num_cons_verifier_circuit_primary = 9819;
    // we vary the number of constraints in the step circuit
    for &num_cons_in_augmented_circuit in
        [9819, 16384, 32768, 65536, 131072, 262144, 524288, 1048576].iter()
    {
        // number of constraints in the step circuit
        let num_cons = num_cons_in_augmented_circuit - num_cons_verifier_circuit_primary;

        let mut group = c.benchmark_group(format!("RecursiveSNARK-StepCircuitSize-{num_cons}"));
        group.sample_size(10);

        let step_circuit = NonTrivialTestCircuit::new(num_cons);

        // Produce public parameters
        let pp =
            PublicParams::<G1, G2, C1, C2, PoseidonSponge<CF>, NonTrivialTestCircuit<CF>>::setup(
                ro_config.clone(),
                &step_circuit,
            )
            .unwrap();

        // Bench time to produce a recursive SNARK;
        // we execute a certain number of warm-up steps since executing
        // the first step is cheaper than other steps owing to the presence of
        // a lot of zeros in the satisfying assignment
        let num_warmup_steps = 10;
        let mut recursive_snark: RecursiveSNARK<G1, G2, C1, C2, PoseidonSponge<CF>, _> =
            RecursiveSNARK::new(&pp, &[CF::from(2u64)]);

        for i in 0..num_warmup_steps {
            recursive_snark = recursive_snark.prove_step(&step_circuit).unwrap();

            // verify the recursive snark at each step of recursion
            let res = recursive_snark.verify(i + 1);
            assert!(res.is_ok());
        }

        let _recursive_snark = recursive_snark.clone();
        group.bench_function("Prove", move |b| {
            b.iter(|| {
                // produce a recursive SNARK for a step of the recursion
                black_box(_recursive_snark.clone())
                    .prove_step(black_box(&step_circuit))
                    .unwrap();
            })
        });

        // Benchmark the verification time
        group.bench_function("Verify", |b| {
            b.iter(|| {
                black_box(&recursive_snark)
                    .verify(black_box(num_warmup_steps))
                    .unwrap();
            });
        });
        group.finish();
    }
}

struct NonTrivialTestCircuit<F> {
    num_constraints: usize,
    _p: PhantomData<F>,
}

impl<F> NonTrivialTestCircuit<F>
where
    F: PrimeField,
{
    pub fn new(num_constraints: usize) -> Self {
        Self {
            num_constraints,
            _p: PhantomData,
        }
    }
}

impl<F> StepCircuit<F> for NonTrivialTestCircuit<F>
where
    F: PrimeField,
{
    const ARITY: usize = 1;

    fn generate_constraints(
        &self,
        _: ConstraintSystemRef<F>,
        z: &[FpVar<F>],
    ) -> Result<Vec<FpVar<F>>, SynthesisError> {
        // Consider an equation: `x^2 = y`, where `x` and `y` are respectively the input and output.
        let mut x = z[0].clone();
        let mut y = x.clone();
        for _ in 0..self.num_constraints {
            y = x.square()?;
            x = y.clone();
        }
        Ok(vec![y])
    }
}
