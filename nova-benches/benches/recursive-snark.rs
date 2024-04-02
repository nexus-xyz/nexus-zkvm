//! Mirror of Microsoft Nova benchmarks for sequential implementation.
//!
//! Disable default features to run benchmarks in single-threaded mode.
//!
//! Run with `-- --profile-time=*` to enable profiler and generate flamegraphs:
//!     - on linux, you may want to configure `kernel.perf_event_paranoid`.
//!     - currently doesn't work on mac, see https://github.com/tikv/pprof-rs/issues/210.

use std::{marker::PhantomData, time::Duration};

use ark_crypto_primitives::sponge::poseidon::PoseidonSponge;
use ark_ff::PrimeField;
use ark_r1cs_std::fields::{fp::FpVar, FieldVar};
use ark_relations::r1cs::{ConstraintSystemRef, SynthesisError};

use criterion::*;
use pprof::criterion::{Output, PProfProfiler};

use nexus_nova::{
    nova::{
        public_params::pedersen_setup,
        sequential::{IVCProof, PublicParams},
    },
    pedersen::PedersenCommitment,
    poseidon_config, StepCircuit,
};

type G1 = ark_pallas::PallasConfig;
type G2 = ark_vesta::VestaConfig;
type C1 = PedersenCommitment<ark_pallas::PallasConfig>;
type C2 = PedersenCommitment<ark_vesta::VestaConfig>;

type CF = ark_pallas::Fr;

criterion_group! {
    name = recursive_snark;
    config = Criterion::default()
        .with_profiler(PProfProfiler::new(100, Output::Flamegraph(None)))
        .warm_up_time(Duration::from_millis(3000));
    targets = bench_recursive_snark,
}

criterion_main!(recursive_snark);

fn bench_recursive_snark(c: &mut Criterion) {
    let ro_config = poseidon_config();

    // we vary the number of constraints in the step circuit
    for &num_cons_in_step_circuit in [0, 6399, 22783, 55551, 121087, 252159, 514303, 1038591].iter()
    {
        let mut group = c.benchmark_group(format!(
            "RecursiveSNARK-StepCircuitSize-{num_cons_in_step_circuit}"
        ));
        group.sample_size(10);

        let step_circuit = NonTrivialTestCircuit::new(num_cons_in_step_circuit);

        // Produce public parameters
        let pp =
            PublicParams::<G1, G2, C1, C2, PoseidonSponge<CF>, NonTrivialTestCircuit<CF>>::setup(
                ro_config.clone(),
                &step_circuit,
                pedersen_setup,
                pedersen_setup,
            )
            .unwrap();

        // Bench time to produce a recursive SNARK;
        // we execute a certain number of warm-up steps since executing
        // the first step is cheaper than other steps owing to the presence of
        // a lot of zeros in the satisfying assignment
        let num_warmup_steps = 10;
        let mut recursive_snark: IVCProof<G1, G2, C1, C2, PoseidonSponge<CF>, _> =
            IVCProof::new(&[CF::from(2u64)]);

        for i in 0..num_warmup_steps {
            recursive_snark = recursive_snark.prove_step(&pp, &step_circuit).unwrap();

            // verify the recursive snark at each step of recursion
            let res = recursive_snark.verify(&pp, i + 1);
            assert!(res.is_ok());
        }

        group.bench_function("Prove", |b| {
            b.iter(|| {
                // produce a recursive SNARK for a step of the recursion
                black_box(recursive_snark.clone())
                    .prove_step(black_box(&pp), black_box(&step_circuit))
                    .unwrap();
            })
        });

        // Benchmark the verification time
        group.bench_function("Verify", |b| {
            b.iter(|| {
                black_box(&recursive_snark)
                    .verify(black_box(&pp), black_box(num_warmup_steps))
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
        Self { num_constraints, _p: PhantomData }
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
        _: &FpVar<F>,
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
