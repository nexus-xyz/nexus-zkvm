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
use ark_spartan::polycommitments::zeromorph::Zeromorph;

use criterion::*;
use pprof::criterion::{Output, PProfProfiler};

use nexus_nova::{
    nova::sequential::{IVCProof as NovaIVC, PublicParams as NovaPP},
    hypernova::{
        sequential::{IVCProof as HyperNovaIVC, PublicParams as HyperNovaPP},
    },
    pedersen::PedersenCommitment,
    poseidon_config, StepCircuit,
};

type NG1 = ark_pallas::PallasConfig;
type NG2 = ark_vesta::VestaConfig;
type NC1 = PedersenCommitment<ark_pallas::Projective>;
type NC2 = PedersenCommitment<ark_vesta::Projective>;

type NCF = ark_pallas::Fr;

type HNG1 = ark_bn254::g1::Config;
type HNG2 = ark_grumpkin::GrumpkinConfig;
type HNC1 = Zeromorph<ark_bn254::Bn254>;
type HNC2 = PedersenCommitment<ark_grumpkin::Projective>;

type HNCF = ark_bn254::Fr;

criterion_group! {
    name = recursive_snark;
    config = Criterion::default()
        .with_profiler(PProfProfiler::new(100, Output::Flamegraph(None)))
        .warm_up_time(Duration::from_millis(3000));
    targets = bench_recursive_snark,
}

criterion_main!(recursive_snark);

const NUM_WARMUP_STEPS: usize = 10;

fn nova(c: &mut Criterion, num_cons_in_step_circuit: usize) -> () {
    let ro_config = poseidon_config();

    let mut group = c.benchmark_group(format!(
        "Nova-RecursiveSNARK-StepCircuitSize-{num_cons_in_step_circuit}"
    ));
    group.sample_size(10);

    let step_circuit = NonTrivialTestCircuit::new(num_cons_in_step_circuit);

    // Produce public parameters
    let pp =
        NovaPP::<NG1, NG2, NC1, NC2, PoseidonSponge<NCF>, NonTrivialTestCircuit<NCF>>::setup(
            ro_config.clone(),
            &step_circuit,
            &(),
            &(),
        )
        .unwrap();

    // Bench time to produce a recursive SNARK;
    // we execute a certain number of warm-up steps since executing
    // the first step is cheaper than other steps owing to the presence of
    // a lot of zeros in the satisfying assignment
    let mut recursive_snark: NovaIVC<NG1, NG2, NC1, NC2, PoseidonSponge<NCF>, _> =
        NovaIVC::new(&[NCF::from(2u64)]);

    for i in 0..NUM_WARMUP_STEPS {
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
                .verify(black_box(&pp), black_box(NUM_WARMUP_STEPS))
                .unwrap();
        });
    });

    group.finish();
}

#[cfg(feature = "spartan")]
fn hypernova(c: &mut Criterion, num_cons_in_step_circuit: usize) -> () {
    let ro_config = poseidon_config();

    let mut group = c.benchmark_group(format!(
        "HyperNova-RecursiveSNARK-StepCircuitSize-{num_cons_in_step_circuit}"
    ));
    group.sample_size(10);

    let step_circuit = NonTrivialTestCircuit::new(num_cons_in_step_circuit);

    // Produce public parameters
    let pp =
        HyperNovaPP::<HNG1, HNG2, HNC1, HNC2, PoseidonSponge<HNCF>, NonTrivialTestCircuit<HNCF>>::setup(
            ro_config.clone(),
            &step_circuit,
            &(),
        )
        .unwrap();

    // Bench time to produce a recursive SNARK;
    // we execute a certain number of warm-up steps since executing
    // the first step is cheaper than other steps owing to the presence of
    // a lot of zeros in the satisfying assignment
    let mut recursive_snark: HyperNovaIVC<HNG1, HNG2, HNC1, HNC2, PoseidonSponge<HNCF>, _> =
        HyperNovaIVC::new(&[HNCF::from(2u64)]);

    for i in 0..NUM_WARMUP_STEPS {
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
                .verify(black_box(&pp), black_box(NUM_WARMUP_STEPS))
                .unwrap();
        });
    });

    group.finish();
}

fn bench_recursive_snark(c: &mut Criterion) {

    // we vary the number of constraints in the step circuit
    for &num_cons_in_step_circuit in [0, 6399, 22783, 55551, 121087, 252159, 514303, 1038591].iter()
    {
        nova(c, num_cons_in_step_circuit);
    }

    #[cfg(feature = "spartan")]
    for &num_cons_in_step_circuit in [0, 6399, 22783, 55551, 121087, 252159, 514303, 1038591].iter()
    {
        hypernova(c, num_cons_in_step_circuit);
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
