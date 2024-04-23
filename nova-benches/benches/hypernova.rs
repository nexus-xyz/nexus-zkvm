//! Mirror of Microsoft Nova benchmarks for sequential implementation.
//!
//! Disable default features to run benchmarks in single-threaded mode.
//!
//! Run with `-- --profile-time=*` to enable profiler and generate flamegraphs:
//!     - on linux, you may want to configure `kernel.perf_event_paranoid`.
//!     - currently doesn't work on mac, see https://github.com/tikv/pprof-rs/issues/210.

use std::time::Duration;

use ark_crypto_primitives::sponge::poseidon::PoseidonSponge;

use criterion::*;
use pprof::criterion::{Output, PProfProfiler};

mod shared;
use shared::{NonTrivialTestCircuit, NUM_WARMUP_STEPS};

use nexus_nova::{
    hypernova::sequential::{IVCProof, PublicParams},
    pedersen::PedersenCommitment,
    zeromorph::ZeromorphCommitment,
    poseidon_config,
};

type G1 = ark_bn254::g1::Config;
type G2 = ark_grumpkin::GrumpkinConfig;
type C1 = Zeromorph<ark_bn254::Bn254>;
type C2 = PedersenCommitment<ark_grumpkin::Projective>;

type CF = ark_bn254::Fr;

criterion_group! {
    name = recursive_snark;
    config = Criterion::default()
        .with_profiler(PProfProfiler::new(100, Output::Flamegraph(None)))
        .warm_up_time(Duration::from_millis(3000));
    targets = bench_recursive_snark,
}

criterion_main!(recursive_snark);

#[cfg(feature = "spartan")]
fn bench_recursive_snark(c: &mut Criterion) {
    let ro_config = poseidon_config();

    // we vary the number of constraints in the step circuit
    for &num_cons_in_step_circuit in [0, 6399, 22783, 55551, 121087, 252159, 514303, 1038591].iter()
    {

        let mut group = c.benchmark_group(format!(
            "HyperNova-RecursiveSNARK-StepCircuitSize-{num_cons_in_step_circuit}"
        ));
        group.sample_size(10);

        let step_circuit = NonTrivialTestCircuit::new(num_cons_in_step_circuit);

            // Produce public parameters
        let pp =
            PublicParams::<G1, G2, C1, C2, PoseidonSponge<CF>, NonTrivialTestCircuit<CF>>::setup(
                ro_config.clone(),
                &step_circuit,
                &(),
            )
            .unwrap();

        // Bench time to produce a recursive SNARK;
        // we execute a certain number of warm-up steps since executing
        // the first step is cheaper than other steps owing to the presence of
        // a lot of zeros in the satisfying assignment
        let mut recursive_snark: IVCProof<G1, G2, C1, C2, PoseidonSponge<CF>, _> =
            IVCProof::new(&[CF::from(2u64)]);

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
}
