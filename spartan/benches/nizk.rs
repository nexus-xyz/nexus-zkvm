#![allow(clippy::assertions_on_result_states)]

extern crate core;
extern crate criterion;
extern crate digest;
extern crate libspartan;
extern crate merlin;
extern crate rand;
extern crate sha3;

use ark_bls12_381::G1Projective;
use ark_ec::CurveGroup;
use libspartan::{Instance, NIZKGens, NIZK};
use merlin::Transcript;

use criterion::*;

fn nizk_prove_benchmark<G: CurveGroup>(c: &mut Criterion) {
  for &s in [10, 12, 16].iter() {
    let plot_config = PlotConfiguration::default().summary_scale(AxisScale::Logarithmic);
    let mut group = c.benchmark_group("NIZK_prove_benchmark");
    group.plot_config(plot_config);

    let num_vars = (2_usize).pow(s as u32);
    let num_cons = num_vars;
    let num_inputs = 10;

    let (inst, vars, inputs) =
      Instance::<G::ScalarField>::produce_synthetic_r1cs(num_cons, num_vars, num_inputs);

    let gens = NIZKGens::<G>::new(num_cons, num_vars, num_inputs);

    let name = format!("NIZK_prove_{}", num_vars);
    group.bench_function(&name, move |b| {
      b.iter(|| {
        let mut prover_transcript = Transcript::new(b"example");
        NIZK::prove(
          black_box(&inst),
          black_box(vars.clone()),
          black_box(&inputs),
          black_box(&gens),
          black_box(&mut prover_transcript),
        );
      });
    });
    group.finish();
  }
}

fn nizk_prove_benchmark_optimized<G: CurveGroup>(c: &mut Criterion) {
  for &s in [10, 12, 16, 18].iter() {
    let plot_config = PlotConfiguration::default().summary_scale(AxisScale::Logarithmic);
    let mut group = c.benchmark_group("NIZK_prove_benchmark_optimized");
    group.plot_config(plot_config);

    let num_vars = (2_usize).pow(s as u32);
    let num_cons = num_vars;
    let num_inputs = 10;

    let (inst, vars, inputs) =
      Instance::<G::ScalarField>::produce_synthetic_r1cs(num_cons, num_vars, num_inputs);

    let gens = NIZKGens::<G>::new(num_cons, num_vars, num_inputs);

    let name = format!("NIZK_prove_optimized_{}", num_vars);
    group.bench_function(&name, move |b| {
      b.iter(|| {
        let mut prover_transcript = Transcript::new(b"example");
        NIZK::prove(
          black_box(&inst),
          black_box(vars.clone()),
          black_box(&inputs),
          black_box(&gens),
          black_box(&mut prover_transcript),
        );
      });
    });
    group.finish();
  }
}

fn nizk_verify_benchmark<G: CurveGroup>(c: &mut Criterion) {
  for &s in [10, 12, 16].iter() {
    let plot_config = PlotConfiguration::default().summary_scale(AxisScale::Logarithmic);
    let mut group = c.benchmark_group("NIZK_verify_benchmark");
    group.plot_config(plot_config);

    let num_vars = (2_usize).pow(s as u32);
    let num_cons = num_vars;
    let num_inputs = 10;
    let (inst, vars, inputs) =
      Instance::<G::ScalarField>::produce_synthetic_r1cs(num_cons, num_vars, num_inputs);

    let gens = NIZKGens::<G>::new(num_cons, num_vars, num_inputs);

    // produce a proof of satisfiability
    let mut prover_transcript = Transcript::new(b"example");
    let proof = NIZK::prove(&inst, vars, &inputs, &gens, &mut prover_transcript);

    let name = format!("NIZK_verify_{}", num_cons);
    group.bench_function(&name, move |b| {
      b.iter(|| {
        let mut verifier_transcript = Transcript::new(b"example");
        assert!(proof
          .verify(
            black_box(&inst),
            black_box(&inputs),
            black_box(&mut verifier_transcript),
            black_box(&gens)
          )
          .is_ok());
      });
    });
    group.finish();
  }
}

fn set_duration() -> Criterion {
  Criterion::default().sample_size(10)
}

criterion_group! {
name = benches_nizk;
config = set_duration();
targets = nizk_prove_benchmark::<G1Projective>, nizk_prove_benchmark_optimized::<G1Projective>, nizk_verify_benchmark::<G1Projective>
}

criterion_main!(benches_nizk);
