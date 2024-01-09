#![allow(clippy::assertions_on_result_states)]
extern crate libspartan;
extern crate merlin;

use ark_bls12_381::{Bls12_381, G1Projective};
use ark_ec::CurveGroup;
use libspartan::{
  committed_relaxed_snark::SNARK,
  crr1csproof::produce_synthetic_crr1cs,
  polycommitments::{zeromorph::Zeromorph, PolyCommitmentScheme},
};
use merlin::Transcript;

use criterion::*;

fn snark_encode_benchmark<G: CurveGroup, PC: PolyCommitmentScheme<G>>(c: &mut Criterion) {
  for s in 10..21 {
    let plot_config = PlotConfiguration::default().summary_scale(AxisScale::Logarithmic);
    let mut group = c.benchmark_group("SNARK_encode_benchmark");
    group.plot_config(plot_config);

    let num_vars = (2_usize).pow(s as u32);
    let num_cons = num_vars;
    let num_inputs = 10;
    let (shape, _instance, _witness, gens) =
      produce_synthetic_crr1cs::<G, PC>(num_cons, num_vars, num_inputs);

    // produce a commitment to R1CS instance
    let name = format!("SNARK_encode_{}", num_cons);
    group.bench_function(&name, move |b| {
      b.iter(|| {
        SNARK::encode(black_box(&shape.inst), black_box(&gens));
      });
    });
    group.finish();
  }
}

fn snark_prove_benchmark<G: CurveGroup, PC: PolyCommitmentScheme<G>>(c: &mut Criterion) {
  for s in 9..21 {
    let plot_config = PlotConfiguration::default().summary_scale(AxisScale::Logarithmic);
    let mut group = c.benchmark_group("SNARK_prove_benchmark");
    group.plot_config(plot_config);

    let num_vars = (2_usize).pow(s as u32);
    let num_cons = num_vars;
    let num_inputs = 10;

    let (shape, instance, witness, gens) =
      produce_synthetic_crr1cs::<G, PC>(num_cons, num_vars, num_inputs);

    // produce a commitment to R1CS instance
    let (comm, decomm) = SNARK::encode(&shape.inst, &gens);

    // produce a proof
    let name = format!("SNARK_prove_{}", num_cons);
    group.bench_function(&name, move |b| {
      b.iter(|| {
        let mut prover_transcript = Transcript::new(b"example");
        SNARK::prove(
          black_box(&shape),
          black_box(&instance),
          black_box(witness.clone()),
          black_box(&comm),
          black_box(&decomm),
          black_box(&gens),
          black_box(&mut prover_transcript),
        );
      });
    });
    group.finish();
  }
}

fn snark_verify_benchmark<G: CurveGroup, PC: PolyCommitmentScheme<G>>(c: &mut Criterion) {
  for s in 10..21 {
    let plot_config = PlotConfiguration::default().summary_scale(AxisScale::Logarithmic);
    let mut group = c.benchmark_group("SNARK_verify_benchmark");
    group.plot_config(plot_config);

    let num_vars = (2_usize).pow(s as u32);
    let num_cons = num_vars;
    let num_inputs = 10;

    let (shape, instance, witness, gens) =
      produce_synthetic_crr1cs::<G, PC>(num_cons, num_vars, num_inputs);

    // produce a commitment to R1CS instance
    let (comm, decomm) = SNARK::encode(&shape.inst, &gens);

    // produce a proof of satisfiability
    let mut prover_transcript = Transcript::new(b"example");
    let proof = SNARK::prove(
      &shape,
      &instance,
      witness,
      &comm,
      &decomm,
      &gens,
      &mut prover_transcript,
    );

    // verify the proof
    let name = format!("SNARK_verify_{}", num_cons);
    group.bench_function(&name, move |b| {
      b.iter(|| {
        let mut verifier_transcript = Transcript::new(b"example");
        assert!(proof
          .verify(
            black_box(&comm),
            black_box(&instance),
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
name = benches_snark;
config = set_duration();
targets = snark_encode_benchmark::<G1Projective, Zeromorph<Bls12_381> >,
snark_prove_benchmark::<G1Projective, Zeromorph<Bls12_381>>, snark_verify_benchmark::<G1Projective, Zeromorph<Bls12_381>>
}

criterion_main!(benches_snark);
