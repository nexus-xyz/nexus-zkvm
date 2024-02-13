#![allow(non_snake_case)]
#![allow(clippy::assertions_on_result_states)]

extern crate libspartan;
extern crate merlin;

use ark_bls12_381::G1Projective;
use ark_serialize::CanonicalSerialize;
use ark_std::test_rng;

use libspartan::{
  committed_relaxed_snark::SNARK, crr1csproof::produce_synthetic_crr1cs,
  polycommitments::hyrax::Hyrax, polycommitments::PolyCommitmentScheme,
};
use merlin::Transcript;

fn print(msg: &str) {
  let star = "* ";
  println!("{:indent$}{}{}", "", star, msg, indent = 2);
}

pub fn main() {
  // the list of number of variables (and constraints) in an R1CS instance
  let inst_sizes = [10, 11, 12, 13, 14, 15, 16];
  let srs = Hyrax::<G1Projective>::setup(
    *inst_sizes.iter().max().unwrap(),
    b"hyrax-profiler",
    &mut test_rng(),
  )
  .unwrap();

  println!("Profiler:: SNARK with Hyrax");
  for &s in inst_sizes.iter() {
    let num_vars = (2_usize).pow(s as u32);
    let num_cons = num_vars;
    let num_inputs = 10;

    // produce a synthetic R1CSInstance
    let (shape, instance, witness, gens) = produce_synthetic_crr1cs::<
      G1Projective,
      Hyrax<G1Projective>,
    >(&srs, num_cons, num_vars, num_inputs);

    // create a commitment to R1CSInstance
    let (comm, decomm) = SNARK::encode(&shape.inst, &gens);

    // produce a proof of satisfiability
    let mut prover_transcript = Transcript::new(b"snark_example");
    let proof = SNARK::prove(
      &shape,
      &instance,
      witness,
      &comm,
      &decomm,
      &gens,
      &mut prover_transcript,
    );

    let mut proof_encoded = vec![];
    proof.serialize_compressed(&mut proof_encoded).unwrap();

    let msg_proof_len = format!("SNARK::proof_compressed_len {:?}", proof_encoded.len());
    print(&msg_proof_len);

    // verify the proof of satisfiability
    let mut verifier_transcript = Transcript::new(b"snark_example");
    assert!(proof
      .verify(&comm, &instance, &mut verifier_transcript, &gens)
      .is_ok());

    println!();
  }
}
