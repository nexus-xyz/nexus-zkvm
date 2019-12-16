#![allow(non_snake_case)]
#![allow(clippy::assertions_on_result_states)]

extern crate libspartan;
extern crate merlin;
extern crate rand;

use ark_bls12_381::{Fr, G1Projective};
use ark_serialize::CanonicalSerialize;
use libspartan::{Instance, NIZKGens, NIZK};
use merlin::Transcript;

fn print(msg: &str) {
  let star = "* ";
  println!("{:indent$}{}{}", "", star, msg, indent = 2);
}

pub fn main() {
  // the list of number of variables (and constraints) in an R1CS instance
  let inst_sizes = vec![10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20];

  println!("Profiler:: NIZK");
  for &s in inst_sizes.iter() {
    let num_vars = (2_usize).pow(s as u32);
    let num_cons = num_vars;
    let num_inputs = 10;

    // produce a synthetic R1CSInstance
    let (inst, vars, inputs) =
      Instance::<Fr>::produce_synthetic_r1cs(num_cons, num_vars, num_inputs);

    // produce public generators
    let gens = NIZKGens::<G1Projective>::new(num_cons, num_vars, num_inputs);

    // produce a proof of satisfiability
    let mut prover_transcript = Transcript::new(b"nizk_example");
    let proof = NIZK::prove(&inst, vars, &inputs, &gens, &mut prover_transcript);

    let mut proof_encoded = vec![];
    proof.serialize_compressed(&mut proof_encoded).unwrap();

    let msg_proof_len = format!("NIZK::proof_compressed_len {:?}", proof_encoded.len());
    print(&msg_proof_len);

    // verify the proof of satisfiability
    let mut verifier_transcript = Transcript::new(b"nizk_example");
    assert!(proof
      .verify(&inst, &inputs, &mut verifier_transcript, &gens)
      .is_ok());

    println!();
  }
}
