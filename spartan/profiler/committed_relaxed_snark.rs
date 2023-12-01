#![allow(non_snake_case)]
#![allow(clippy::assertions_on_result_states)]

extern crate libspartan;
extern crate merlin;

use ark_bls12_381::{Bls12_381, G1Projective};
use ark_ec::CurveGroup;
use ark_serialize::CanonicalSerialize;
use ark_std::{cmp::max, test_rng, One, UniformRand, Zero};

use libspartan::{
  committed_relaxed_snark::{SNARKGens, SNARK},
  crr1csproof::{CRR1CSInstance, CRR1CSShape, CRR1CSWitness},
  math::Math,
  polycommitments::{zeromorph::Zeromorph, PolyCommitmentScheme, VectorCommitmentScheme},
  Instance,
};
use merlin::Transcript;

fn print(msg: &str) {
  let star = "* ";
  println!("{:indent$}{}{}", "", star, msg, indent = 2);
}

#[allow(clippy::type_complexity)]
// This produces a random satisfying structure, instance, witness, and public parameters for testing and benchmarking purposes.
fn produce_synthetic_crr1cs<G: CurveGroup, PC: PolyCommitmentScheme<G>>(
  num_cons: usize,
  num_vars: usize,
  num_inputs: usize,
) -> (
  CRR1CSShape<G::ScalarField>,
  CRR1CSInstance<G, PC>,
  CRR1CSWitness<G::ScalarField>,
  SNARKGens<G, PC>,
) {
  // compute random satisfying assignment for r1cs
  let (inst, vars, inputs) = Instance::produce_synthetic_r1cs(num_cons, num_vars, num_inputs);
  // the `Instance` initializer may have padded the variable lengths
  let (num_cons, num_vars, num_inputs) = (
    inst.inst.get_num_cons(),
    inst.inst.get_num_vars(),
    inst.inst.get_num_inputs(),
  );
  assert_eq!(num_vars, vars.assignment.len());
  assert_eq!(num_inputs, inputs.assignment.len());
  let shape = CRR1CSShape { inst };

  // Note that `produce_synthetic_r1cs` produces a satisfying assignment for Z = [vars, 1, inputs].
  let mut Z = vars.assignment.clone();
  Z.extend(&vec![G::ScalarField::one()]);
  Z.extend(inputs.assignment.clone());

  // Choose a random u and set Z[num_vars] = u.
  let u = G::ScalarField::rand(&mut test_rng());
  Z[num_vars] = u;

  let (poly_A, poly_B, poly_C) =
    shape
      .inst
      .inst
      .multiply_vec(num_cons, num_vars + num_inputs + 1, Z.as_slice());

  // Compute the error vector E = (AZ * BZ) - (u * CZ)
  let mut E = vec![G::ScalarField::zero(); num_cons];
  for i in 0..num_cons {
    let AB_val = poly_A[i] * poly_B[i];
    let C_val = poly_C[i];
    E[i] = AB_val - u * C_val;
  }

  // compute commitments to the vectors `vars` and `E`.
  let n = max(num_cons, num_vars);
  let mut rng = test_rng();
  let SRS = PC::setup(n.log_2(), b"test-SRS", &mut rng).unwrap();
  let gens = SNARKGens::<G, PC>::new(&SRS, num_cons, num_vars, num_inputs, num_cons);
  let comm_W = <PC as VectorCommitmentScheme<G>>::commit(
    vars.assignment.as_slice(),
    &gens.gens_r1cs_sat.pc_commit_key,
  );
  let comm_E =
    <PC as VectorCommitmentScheme<G>>::commit(E.as_slice(), &gens.gens_r1cs_sat.pc_commit_key);
  (
    shape,
    CRR1CSInstance::<G, PC> {
      input: inputs,
      u,
      comm_W,
      comm_E,
    },
    CRR1CSWitness::<G::ScalarField> {
      W: vars.clone(),
      E: E.clone(),
    },
    gens,
  )
}

pub fn main() {
  // the list of number of variables (and constraints) in an R1CS instance
  let inst_sizes = [10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20];

  println!("Profiler:: SNARK");
  for &s in inst_sizes.iter() {
    let num_vars = (2_usize).pow(s as u32);
    let num_cons = num_vars;
    let num_inputs = 10;

    // produce a synthetic R1CSInstance
    let (shape, instance, witness, gens) = produce_synthetic_crr1cs::<
      G1Projective,
      Zeromorph<Bls12_381>,
    >(num_cons, num_vars, num_inputs);

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
