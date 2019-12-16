//! Demonstrates how to produces a proof for canonical cubic equation: `x^3 + x + 5 = y`.
//! The example is described in detail [here].
//!
//! The R1CS for this problem consists of the following 4 constraints:
//! `Z0 * Z0 - Z1 = 0`
//! `Z1 * Z0 - Z2 = 0`
//! `(Z2 + Z0) * 1 - Z3 = 0`
//! `(Z3 + 5) * 1 - I0 = 0`
//!
//! [here]: https://medium.com/@VitalikButerin/quadratic-arithmetic-programs-from-zero-to-hero-f6d558cea649
#![allow(clippy::assertions_on_result_states)]
use ark_bls12_381::Fr;
use ark_bls12_381::G1Projective;
use ark_ff::PrimeField;
use ark_std::test_rng;
use libspartan::{InputsAssignment, Instance, SNARKGens, VarsAssignment, SNARK};
use merlin::Transcript;

#[allow(non_snake_case)]
fn produce_r1cs<F: PrimeField>() -> (
  usize,
  usize,
  usize,
  usize,
  Instance<F>,
  VarsAssignment<F>,
  InputsAssignment<F>,
) {
  // parameters of the R1CS instance
  let num_cons = 4;
  let num_vars = 4;
  let num_inputs = 1;
  let num_non_zero_entries = 8;

  // We will encode the above constraints into three matrices, where
  // the coefficients in the matrix are in the little-endian byte order
  let mut A: Vec<(usize, usize, F)> = Vec::new();
  let mut B: Vec<(usize, usize, F)> = Vec::new();
  let mut C: Vec<(usize, usize, F)> = Vec::new();

  let one = F::one();

  // R1CS is a set of three sparse matrices A B C, where is a row for every
  // constraint and a column for every entry in z = (vars, 1, inputs)
  // An R1CS instance is satisfiable iff:
  // Az \circ Bz = Cz, where z = (vars, 1, inputs)

  // constraint 0 entries in (A,B,C)
  // constraint 0 is Z0 * Z0 - Z1 = 0.
  A.push((0, 0, one));
  B.push((0, 0, one));
  C.push((0, 1, one));

  // constraint 1 entries in (A,B,C)
  // constraint 1 is Z1 * Z0 - Z2 = 0.
  A.push((1, 1, one));
  B.push((1, 0, one));
  C.push((1, 2, one));

  // constraint 2 entries in (A,B,C)
  // constraint 2 is (Z2 + Z0) * 1 - Z3 = 0.
  A.push((2, 2, one));
  A.push((2, 0, one));
  B.push((2, num_vars, one));
  C.push((2, 3, one));

  // constraint 3 entries in (A,B,C)
  // constraint 3 is (Z3 + 5) * 1 - I0 = 0.
  A.push((3, 3, one));
  A.push((3, num_vars, F::from(5u32)));
  B.push((3, num_vars, one));
  C.push((3, num_vars + 1, one));

  let inst = Instance::new(num_cons, num_vars, num_inputs, &A, &B, &C).unwrap();

  // compute a satisfying assignment
  let mut prng = test_rng();
  let z0 = F::rand(&mut prng);
  let z1 = z0 * z0; // constraint 0
  let z2 = z1 * z0; // constraint 1
  let z3 = z2 + z0; // constraint 2
  let i0 = z3 + F::from(5u32); // constraint 3

  // create a VarsAssignment
  let mut vars = vec![F::zero(); num_vars];
  vars[0] = z0;
  vars[1] = z1;
  vars[2] = z2;
  vars[3] = z3;
  let assignment_vars = VarsAssignment::new(&vars).unwrap();

  // create an InputsAssignment
  let mut inputs = vec![F::zero(); num_inputs];
  inputs[0] = i0;
  let assignment_inputs = InputsAssignment::new(&inputs).unwrap();

  // check if the instance we created is satisfiable
  let res = inst.is_sat(&assignment_vars, &assignment_inputs);
  assert!(res.unwrap(), "should be satisfied");

  (
    num_cons,
    num_vars,
    num_inputs,
    num_non_zero_entries,
    inst,
    assignment_vars,
    assignment_inputs,
  )
}

fn main() {
  // produce an R1CS instance
  let (
    num_cons,
    num_vars,
    num_inputs,
    num_non_zero_entries,
    inst,
    assignment_vars,
    assignment_inputs,
  ) = produce_r1cs::<Fr>();

  // produce public parameters
  let gens = SNARKGens::<G1Projective>::new(num_cons, num_vars, num_inputs, num_non_zero_entries);

  // create a commitment to the R1CS instance
  let (comm, decomm) = SNARK::encode(&inst, &gens);

  // produce a proof of satisfiability
  let mut prover_transcript = Transcript::new(b"snark_example");
  let proof = SNARK::prove(
    &inst,
    &comm,
    &decomm,
    assignment_vars,
    &assignment_inputs,
    &gens,
    &mut prover_transcript,
  );

  // verify the proof of satisfiability
  let mut verifier_transcript = Transcript::new(b"snark_example");
  assert!(proof
    .verify(&comm, &assignment_inputs, &mut verifier_transcript, &gens)
    .is_ok());
  println!("proof verification successful!");
}
