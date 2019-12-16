#![allow(non_snake_case)]
#![doc = include_str!("../README.md")]
#![deny(missing_docs)]
#![allow(clippy::assertions_on_result_states)]

extern crate core;
extern crate digest;
extern crate merlin;
extern crate rand;
extern crate sha3;

#[cfg(feature = "multicore")]
extern crate rayon;

mod commitments;
mod dense_mlpoly;
mod errors;
mod math;
mod nizk;
mod product_tree;
mod r1csinstance;
mod r1csproof;
mod random;
mod sparse_mlpoly;
mod sumcheck;
mod timer;
mod transcript;
mod unipoly;

use ark_ec::CurveGroup;
use ark_ff::PrimeField;
use ark_serialize::*;
use core::cmp::max;
use errors::{ProofVerifyError, R1CSError};
use merlin::Transcript;
use r1csinstance::{
  R1CSCommitment, R1CSCommitmentGens, R1CSDecommitment, R1CSEvalProof, R1CSInstance,
};
use r1csproof::{R1CSGens, R1CSProof};
use random::RandomTape;
use timer::Timer;
use transcript::{AppendToTranscript, ProofTranscript};

/// `ComputationCommitment` holds a public preprocessed NP statement (e.g., R1CS)
pub struct ComputationCommitment<G: CurveGroup> {
  comm: R1CSCommitment<G>,
}

/// `ComputationDecommitment` holds information to decommit `ComputationCommitment`
pub struct ComputationDecommitment<F> {
  decomm: R1CSDecommitment<F>,
}

/// `Assignment` holds an assignment of values to either the inputs or variables in an `Instance`
#[derive(Clone)]
pub struct Assignment<F> {
  assignment: Vec<F>,
}

impl<F: PrimeField> Assignment<F> {
  /// Constructs a new `Assignment` from a vector
  pub fn new(assignment: &[F]) -> Result<Self, R1CSError> {
    let bytes_to_scalar = |vec: &[F]| -> Result<Vec<F>, R1CSError> {
      let mut vec_scalar: Vec<F> = Vec::new();
      for v in vec {
        vec_scalar.push(*v);
      }
      Ok(vec_scalar)
    };

    let assignment_scalar = bytes_to_scalar(assignment)?;

    Ok(Assignment {
      assignment: assignment_scalar,
    })
  }

  /// pads Assignment to the specified length
  fn pad(&self, len: usize) -> VarsAssignment<F> {
    // check that the new length is higher than current length
    assert!(len > self.assignment.len());

    let padded_assignment = {
      let mut padded_assignment = self.assignment.clone();
      padded_assignment.extend(vec![F::zero(); len - self.assignment.len()]);
      padded_assignment
    };

    VarsAssignment {
      assignment: padded_assignment,
    }
  }
}

/// `VarsAssignment` holds an assignment of values to variables in an `Instance`
pub type VarsAssignment<F> = Assignment<F>;

/// `InputsAssignment` holds an assignment of values to variables in an `Instance`
pub type InputsAssignment<F> = Assignment<F>;

/// `Instance` holds the description of R1CS matrices
pub struct Instance<F: PrimeField> {
  inst: R1CSInstance<F>,
}

impl<F: PrimeField> Instance<F> {
  /// Constructs a new `Instance` and an associated satisfying assignment
  pub fn new(
    num_cons: usize,
    num_vars: usize,
    num_inputs: usize,
    A: &[(usize, usize, F)],
    B: &[(usize, usize, F)],
    C: &[(usize, usize, F)],
  ) -> Result<Self, R1CSError> {
    let (num_vars_padded, num_cons_padded) = {
      let num_vars_padded = {
        let mut num_vars_padded = num_vars;

        // ensure that num_inputs + 1 <= num_vars
        num_vars_padded = max(num_vars_padded, num_inputs + 1);

        // ensure that num_vars_padded a power of two
        if num_vars_padded.next_power_of_two() != num_vars_padded {
          num_vars_padded = num_vars_padded.next_power_of_two();
        }
        num_vars_padded
      };

      let num_cons_padded = {
        let mut num_cons_padded = num_cons;

        // ensure that num_cons_padded is at least 2
        if num_cons_padded == 0 || num_cons_padded == 1 {
          num_cons_padded = 2;
        }

        // ensure that num_cons_padded is power of 2
        if num_cons.next_power_of_two() != num_cons {
          num_cons_padded = num_cons.next_power_of_two();
        }
        num_cons_padded
      };

      (num_vars_padded, num_cons_padded)
    };

    let bytes_to_scalar =
      |tups: &[(usize, usize, F)]| -> Result<Vec<(usize, usize, F)>, R1CSError> {
        let mut mat: Vec<(usize, usize, F)> = Vec::new();
        for &(row, col, val) in tups {
          // row must be smaller than num_cons
          if row >= num_cons {
            return Err(R1CSError::InvalidIndex);
          }

          // col must be smaller than num_vars + 1 + num_inputs
          if col >= num_vars + 1 + num_inputs {
            return Err(R1CSError::InvalidIndex);
          }

          if col >= num_vars {
            mat.push((row, col + num_vars_padded - num_vars, val));
          } else {
            mat.push((row, col, val));
          }
        }

        // pad with additional constraints up until num_cons_padded if the original constraints were 0 or 1
        // we do not need to pad otherwise because the dummy constraints are implicit in the sum-check protocol
        if num_cons == 0 || num_cons == 1 {
          for i in tups.len()..num_cons_padded {
            mat.push((i, num_vars, F::zero()));
          }
        }

        Ok(mat)
      };

    let A_scalar = bytes_to_scalar(A);
    if A_scalar.is_err() {
      return Err(A_scalar.err().unwrap());
    }

    let B_scalar = bytes_to_scalar(B);
    if B_scalar.is_err() {
      return Err(B_scalar.err().unwrap());
    }

    let C_scalar = bytes_to_scalar(C);
    if C_scalar.is_err() {
      return Err(C_scalar.err().unwrap());
    }

    let inst = R1CSInstance::<F>::new(
      num_cons_padded,
      num_vars_padded,
      num_inputs,
      &A_scalar.unwrap(),
      &B_scalar.unwrap(),
      &C_scalar.unwrap(),
    );

    Ok(Instance { inst })
  }

  /// Checks if a given R1CSInstance is satisfiable with a given variables and inputs assignments
  pub fn is_sat(
    &self,
    vars: &VarsAssignment<F>,
    inputs: &InputsAssignment<F>,
  ) -> Result<bool, R1CSError> {
    if vars.assignment.len() > self.inst.get_num_vars() {
      return Err(R1CSError::InvalidNumberOfInputs);
    }

    if inputs.assignment.len() != self.inst.get_num_inputs() {
      return Err(R1CSError::InvalidNumberOfInputs);
    }

    // we might need to pad variables
    let padded_vars = {
      let num_padded_vars = self.inst.get_num_vars();
      let num_vars = vars.assignment.len();
      if num_padded_vars > num_vars {
        vars.pad(num_padded_vars)
      } else {
        vars.clone()
      }
    };

    Ok(
      self
        .inst
        .is_sat(&padded_vars.assignment, &inputs.assignment),
    )
  }

  /// Constructs a new synthetic R1CS `Instance` and an associated satisfying assignment
  pub fn produce_synthetic_r1cs(
    num_cons: usize,
    num_vars: usize,
    num_inputs: usize,
  ) -> (Instance<F>, VarsAssignment<F>, InputsAssignment<F>) {
    let (inst, vars, inputs) = R1CSInstance::produce_synthetic_r1cs(num_cons, num_vars, num_inputs);
    (
      Instance { inst },
      VarsAssignment { assignment: vars },
      InputsAssignment { assignment: inputs },
    )
  }
}

/// `SNARKGens` holds public parameters for producing and verifying proofs with the Spartan SNARK
pub struct SNARKGens<G> {
  gens_r1cs_sat: R1CSGens<G>,
  gens_r1cs_eval: R1CSCommitmentGens<G>,
}

impl<G: CurveGroup> SNARKGens<G> {
  /// Constructs a new `SNARKGens` given the size of the R1CS statement
  /// `num_nz_entries` specifies the maximum number of non-zero entries in any of the three R1CS matrices
  pub fn new(num_cons: usize, num_vars: usize, num_inputs: usize, num_nz_entries: usize) -> Self {
    let num_vars_padded = {
      let mut num_vars_padded = max(num_vars, num_inputs + 1);
      if num_vars_padded != num_vars_padded.next_power_of_two() {
        num_vars_padded = num_vars_padded.next_power_of_two();
      }
      num_vars_padded
    };

    let gens_r1cs_sat = R1CSGens::<G>::new(b"gens_r1cs_sat", num_cons, num_vars_padded);
    let gens_r1cs_eval = R1CSCommitmentGens::new(
      b"gens_r1cs_eval",
      num_cons,
      num_vars_padded,
      num_inputs,
      num_nz_entries,
    );
    SNARKGens {
      gens_r1cs_sat,
      gens_r1cs_eval,
    }
  }
}

/// `SNARK` holds a proof produced by Spartan SNARK
#[derive(CanonicalSerialize, CanonicalDeserialize, Debug)]
pub struct SNARK<G: CurveGroup> {
  r1cs_sat_proof: R1CSProof<G>,
  inst_evals: (G::ScalarField, G::ScalarField, G::ScalarField),
  r1cs_eval_proof: R1CSEvalProof<G>,
}

impl<G: CurveGroup> SNARK<G> {
  fn protocol_name() -> &'static [u8] {
    b"Spartan SNARK proof"
  }

  /// A public computation to create a commitment to an R1CS instance
  pub fn encode(
    inst: &Instance<G::ScalarField>,
    gens: &SNARKGens<G>,
  ) -> (
    ComputationCommitment<G>,
    ComputationDecommitment<G::ScalarField>,
  ) {
    let timer_encode = Timer::new("SNARK::encode");
    let (comm, decomm) = inst.inst.commit(&gens.gens_r1cs_eval);
    timer_encode.stop();
    (
      ComputationCommitment { comm },
      ComputationDecommitment { decomm },
    )
  }

  /// A method to produce a SNARK proof of the satisfiability of an R1CS instance
  pub fn prove(
    inst: &Instance<G::ScalarField>,
    comm: &ComputationCommitment<G>,
    decomm: &ComputationDecommitment<G::ScalarField>,
    vars: VarsAssignment<G::ScalarField>,
    inputs: &InputsAssignment<G::ScalarField>,
    gens: &SNARKGens<G>,
    transcript: &mut Transcript,
  ) -> Self {
    let timer_prove = Timer::new("SNARK::prove");

    // we create a Transcript object seeded with a random F
    // to aid the prover produce its randomness
    let mut random_tape = RandomTape::<G>::new(b"proof");
    <Transcript as ProofTranscript<G>>::append_protocol_name(
      transcript,
      SNARK::<G>::protocol_name(),
    );
    comm.comm.append_to_transcript(b"comm", transcript);

    let (r1cs_sat_proof, rx, ry) = {
      let (proof, rx, ry) = {
        // we might need to pad variables
        let padded_vars = {
          let num_padded_vars = inst.inst.get_num_vars();
          let num_vars = vars.assignment.len();
          if num_padded_vars > num_vars {
            vars.pad(num_padded_vars)
          } else {
            vars
          }
        };

        R1CSProof::prove(
          &inst.inst,
          padded_vars.assignment,
          &inputs.assignment,
          &gens.gens_r1cs_sat,
          transcript,
          &mut random_tape,
        )
      };

      let mut proof_encoded = vec![];
      proof.serialize_compressed(&mut proof_encoded).unwrap();

      Timer::print(&format!("len_r1cs_sat_proof {:?}", proof_encoded.len()));

      (proof, rx, ry)
    };

    // We send evaluations of A, B, C at r = (rx, ry) as claims
    // to enable the verifier complete the first sum-check
    let timer_eval = Timer::new("eval_sparse_polys");
    let inst_evals = {
      let (Ar, Br, Cr) = inst.inst.evaluate(&rx, &ry);
      <Transcript as ProofTranscript<G>>::append_scalar(transcript, b"Ar_claim", &Ar);
      <Transcript as ProofTranscript<G>>::append_scalar(transcript, b"Ar_claim", &Br);
      <Transcript as ProofTranscript<G>>::append_scalar(transcript, b"Ar_claim", &Cr);
      (Ar, Br, Cr)
    };
    timer_eval.stop();

    let r1cs_eval_proof = {
      let proof = R1CSEvalProof::prove(
        &decomm.decomm,
        &rx,
        &ry,
        &inst_evals,
        &gens.gens_r1cs_eval,
        transcript,
        &mut random_tape,
      );

      let mut proof_encoded = vec![];
      proof.serialize_compressed(&mut proof_encoded).unwrap();

      Timer::print(&format!("len_r1cs_eval_proof {:?}", proof_encoded.len()));
      proof
    };

    timer_prove.stop();
    SNARK {
      r1cs_sat_proof,
      inst_evals,
      r1cs_eval_proof,
    }
  }

  /// A method to verify the SNARK proof of the satisfiability of an R1CS instance
  pub fn verify(
    &self,
    comm: &ComputationCommitment<G>,
    input: &InputsAssignment<G::ScalarField>,
    transcript: &mut Transcript,
    gens: &SNARKGens<G>,
  ) -> Result<(), ProofVerifyError> {
    let timer_verify = Timer::new("SNARK::verify");
    <Transcript as ProofTranscript<G>>::append_protocol_name(
      transcript,
      SNARK::<G>::protocol_name(),
    );

    // append a commitment to the computation to the transcript
    comm.comm.append_to_transcript(b"comm", transcript);

    let timer_sat_proof = Timer::new("verify_sat_proof");
    assert_eq!(input.assignment.len(), comm.comm.get_num_inputs());
    let (rx, ry) = self.r1cs_sat_proof.verify(
      comm.comm.get_num_vars(),
      comm.comm.get_num_cons(),
      &input.assignment,
      &self.inst_evals,
      transcript,
      &gens.gens_r1cs_sat,
    )?;
    timer_sat_proof.stop();

    let timer_eval_proof = Timer::new("verify_eval_proof");
    let (Ar, Br, Cr) = &self.inst_evals;
    <Transcript as ProofTranscript<G>>::append_scalar(transcript, b"Ar_claim", Ar);
    <Transcript as ProofTranscript<G>>::append_scalar(transcript, b"Ar_claim", Br);
    <Transcript as ProofTranscript<G>>::append_scalar(transcript, b"Ar_claim", Cr);
    self.r1cs_eval_proof.verify(
      &comm.comm,
      &rx,
      &ry,
      &self.inst_evals,
      &gens.gens_r1cs_eval,
      transcript,
    )?;
    timer_eval_proof.stop();
    timer_verify.stop();
    Ok(())
  }
}

/// `NIZKGens` holds public parameters for producing and verifying proofs with the Spartan NIZK
pub struct NIZKGens<G> {
  gens_r1cs_sat: R1CSGens<G>,
}

impl<G: CurveGroup> NIZKGens<G> {
  /// Constructs a new `NIZKGens` given the size of the R1CS statement
  pub fn new(num_cons: usize, num_vars: usize, num_inputs: usize) -> Self {
    let num_vars_padded = {
      let mut num_vars_padded = max(num_vars, num_inputs + 1);
      if num_vars_padded != num_vars_padded.next_power_of_two() {
        num_vars_padded = num_vars_padded.next_power_of_two();
      }
      num_vars_padded
    };

    let gens_r1cs_sat = R1CSGens::<G>::new(b"gens_r1cs_sat", num_cons, num_vars_padded);
    NIZKGens { gens_r1cs_sat }
  }
}

/// `NIZK` holds a proof produced by Spartan NIZK
#[derive(CanonicalSerialize, CanonicalDeserialize, Debug)]
pub struct NIZK<G: CurveGroup> {
  r1cs_sat_proof: R1CSProof<G>,
  r: (Vec<G::ScalarField>, Vec<G::ScalarField>),
}

impl<G: CurveGroup> NIZK<G> {
  fn protocol_name() -> &'static [u8] {
    b"Spartan NIZK proof"
  }

  /// A method to produce a NIZK proof of the satisfiability of an R1CS instance
  pub fn prove(
    inst: &Instance<G::ScalarField>,
    vars: VarsAssignment<G::ScalarField>,
    input: &InputsAssignment<G::ScalarField>,
    gens: &NIZKGens<G>,
    transcript: &mut Transcript,
  ) -> Self {
    let timer_prove = Timer::new("NIZK::prove");
    // we create a Transcript object seeded with a random F
    // to aid the prover produce its randomness
    let mut random_tape = RandomTape::new(b"proof");

    <Transcript as ProofTranscript<G>>::append_protocol_name(
      transcript,
      NIZK::<G>::protocol_name(),
    );
    <R1CSInstance<G::ScalarField> as AppendToTranscript<G>>::append_to_transcript(
      &inst.inst, b"inst", transcript,
    );

    let (r1cs_sat_proof, rx, ry) = {
      // we might need to pad variables
      let padded_vars = {
        let num_padded_vars = inst.inst.get_num_vars();
        let num_vars = vars.assignment.len();
        if num_padded_vars > num_vars {
          vars.pad(num_padded_vars)
        } else {
          vars
        }
      };

      let (proof, rx, ry) = R1CSProof::prove(
        &inst.inst,
        padded_vars.assignment,
        &input.assignment,
        &gens.gens_r1cs_sat,
        transcript,
        &mut random_tape,
      );

      let mut proof_encoded = vec![];
      proof.serialize_compressed(&mut proof_encoded).unwrap();

      Timer::print(&format!("len_r1cs_sat_proof {:?}", proof_encoded.len()));
      (proof, rx, ry)
    };

    timer_prove.stop();
    NIZK {
      r1cs_sat_proof,
      r: (rx, ry),
    }
  }

  /// A method to verify a NIZK proof of the satisfiability of an R1CS instance
  pub fn verify(
    &self,
    inst: &Instance<G::ScalarField>,
    input: &InputsAssignment<G::ScalarField>,
    transcript: &mut Transcript,
    gens: &NIZKGens<G>,
  ) -> Result<(), ProofVerifyError> {
    let timer_verify = Timer::new("NIZK::verify");

    <Transcript as ProofTranscript<G>>::append_protocol_name(
      transcript,
      NIZK::<G>::protocol_name(),
    );
    <R1CSInstance<G::ScalarField> as AppendToTranscript<G>>::append_to_transcript(
      &inst.inst, b"inst", transcript,
    );

    // We send evaluations of A, B, C at r = (rx, ry) as claims
    // to enable the verifier complete the first sum-check
    let timer_eval = Timer::new("eval_sparse_polys");
    let (claimed_rx, claimed_ry) = &self.r;
    let inst_evals = inst.inst.evaluate(claimed_rx, claimed_ry);
    timer_eval.stop();

    let timer_sat_proof = Timer::new("verify_sat_proof");
    assert_eq!(input.assignment.len(), inst.inst.get_num_inputs());
    let (rx, ry) = self.r1cs_sat_proof.verify(
      inst.inst.get_num_vars(),
      inst.inst.get_num_cons(),
      &input.assignment,
      &inst_evals,
      transcript,
      &gens.gens_r1cs_sat,
    )?;

    // verify if claimed rx and ry are correct
    assert_eq!(rx, *claimed_rx);
    assert_eq!(ry, *claimed_ry);
    timer_sat_proof.stop();
    timer_verify.stop();

    Ok(())
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  use ark_bls12_381::{Fr, G1Projective};
  use ark_std::One;
  use ark_std::Zero;

  #[test]
  pub fn check_snark() {
    check_snark_helper::<G1Projective>()
  }
  pub fn check_snark_helper<G: CurveGroup>() {
    let num_vars = 256;
    let num_cons = num_vars;
    let num_inputs = 10;

    // produce public generators
    let gens = SNARKGens::<G>::new(num_cons, num_vars, num_inputs, num_cons);

    // produce a synthetic R1CSInstance
    let (inst, vars, inputs) = Instance::produce_synthetic_r1cs(num_cons, num_vars, num_inputs);

    // create a commitment to R1CSInstance
    let (comm, decomm) = SNARK::encode(&inst, &gens);

    // produce a proof
    let mut prover_transcript = Transcript::new(b"example");
    let proof = SNARK::prove(
      &inst,
      &comm,
      &decomm,
      vars,
      &inputs,
      &gens,
      &mut prover_transcript,
    );

    // verify the proof
    let mut verifier_transcript = Transcript::new(b"example");
    assert!(proof
      .verify(&comm, &inputs, &mut verifier_transcript, &gens)
      .is_ok());
  }

  #[test]
  pub fn check_r1cs_invalid_index() {
    check_r1cs_invalid_index_helper::<Fr>();
  }

  pub fn check_r1cs_invalid_index_helper<F: PrimeField>() {
    let num_cons = 4;
    let num_vars = 8;
    let num_inputs = 1;

    let zero = F::zero();

    let A = vec![(0, 0, zero)];
    let B = vec![(100, 1, zero)];
    let C = vec![(1, 1, zero)];

    let inst = Instance::new(num_cons, num_vars, num_inputs, &A, &B, &C);
    assert!(inst.is_err());
    // assert_eq!(inst.err(), Some(R1CSError::InvalidIndex));
  }

  // #[test]
  // pub fn check_r1cs_invalid_scalar() {
  //   let num_cons = 4;
  //   let num_vars = 8;
  //   let num_inputs = 1;

  //   let zero = F::from(0);

  //   let larger_than_mod = [
  //     3, 0, 0, 0, 255, 255, 255, 255, 254, 91, 254, 255, 2, 164, 189, 83, 5, 216, 161, 9, 8, 216,
  //     57, 51, 72, 125, 157, 41, 83, 167, 237, 115,
  //   ];

  //   let A = vec![(0, 0, zero)];
  //   let B = vec![(1, 1, larger_than_mod)];
  //   let C = vec![(1, 1, zero)];

  //   let inst = Instance::new(num_cons, num_vars, num_inputs, &A, &B, &C);
  //   assert!(inst.is_err());
  //   // assert_eq!(inst.err(), Some(R1CSError::InvalidF));
  // }

  #[test]
  fn test_padded_constraints() {
    test_padded_constraints_helper::<G1Projective>()
  }

  fn test_padded_constraints_helper<G: CurveGroup>() {
    // parameters of the R1CS instance
    let num_cons = 1;
    let num_vars = 0;
    let num_inputs = 3;
    let num_non_zero_entries = 3;

    // We will encode the above constraints into three matrices, where
    // the coefficients in the matrix are in the little-endian byte order
    let mut A: Vec<(usize, usize, G::ScalarField)> = Vec::new();
    let mut B: Vec<(usize, usize, G::ScalarField)> = Vec::new();
    let mut C: Vec<(usize, usize, G::ScalarField)> = Vec::new();

    let zero = G::ScalarField::zero();
    let one = G::ScalarField::one();

    // Create a^2 + b + 13
    A.push((0, num_vars + 2, one)); // 1*a
    B.push((0, num_vars + 2, one)); // 1*a
    C.push((0, num_vars + 1, one)); // 1*z
    C.push((0, num_vars, -G::ScalarField::from(13u64))); // -13*1
    C.push((0, num_vars + 3, -G::ScalarField::one())); // -1*b

    // Var Assignments (Z_0 = 16 is the only output)
    let vars = vec![zero; num_vars];

    // create an InputsAssignment (a = 1, b = 2)
    let mut inputs = vec![zero; num_inputs];
    inputs[0] = G::ScalarField::from(16u64);
    inputs[1] = G::ScalarField::from(1u64);
    inputs[2] = G::ScalarField::from(2u64);

    let assignment_inputs = InputsAssignment::new(&inputs).unwrap();
    let assignment_vars = VarsAssignment::new(&vars).unwrap();

    // Check if instance is satisfiable
    let inst = Instance::new(num_cons, num_vars, num_inputs, &A, &B, &C).unwrap();
    let res = inst.is_sat(&assignment_vars, &assignment_inputs);
    assert!(res.unwrap(), "should be satisfied");

    // SNARK public params
    let gens = SNARKGens::<G>::new(num_cons, num_vars, num_inputs, num_non_zero_entries);

    // create a commitment to the R1CS instance
    let (comm, decomm) = SNARK::encode(&inst, &gens);

    // produce a SNARK
    let mut prover_transcript = Transcript::new(b"snark_example");
    let proof = SNARK::prove(
      &inst,
      &comm,
      &decomm,
      assignment_vars.clone(),
      &assignment_inputs,
      &gens,
      &mut prover_transcript,
    );

    // verify the SNARK
    let mut verifier_transcript = Transcript::new(b"snark_example");
    assert!(proof
      .verify(&comm, &assignment_inputs, &mut verifier_transcript, &gens)
      .is_ok());

    // NIZK public params
    let gens = NIZKGens::<G>::new(num_cons, num_vars, num_inputs);

    // produce a NIZK
    let mut prover_transcript = Transcript::new(b"nizk_example");
    let proof = NIZK::prove(
      &inst,
      assignment_vars,
      &assignment_inputs,
      &gens,
      &mut prover_transcript,
    );

    // verify the NIZK
    let mut verifier_transcript = Transcript::new(b"nizk_example");
    assert!(proof
      .verify(&inst, &assignment_inputs, &mut verifier_transcript, &gens)
      .is_ok());
  }
}
