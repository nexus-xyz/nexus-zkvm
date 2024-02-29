#![allow(dead_code)]
/// This is mostly a copy of the SNARK implementation in lib.rs, with minor modifications to work with committed relaxed R1CS.
use core::cmp::max;

use ark_ec::CurveGroup;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::Zero;
use merlin::Transcript;

use crate::{
  crr1csproof::{CRR1CSInstance, CRR1CSKey, CRR1CSProof, CRR1CSShape, CRR1CSWitness},
  errors::ProofVerifyError,
  polycommitments::PolyCommitmentScheme,
  r1csinstance::{R1CSCommitmentGens, R1CSEvalProof},
  timer::Timer,
  transcript::{AppendToTranscript, ProofTranscript},
  ComputationCommitment, ComputationDecommitment, Instance,
};

/// `SNARKGens` holds public parameters for producing and verifying proofs with the Spartan SNARK
#[derive(CanonicalDeserialize, CanonicalSerialize)]
pub struct CRSNARKKey<G: CurveGroup, PC: PolyCommitmentScheme<G>> {
  pub gens_r1cs_sat: CRR1CSKey<G, PC>,
  pub gens_r1cs_eval: R1CSCommitmentGens<G, PC>,
}

impl<G: CurveGroup, PC: PolyCommitmentScheme<G>> CRSNARKKey<G, PC> {
  /// Constructs a new `SNARKGens` given the size of the R1CS statement
  /// `num_nz_entries` specifies the maximum number of non-zero entries in any of the three R1CS matrices
  pub fn new(
    SRS: &PC::SRS,
    num_cons: usize,
    num_vars: usize,
    num_inputs: usize,
    num_nz_entries: usize,
  ) -> Self {
    let num_vars_padded = Self::get_num_vars_padded(num_vars, num_inputs);
    let gens_r1cs_sat = CRR1CSKey::<G, PC>::new(SRS, num_cons, num_vars_padded);
    let gens_r1cs_eval =
      R1CSCommitmentGens::new(SRS, num_cons, num_vars_padded, num_inputs, num_nz_entries);
    CRSNARKKey {
      gens_r1cs_sat,
      gens_r1cs_eval,
    }
  }
  fn get_num_vars_padded(num_vars: usize, num_inputs: usize) -> usize {
    let mut num_vars_padded = max(num_vars, num_inputs + 1);
    if num_vars_padded != num_vars_padded.next_power_of_two() {
      num_vars_padded = num_vars_padded.next_power_of_two();
    }
    num_vars_padded
  }
  pub fn get_min_num_vars(
    num_cons: usize,
    num_vars: usize,
    num_inputs: usize,
    num_nz_entries: usize,
  ) -> usize {
    let num_vars_padded = Self::get_num_vars_padded(num_vars, num_inputs);
    let min_num_vars_sat = CRR1CSKey::<G, PC>::get_min_num_vars(num_cons, num_vars_padded);
    let min_num_vars_eval =
      R1CSCommitmentGens::<G, PC>::get_min_num_vars(num_cons, num_vars_padded, num_nz_entries);
    max(min_num_vars_sat, min_num_vars_eval)
  }
}

/// `SNARK` holds a proof produced by Spartan SNARK
#[derive(CanonicalSerialize, CanonicalDeserialize, Debug)]
#[allow(clippy::upper_case_acronyms)]
pub struct SNARK<G: CurveGroup, PC: PolyCommitmentScheme<G>> {
  r1cs_sat_proof: CRR1CSProof<G, PC>,
  inst_evals: (G::ScalarField, G::ScalarField, G::ScalarField),
  r1cs_eval_proof: R1CSEvalProof<G, PC>,
}

impl<G: CurveGroup, PC: PolyCommitmentScheme<G>> SNARK<G, PC> {
  fn protocol_name() -> &'static [u8] {
    b"Spartan SNARK proof"
  }

  /// A public computation to create a commitment to an R1CS instance
  pub fn encode(
    inst: &Instance<G::ScalarField>,
    gens: &CRSNARKKey<G, PC>,
  ) -> (
    ComputationCommitment<G, PC>,
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
    shape: &CRR1CSShape<G::ScalarField>,
    instance: &CRR1CSInstance<G, PC>,
    witness: CRR1CSWitness<G::ScalarField>,
    comm: &ComputationCommitment<G, PC>,
    decomm: &ComputationDecommitment<G::ScalarField>,
    key: &CRSNARKKey<G, PC>,
    transcript: &mut Transcript,
  ) -> Self {
    let timer_prove = Timer::new("SNARK::prove");

    let inst = &shape.inst;
    let CRR1CSWitness { W: vars, E } = witness;

    <Transcript as ProofTranscript<G>>::append_protocol_name(
      transcript,
      SNARK::<G, PC>::protocol_name(),
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

        // we also might need to pad the error vector
        let padded_error = {
          let num_padded_cons = inst.inst.get_num_cons();
          let num_cons = E.len();
          if num_padded_cons > num_cons {
            let mut padded_error = E.clone();
            padded_error.resize(num_padded_cons, G::ScalarField::zero());
            padded_error
          } else {
            E
          }
        };

        let witness = CRR1CSWitness::<G::ScalarField> {
          W: padded_vars,
          E: padded_error,
        };

        CRR1CSProof::prove(shape, instance, witness, &key.gens_r1cs_sat, transcript)
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
        &key.gens_r1cs_eval,
        transcript,
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
    comm: &ComputationCommitment<G, PC>,
    instance: &CRR1CSInstance<G, PC>,
    transcript: &mut Transcript,
    key: &CRSNARKKey<G, PC>,
  ) -> Result<(), ProofVerifyError> {
    let timer_verify = Timer::new("SNARK::verify");
    <Transcript as ProofTranscript<G>>::append_protocol_name(
      transcript,
      SNARK::<G, PC>::protocol_name(),
    );

    let CRR1CSInstance { input, .. } = instance;

    // append a commitment to the computation to the transcript
    comm.comm.append_to_transcript(b"comm", transcript);

    let timer_sat_proof = Timer::new("verify_sat_proof");
    assert_eq!(input.assignment.len(), comm.comm.get_num_inputs());
    let (rx, ry) = self.r1cs_sat_proof.verify(
      comm.comm.get_num_vars(),
      comm.comm.get_num_cons(),
      instance,
      &self.inst_evals,
      transcript,
      &key.gens_r1cs_sat.keys.vk,
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
      &key.gens_r1cs_eval,
      transcript,
    )?;
    timer_eval_proof.stop();
    timer_verify.stop();
    Ok(())
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  use crate::{
    crr1cs::produce_synthetic_crr1cs,
    polycommitments::{zeromorph::Zeromorph, PolyCommitmentScheme},
  };

  use ark_bls12_381::{Bls12_381, G1Projective};

  #[test]
  pub fn check_crsnark() {
    check_crsnark_helper::<G1Projective, Zeromorph<Bls12_381>>()
  }
  pub fn check_crsnark_helper<G: CurveGroup, PC: PolyCommitmentScheme<G>>() {
    let num_vars = 256;
    let num_cons = num_vars;
    let num_inputs = 10;

    // produce a synthetic CRR1CSInstance
    let (shape, instance, witness, key) = produce_synthetic_crr1cs(num_cons, num_vars, num_inputs);

    // create a commitment to R1CSInstance
    let (comm, decomm) = SNARK::<_, PC>::encode(&shape.inst, &key);

    // produce a proof
    let mut prover_transcript = Transcript::new(b"example");
    let proof = SNARK::<_, PC>::prove(
      &shape,
      &instance,
      witness,
      &comm,
      &decomm,
      &key,
      &mut prover_transcript,
    );

    // verify the proof
    let mut verifier_transcript = Transcript::new(b"example");
    assert!(proof
      .verify(&comm, &instance, &mut verifier_transcript, &key)
      .is_ok());
  }
}
