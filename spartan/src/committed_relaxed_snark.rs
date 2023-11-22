#![allow(dead_code)]
/// This is mostly a copy of the SNARK implementation in lib.rs, with minor modifications to work with committed relaxed R1CS.
use core::cmp::max;

use ark_ec::CurveGroup;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use merlin::Transcript;

use crate::{
  crr1csproof::{CRR1CSInstance, CRR1CSKey, CRR1CSProof, CRR1CSShape, CRR1CSWitness},
  errors::ProofVerifyError,
  polycommitments::PolyCommitmentScheme,
  r1csinstance::{R1CSCommitmentGens, R1CSEvalProof},
  random::RandomTape,
  timer::Timer,
  transcript::{AppendToTranscript, ProofTranscript},
  ComputationCommitment, ComputationDecommitment, Instance,
};

/// `SNARKGens` holds public parameters for producing and verifying proofs with the Spartan SNARK
pub struct SNARKGens<G: CurveGroup, PC: PolyCommitmentScheme<G>> {
  gens_r1cs_sat: CRR1CSKey<G, PC>,
  gens_r1cs_eval: R1CSCommitmentGens<G>,
}

impl<G: CurveGroup, PC: PolyCommitmentScheme<G>> SNARKGens<G, PC> {
  /// Constructs a new `SNARKGens` given the size of the R1CS statement
  /// `num_nz_entries` specifies the maximum number of non-zero entries in any of the three R1CS matrices
  pub fn new(
    SRS: PC::SRS,
    num_cons: usize,
    num_vars: usize,
    num_inputs: usize,
    num_nz_entries: usize,
  ) -> Self {
    let num_vars_padded = {
      let mut num_vars_padded = max(num_vars, num_inputs + 1);
      if num_vars_padded != num_vars_padded.next_power_of_two() {
        num_vars_padded = num_vars_padded.next_power_of_two();
      }
      num_vars_padded
    };

    let gens_r1cs_sat = CRR1CSKey::<G, PC>::new(&SRS, num_cons, num_vars_padded);
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
#[allow(clippy::upper_case_acronyms)]
pub struct SNARK<G: CurveGroup, PC: PolyCommitmentScheme<G>> {
  r1cs_sat_proof: CRR1CSProof<G, PC>,
  inst_evals: (G::ScalarField, G::ScalarField, G::ScalarField),
  r1cs_eval_proof: R1CSEvalProof<G>,
}

impl<G: CurveGroup, PC: PolyCommitmentScheme<G>> SNARK<G, PC> {
  fn protocol_name() -> &'static [u8] {
    b"Spartan SNARK proof"
  }

  /// A public computation to create a commitment to an R1CS instance
  pub fn encode(
    inst: &Instance<G::ScalarField>,
    gens: &SNARKGens<G, PC>,
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
    shape: &CRR1CSShape<G::ScalarField>,
    instance: &CRR1CSInstance<G, PC>,
    witness: CRR1CSWitness<G::ScalarField>,
    comm: &ComputationCommitment<G>,
    decomm: &ComputationDecommitment<G::ScalarField>,
    gens: &SNARKGens<G, PC>,
    transcript: &mut Transcript,
  ) -> Self {
    let timer_prove = Timer::new("SNARK::prove");

    let inst = &shape.inst;
    let CRR1CSWitness { W: vars, E } = witness;

    // we create a Transcript object seeded with a random F
    // to aid the prover produce its randomness
    let mut random_tape = Some(RandomTape::<G>::new(b"proof"));
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

        let witness = CRR1CSWitness::<G::ScalarField> { W: padded_vars, E };

        CRR1CSProof::prove(
          shape,
          instance,
          &witness,
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
        &mut random_tape.unwrap(),
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
    instance: &CRR1CSInstance<G, PC>,
    transcript: &mut Transcript,
    gens: &SNARKGens<G, PC>,
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
