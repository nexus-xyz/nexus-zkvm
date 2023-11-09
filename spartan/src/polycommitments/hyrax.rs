use ark_ec::CurveGroup;
use ark_ff::PrimeField;
use ark_poly_commit::{
  PCCommitment, PCCommitterKey, PCRandomness, PCUniversalParams, PCVerifierKey,
};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{fmt::Debug, rand::RngCore};
use merlin::Transcript;

pub use crate::dense_mlpoly::{
  PolyCommitment, PolyCommitmentBlinds, PolyCommitmentGens, PolyEvalProof,
};

use crate::{
  dense_mlpoly::DensePolynomial,
  errors::ProofVerifyError,
  polycommitments::{CommitmentKeyTrait, PolyCommitmentScheme, VectorCommitmentTrait},
  random::RandomTape,
  transcript::{AppendToTranscript, ProofTranscript},
};

#[derive(Clone, CanonicalSerialize, CanonicalDeserialize, Debug)]
pub struct HyraxKey<G: CurveGroup> {
  pub gens: PolyCommitmentGens<G>,
}

#[derive(Clone, CanonicalSerialize, CanonicalDeserialize, Debug, PartialEq)]
pub struct HyraxCommitment<G: CurveGroup> {
  pub C: PolyCommitment<G>,
}

impl<G: CurveGroup> PCCommitment for HyraxCommitment<G> {
  fn empty() -> Self {
    Self {
      C: PolyCommitment::<G> { C: vec![] },
    }
  }
  fn has_degree_bound(&self) -> bool {
    true
  }
}
impl<G: CurveGroup> AppendToTranscript<G> for HyraxCommitment<G> {
  fn append_to_transcript(&self, label: &'static [u8], transcript: &mut Transcript) {
    transcript.append_message(label, b"hyrax_commitment_begin");
    let comm = &self.C.C;
    for i in 0..comm.len() {
      transcript.append_point(b"hyrax_commitment_share", &(*comm)[i]);
    }
    transcript.append_message(label, b"hyrax_commitment_end");
  }
}

#[derive(Clone, CanonicalSerialize, CanonicalDeserialize, Debug)]
pub struct HyraxBlinds<F: PrimeField> {
  pub blinds: PolyCommitmentBlinds<F>,
}

#[derive(CanonicalSerialize, CanonicalDeserialize, Debug)]
pub struct HyraxProof<G: CurveGroup> {
  pub proof: PolyEvalProof<G>,
}

#[derive(CanonicalSerialize, CanonicalDeserialize, Debug)]
pub struct HyraxVectorCommitment<G: CurveGroup> {
  pub C: PolyCommitment<G>,
}

impl<G: CurveGroup> AppendToTranscript<G> for HyraxVectorCommitment<G> {
  fn append_to_transcript(&self, label: &'static [u8], transcript: &mut Transcript) {
    transcript.append_message(label, b"hyrax_vector_commitment_begin");
    let comm = &self.C.C;
    for i in 0..comm.len() {
      transcript.append_point(b"hyrax_vector_commitment_share", &(*comm)[i]);
    }
    transcript.append_message(label, b"hyrax_vector_commitment_end");
  }
}

// impl<G: CurveGroup> CommitmentKeyTrait<G> for MultiCommitGens<G> {
//   fn setup(num_poly_vars: usize, label: &'static [u8]) -> Self {
//     MultiCommitGens::setup(num_poly_vars, label)
//   }
//}
impl<F: PrimeField> PCRandomness for HyraxBlinds<F> {
  fn rand<R: RngCore>(
    num_queries: usize,
    has_degree_bound: bool,
    degree: Option<usize>,
    rng: &mut R,
  ) -> Self {
    todo!()
  }
  fn empty() -> Self {
    Self {
      blinds: PolyCommitmentBlinds { blinds: vec![] },
    }
  }
}

impl<F: PrimeField> HyraxBlinds<F> {
  fn from_vec(vec: Vec<F>) -> Self {
    Self {
      blinds: PolyCommitmentBlinds { blinds: vec },
    }
  }
}
pub struct Hyrax<G> {
  phantom: G,
}

impl<G: CurveGroup> PolyCommitmentScheme<G> for Hyrax<G> {
  type SRS = HyraxKey<G>;
  type Commitment = HyraxCommitment<G>;
  type PolyCommitmentKey = HyraxKey<G>;
  type EvalVerifierKey = HyraxKey<G>;

  type Blinds = HyraxBlinds<G::ScalarField>;

  type PolyCommitmentProof = HyraxProof<G>;

  fn trim(
    srs: &Self::SRS,
    supported_degree: usize,
    supported_hiding_bound: usize,
    enforced_degree_bounds: Option<&[usize]>,
  ) -> (Self::PolyCommitmentKey, Self::EvalVerifierKey) {
    let commit_key = srs.clone();
    let verifier_key = srs.clone();
    let vector_commit_key = srs.clone();
    (commit_key, verifier_key)
  }

  fn commit(
    poly: &DensePolynomial<G::ScalarField>,
    ck: &Self::PolyCommitmentKey,
    random_tape: &mut Option<RandomTape<G>>,
  ) -> (
    HyraxCommitment<G>,
    Option<HyraxBlinds<<G as ark_ec::Group>::ScalarField>>,
  ) {
    let (C, blinds) = poly.commit(&ck.gens, random_tape.into());
    let comm = HyraxCommitment { C };
    let blinds = HyraxBlinds { blinds };
    (comm, Some(blinds))
  }

  fn prove(
    poly: &DensePolynomial<G::ScalarField>,
    r: &[<G>::ScalarField],
    eval: &<G>::ScalarField,
    ck: &Self::PolyCommitmentKey,
    transcript: &mut Transcript,
    random_tape: &mut Option<RandomTape<G>>,
  ) -> Self::PolyCommitmentProof {
    let mut new_tape = RandomTape::new(b"HyraxPolyCommitmentProof");
    let random_tape = random_tape.as_mut().unwrap_or(&mut new_tape);
    let (_proof, _) =
      PolyEvalProof::prove(poly, None, r, eval, None, &ck.gens, transcript, random_tape);
    let proof = HyraxProof { proof: _proof };
    proof
  }

  fn prove_blinded(
    poly: &DensePolynomial<G::ScalarField>,
    r: &[<G>::ScalarField],
    eval: &<G>::ScalarField,
    ck: &Self::PolyCommitmentKey,
    transcript: &mut Transcript,
    random_tape: &mut Option<RandomTape<G>>,
    blinds: &Self::Blinds,
    blind_eval: &<G>::ScalarField,
  ) -> (Self::PolyCommitmentProof, G) {
    let mut new_tape = RandomTape::new(b"HyraxPolyCommitmentProof");
    let random_tape = random_tape.as_mut().unwrap_or(&mut new_tape);
    let (_proof, g) = PolyEvalProof::prove(
      poly,
      Some(&blinds.blinds),
      r,
      eval,
      Some(blind_eval),
      &ck.gens,
      transcript,
      random_tape,
    );
    let proof = HyraxProof { proof: _proof };
    (proof, g)
  }

  fn verify(
    commitment: &Self::Commitment,
    proof: &Self::PolyCommitmentProof,
    ck: &Self::EvalVerifierKey,
    transcript: &mut Transcript,
    r: &[<G>::ScalarField],
    eval: &<G>::ScalarField,
  ) -> Result<(), ProofVerifyError> {
    proof
      .proof
      .verify_plain(&ck.gens, transcript, r, eval, &commitment.C)
  }

  fn verify_blinded(
    commitment: &Self::Commitment,
    proof: &Self::PolyCommitmentProof,
    ck: &Self::EvalVerifierKey,
    transcript: &mut Transcript,
    r: &[<G>::ScalarField],
    eval_commit: &G,
  ) -> Result<(), ProofVerifyError> {
    proof
      .proof
      .verify(&ck.gens, transcript, r, eval_commit, &commitment.C)
  }

  fn setup(num_poly_vars: usize, label: &'static [u8], rng: &mut impl RngCore) -> Self::SRS {
    HyraxKey {
      gens: PolyCommitmentGens::new(num_poly_vars, label),
    }
  }
}
