use ark_ec::CurveGroup;
use ark_ff::PrimeField;
use ark_poly_commit::{Error, PCCommitment, PCRandomness, PCUniversalParams};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{fmt::Debug, rand::RngCore};
use merlin::Transcript;

pub use crate::dense_mlpoly::{
  PolyCommitment, PolyCommitmentBlinds, PolyCommitmentGens, PolyEvalProof,
};

use crate::{
  dense_mlpoly::DensePolynomial,
  polycommitments::PolyCommitmentScheme,
  random::RandomTape,
  transcript::{AppendToTranscript, ProofTranscript},
};

use super::error::PCSError;

#[derive(Clone, CanonicalSerialize, CanonicalDeserialize, Debug)]
pub struct HyraxKey<G: CurveGroup> {
  pub gens: PolyCommitmentGens<G>,
}

impl<G: CurveGroup> PCUniversalParams for HyraxKey<G> {
  fn max_degree(&self) -> usize {
    self.gens.gens.gens_n.n
  }
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
  type PolyCommitmentKey<'a> = HyraxKey<G>;
  type EvalVerifierKey = HyraxKey<G>;

  type PolyCommitmentProof = HyraxProof<G>;

  fn trim<'a>(
    srs: &Self::SRS,
    supported_degree: usize,
    supported_hiding_bound: usize,
    enforced_degree_bounds: Option<&[usize]>,
  ) -> (Self::PolyCommitmentKey<'a>, Self::EvalVerifierKey) {
    let commit_key = srs.clone();
    let verifier_key = srs.clone();
    (commit_key, verifier_key)
  }

  fn commit<'a>(
    poly: &DensePolynomial<G::ScalarField>,
    ck: &Self::PolyCommitmentKey<'a>,
    random_tape: &mut Option<RandomTape<G>>,
  ) -> HyraxCommitment<G> {
    let (C, _blinds) = poly.commit(&ck.gens, random_tape.into());
    HyraxCommitment { C }
  }

  fn prove<'a>(
    poly: &DensePolynomial<G::ScalarField>,
    r: &[<G>::ScalarField],
    eval: &<G>::ScalarField,
    ck: &Self::PolyCommitmentKey<'a>,
    transcript: &mut Transcript,
    random_tape: &mut Option<RandomTape<G>>,
  ) -> Self::PolyCommitmentProof {
    let mut new_tape = RandomTape::new(b"HyraxPolyCommitmentProof");
    let random_tape = random_tape.as_mut().unwrap_or(&mut new_tape);
    let (_proof, _) =
      PolyEvalProof::prove(poly, None, r, eval, None, &ck.gens, transcript, random_tape);
    HyraxProof { proof: _proof }
  }

  fn verify(
    commitment: &Self::Commitment,
    proof: &Self::PolyCommitmentProof,
    ck: &Self::EvalVerifierKey,
    transcript: &mut Transcript,
    r: &[<G>::ScalarField],
    eval: &<G>::ScalarField,
  ) -> Result<(), PCSError> {
    proof
      .proof
      .verify_plain(&ck.gens, transcript, r, eval, &commitment.C)
      .map_err(|_| PCSError::EvalVerifierFailure)
  }

  fn setup(
    num_poly_vars: usize,
    label: &'static [u8],
    _rng: &mut impl RngCore,
  ) -> Result<Self::SRS, Error> {
    Ok(HyraxKey {
      gens: PolyCommitmentGens::new(num_poly_vars, label),
    })
  }
}
