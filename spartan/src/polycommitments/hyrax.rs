use ark_ec::CurveGroup;
use ark_ff::PrimeField;
use ark_poly_commit::Error;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{
  fmt::Debug,
  marker::PhantomData,
  ops::{Add, AddAssign, Mul, MulAssign},
  rand::RngCore,
};
use merlin::Transcript;

pub use crate::dense_mlpoly::{
  PolyCommitment, PolyCommitmentBlinds, PolyCommitmentGens, PolyEvalProof,
};

use crate::{
  dense_mlpoly::{DensePolynomial, EqPolynomial},
  math::Math,
  polycommitments::{PolyCommitmentScheme, PolyCommitmentTrait},
  random::RandomTape,
  transcript::{AppendToTranscript, ProofTranscript},
};

use super::error::PCSError;

#[derive(Clone, CanonicalSerialize, CanonicalDeserialize, Debug)]
pub struct HyraxKey<G: CurveGroup> {
  pub gens: PolyCommitmentGens<G>,
}

#[derive(Clone, Default, CanonicalSerialize, CanonicalDeserialize, Debug, PartialEq, Eq)]
pub struct HyraxCommitment<G: CurveGroup> {
  pub C: PolyCommitment<G>,
}

impl<G> Add<Self> for HyraxCommitment<G>
where
  G: CurveGroup,
{
  type Output = Self;
  fn add(self, other: Self) -> Self::Output {
    let C = self
      .C
      .C
      .iter()
      .zip(other.C.C.iter())
      .map(|(a, b)| *a + *b)
      .collect();
    Self {
      C: PolyCommitment { C },
    }
  }
}

impl<G> AddAssign<Self> for HyraxCommitment<G>
where
  G: CurveGroup,
{
  fn add_assign(&mut self, other: Self) {
    for (a, b) in self.C.C.iter_mut().zip(other.C.C.iter()) {
      *a += *b;
    }
  }
}

impl<G> MulAssign<G::ScalarField> for HyraxCommitment<G>
where
  G: CurveGroup,
{
  fn mul_assign(&mut self, scalar: G::ScalarField) {
    for a in self.C.C.iter_mut() {
      *a *= scalar;
    }
  }
}

impl<G> Mul<G::ScalarField> for HyraxCommitment<G>
where
  G: CurveGroup,
{
  type Output = Self;
  fn mul(self, scalar: G::ScalarField) -> Self::Output {
    let C = self.C.C.iter().map(|a| *a * scalar).collect::<Vec<_>>();
    Self {
      C: PolyCommitment { C },
    }
  }
}

impl<G: CurveGroup> PolyCommitmentTrait<G> for HyraxCommitment<G> {
  fn zero(n: usize) -> Self {
    let ell = n.log_2();

    let (left_num_vars, _) = EqPolynomial::<G::ScalarField>::compute_factored_lens(ell);
    let commitment_size = left_num_vars.pow2();
    Self {
      C: PolyCommitment {
        C: vec![G::zero(); commitment_size],
      },
    }
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

pub struct Hyrax<G> {
  _phantom: PhantomData<G>,
}

impl<G: CurveGroup> PolyCommitmentScheme<G> for Hyrax<G> {
  type SRS = HyraxKey<G>;
  type Commitment = HyraxCommitment<G>;
  type PolyCommitmentKey = HyraxKey<G>;
  type EvalVerifierKey = HyraxKey<G>;

  type PolyCommitmentProof = HyraxProof<G>;

  fn trim<'a>(
    srs: &Self::SRS,
    _supported_num_vars: usize,
  ) -> (Self::PolyCommitmentKey, Self::EvalVerifierKey) {
    let commit_key = srs.clone();
    let verifier_key = srs.clone();
    (commit_key, verifier_key)
  }

  fn commit<'a>(
    poly: &DensePolynomial<G::ScalarField>,
    ck: &Self::PolyCommitmentKey,
  ) -> HyraxCommitment<G> {
    let (C, _blinds) = poly.commit(&ck.gens, None);
    HyraxCommitment { C }
  }

  fn prove<'a>(
    poly: &DensePolynomial<G::ScalarField>,
    r: &[<G>::ScalarField],
    eval: &<G>::ScalarField,
    ck: &Self::PolyCommitmentKey,
    transcript: &mut Transcript,
  ) -> Self::PolyCommitmentProof {
    let mut new_tape = RandomTape::new(b"HyraxPolyCommitmentProof");
    let (_proof, _) = PolyEvalProof::prove(
      poly,
      None,
      r,
      eval,
      None,
      &ck.gens,
      transcript,
      &mut new_tape,
    );
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
