use super::{CommitmentKeyTrait, PolyCommitmentScheme, VectorCommitmentTrait};
use crate::dense_mlpoly::DensePolynomial;
use crate::random::RandomTape;
use crate::transcript::{AppendToTranscript, ProofTranscript};
use ark_crypto_primitives::sponge::{Absorb, CryptographicSponge};
use ark_ec::CurveGroup;
use ark_ff::{Field, PrimeField};
use ark_poly::{DenseUVPolynomial, Polynomial};
use ark_poly_commit::{LabeledPolynomial, PolynomialCommitment as UnivarPCS};
use merlin::Transcript;
use transcript_utils::PolyCommitmentTranscript;
// use ark_poly_commit::{
//   PCCommitment as UnivarCommitment, PCCommitterKey as UnivarCommitmentKey, PCRandomness,
//   PCUniversalParams, PCVerifierKey};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::rand::RngCore;
use ark_std::{marker::PhantomData, vec::Vec};
use std::fmt::Debug;

use super::transcript_utils;
mod algebra;
mod data_structures;

// impl<U: UnivarCommitment, G: CurveGroup> AppendToTranscript<G> for U {
//   fn append_to_transcript(&self, label: &'static [u8], transcript: &mut Transcript) {
//     transcript.append_message(label, b"univar_commitment_begin");
//     transcript.append_message(b"univar_commitment_params", &self.params);
//     transcript.append_point(b"univar_commitment_commitment", &self.comm);
//     transcript.append_message(b"univar_commitment_end", b"univar_commitment_end");
//   }
// }

#[derive(Clone, Debug, PartialEq, CanonicalSerialize, CanonicalDeserialize)]
struct ZeromorphVC<G, P, U>
where
  G: CurveGroup,
  P: DenseUVPolynomial<G::ScalarField>,
  U: UnivarPCS<G::ScalarField, P, PolyCommitmentTranscript>,
  U::Commitment: AppendToTranscript<G>,
{
  comm: U::Commitment,
}
impl<G, P, U> AppendToTranscript<G> for ZeromorphVC<G, P, U>
where
  G: CurveGroup,
  P: DenseUVPolynomial<G::ScalarField>,
  U: UnivarPCS<G::ScalarField, P, PolyCommitmentTranscript>,
  U::Commitment: AppendToTranscript<G>,
{
  fn append_to_transcript(&self, label: &'static [u8], transcript: &mut Transcript) {
    &self.comm.append_to_transcript(label, transcript);
  }
}

struct Zeromorph<G, P, U>
where
  G: CurveGroup,
  P: DenseUVPolynomial<G::ScalarField>,
  U: UnivarPCS<G::ScalarField, P, PolyCommitmentTranscript>,
{
  _phantom: PhantomData<U>,
  _phantom2: PhantomData<G>,
  _phantom3: PhantomData<P>,
}

impl<G, P, U> PolyCommitmentScheme<G> for Zeromorph<G, P, U>
where
  G: CurveGroup,
  P: DenseUVPolynomial<G::ScalarField>,
  U: UnivarPCS<G::ScalarField, P, PolyCommitmentTranscript>,
  U::Commitment:
    PartialEq + AppendToTranscript<G> + Debug + CanonicalSerialize + CanonicalDeserialize,
  U::Proof: Debug + CanonicalSerialize + CanonicalDeserialize,
{
  type PolyCommitmentKey = U::CommitterKey;

  type EvalVerifierKey = U::VerifierKey;

  type Commitment = U::Commitment;

  type SRS = U::UniversalParams;

  type PolyCommitmentProof = U::Proof;

  fn commit(
    poly: &DensePolynomial<<G>::ScalarField>,
    ck: &Self::PolyCommitmentKey,
    random_tape: &mut Option<RandomTape<G>>,
  ) -> Self::Commitment {
    let uni_poly = Zeromorph::<G, P, U>::multilinear_to_univar(poly.clone());
    let labeled_poly = LabeledPolynomial::new("poly".to_string(), uni_poly, None, None);
    let rt = random_tape
      .as_mut()
      .map_or(None, |rt| Some(rt as &mut dyn RngCore));
    let (labeled_commitment_vec, blinds) = U::commit(&ck, vec![&labeled_poly], rt).unwrap();
    labeled_commitment_vec[0].commitment().clone()
  }

  fn prove(
    poly: &DensePolynomial<<G>::ScalarField>,
    r: &[<G>::ScalarField],
    eval: &<G>::ScalarField,
    ck: &Self::PolyCommitmentKey,
    transcript: &mut Transcript,
    random_tape: &mut Option<RandomTape<G>>,
  ) -> Self::PolyCommitmentProof {
    todo!()
  }

  fn verify(
    commitment: &Self::Commitment,
    proof: &Self::PolyCommitmentProof,
    ck: &Self::EvalVerifierKey,
    transcript: &mut Transcript,
    r: &[<G>::ScalarField],
    eval: &<G>::ScalarField,
  ) -> Result<(), crate::errors::ProofVerifyError> {
    todo!()
  }

  fn setup(num_poly_vars: usize, label: &'static [u8], rng: &mut impl RngCore) -> (Self::SRS) {
    todo!()
  }
  fn trim(
    srs: &Self::SRS,
    supported_degree: usize,
    supported_hiding_bound: usize,
    enforced_degree_bounds: Option<&[usize]>,
  ) -> (Self::PolyCommitmentKey, Self::EvalVerifierKey) {
    todo!()
  }
}
