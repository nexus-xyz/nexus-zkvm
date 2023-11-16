use crate::dense_mlpoly::DensePolynomial;
use crate::math::Math;
use crate::polycommitments::{
  PolyCommitmentScheme, PolyCommitmentTrait, SRSTrait, VectorCommitmentTrait,
};
use crate::transcript::{AppendToTranscript, ProofTranscript};
use ark_ec::pairing::Pairing;
use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::PrimeField;
use ark_poly_commit::{
  kzg10::Commitment as KZGCommitment, LabeledCommitment, LabeledPolynomial, PCCommitment,
  PCRandomness, PCUniversalParams, PolynomialCommitment as UnivarPolyCommitment,
};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::fmt::Debug;
use ark_std::rand::RngCore;
use ark_std::{marker::PhantomData, vec::Vec};
use merlin::Transcript;

impl<G: CurveGroup, C: PCCommitment> PolyCommitmentTrait<G> for C
where
  C: PartialEq + Debug + AppendToTranscript<G>,
{
  fn zero(_n: usize) -> Self {
    C::empty()
  }
}

impl<U: PCUniversalParams> SRSTrait for U {
  fn setup(num_poly_vars: usize, label: &'static [u8], rng: &mut impl RngCore) -> Self {
    Self::setup(num_poly_vars.log_2() as usize, label, rng)
  }
}

impl<G: CurveGroup, C: PCCommitment> AppendToTranscript<G> for LabeledCommitment<C> {
  fn append_to_transcript(&self, label: &'static [u8], transcript: &mut Transcript) {
    todo!()
  }
}

impl<E: Pairing> AppendToTranscript<E::G1> for KZGCommitment<E> {
  fn append_to_transcript(&self, label: &'static [u8], transcript: &mut Transcript) {
    transcript.append_point(label, &self.0.into_group());
  }
}

#[derive(Clone, Debug, PartialEq, CanonicalSerialize, CanonicalDeserialize)]
struct ZeromorphVC<E>
where
  E: Pairing,
{
  comm: KZGCommitment<E>,
}

impl<E> AppendToTranscript<E::G1> for ZeromorphVC<E>
where
  E: Pairing,
{
  fn append_to_transcript(&self, label: &'static [u8], transcript: &mut Transcript) {
    self.comm.append_to_transcript(label, transcript);
  }
}
