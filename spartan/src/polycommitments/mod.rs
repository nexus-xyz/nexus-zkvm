use ark_ec::CurveGroup;
use ark_poly_commit::Error;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{
  ops::{Add, AddAssign, Mul, MulAssign},
  rand::RngCore,
};
use core::fmt::Debug;
use derivative::Derivative;
use merlin::Transcript;

use crate::{dense_mlpoly::DensePolynomial, transcript::AppendToTranscript};

pub mod error;
pub mod hyrax;
mod transcript_utils;
pub mod zeromorph;

pub trait VectorCommitmentScheme<G: CurveGroup> {
  type VectorCommitment: AppendToTranscript<G>
    + Sized
    + Sync
    + CanonicalSerialize
    + CanonicalDeserialize;
  type CommitmentKey;
  fn commit(vec: &[G::ScalarField], ck: &Self::CommitmentKey) -> Self::VectorCommitment;

  // Commitment to the zero vector of length n
  fn zero(n: usize) -> Self::VectorCommitment;
}

pub trait PolyCommitmentTrait<G: CurveGroup>:
  Sized
  + AppendToTranscript<G>
  + Debug
  + CanonicalSerialize
  + CanonicalDeserialize
  + PartialEq
  + Eq
  + Add<Self, Output = Self>
  + AddAssign<Self>
  + MulAssign<G::ScalarField>
  + Mul<G::ScalarField, Output = Self>
  + Default
  + Clone
  + Send
  + Sync
{
  // this should be the commitment to the zero vector of length n
  fn zero(n: usize) -> Self;

  fn into_affine(&self) -> Vec<G::Affine>;
}

pub trait SRSTrait: CanonicalSerialize + CanonicalDeserialize {
  fn max_num_vars(&self) -> usize;
}

#[derive(CanonicalSerialize, CanonicalDeserialize, Derivative, Debug)]
#[derivative(Clone(bound = ""))]
pub struct PCSKeys<G, PC>
where
  G: CurveGroup,
  PC: PolyCommitmentScheme<G> + ?Sized,
{
  pub ck: PC::PolyCommitmentKey,
  pub vk: PC::EvalVerifierKey,
}

pub trait PolyCommitmentScheme<G: CurveGroup>: Send + Sync {
  type SRS: SRSTrait;
  type PolyCommitmentKey: CanonicalSerialize + CanonicalDeserialize + Clone;
  type EvalVerifierKey: CanonicalSerialize + CanonicalDeserialize + Clone;
  type Commitment: PolyCommitmentTrait<G>;
  // The commitments should be compatible with a homomorphic vector commitment valued in G
  type PolyCommitmentProof: Sync + CanonicalSerialize + CanonicalDeserialize + Debug;

  // Optionally takes `vector_comm` as a "hint" to speed up the commitment process if a
  // commitment to the vector of evaluations has already been computed
  fn commit(
    poly: &DensePolynomial<G::ScalarField>,
    ck: &Self::PolyCommitmentKey,
  ) -> Self::Commitment;

  fn prove(
    C: Option<&Self::Commitment>,
    poly: &DensePolynomial<G::ScalarField>,
    r: &[G::ScalarField],
    eval: &G::ScalarField,
    ck: &Self::PolyCommitmentKey,
    transcript: &mut Transcript,
  ) -> Self::PolyCommitmentProof;

  fn verify(
    commitment: &Self::Commitment,
    proof: &Self::PolyCommitmentProof,
    ck: &Self::EvalVerifierKey,
    transcript: &mut Transcript,
    r: &[G::ScalarField],
    eval: &G::ScalarField,
  ) -> Result<(), error::PCSError>;

  // Generate a SRS using the provided RNG; this is just for testing purposes, since in reality
  // we need to perform a trusted setup ceremony and then read the SRS from a file.
  fn setup(
    max_poly_vars: usize,
    label: &'static [u8],
    rng: &mut impl RngCore,
  ) -> Result<Self::SRS, Error>;

  fn trim(srs: &Self::SRS, supported_num_vars: usize) -> PCSKeys<G, Self>;
}

impl<G: CurveGroup, PC: PolyCommitmentScheme<G>> VectorCommitmentScheme<G> for PC {
  type VectorCommitment = PC::Commitment;
  type CommitmentKey = PC::PolyCommitmentKey;
  fn commit(vec: &[<G>::ScalarField], ck: &Self::CommitmentKey) -> Self::VectorCommitment {
    let poly = DensePolynomial::new(vec.to_vec());
    PC::commit(&poly, ck)
  }
  fn zero(n: usize) -> Self::VectorCommitment {
    PC::Commitment::zero(n)
  }
}
