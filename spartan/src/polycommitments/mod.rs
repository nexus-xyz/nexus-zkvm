use ark_ec::CurveGroup;
use ark_poly_commit::{
  PCCommitment, PCCommitterKey, PCRandomness, PCUniversalParams, PCVerifierKey,
};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::rand::RngCore;
use core::fmt::Debug;
use merlin::Transcript;

use crate::{
  dense_mlpoly::DensePolynomial, errors::ProofVerifyError, random::RandomTape,
  transcript::AppendToTranscript,
};

pub mod hyrax;
mod transcript_utils;
pub mod zeromorph;

pub trait CommitmentKeyTrait<G: CurveGroup> {
  fn setup(num_poly_vars: usize, label: &'static [u8]) -> Self;
  // fn size(&self) -> usize;
  // fn main_gens(&self) -> Vec<G>;
  // fn blind_gen(&self) -> G;
}

pub trait VectorCommitmentTrait<G: CurveGroup>:
  AppendToTranscript<G> + Sized + Sync + CanonicalSerialize + CanonicalDeserialize
{
  type CommitmentKey;
  type VCBlinds: PCRandomness;
  fn commit(
    vec: &[G::ScalarField],
    blinds: Option<&Self::VCBlinds>,
    ck: &Self::CommitmentKey,
    random_tape: &mut Option<RandomTape<G>>,
  ) -> Self;

  // Commitment to the zero vector of length n
  fn zero(n: usize) -> Self;
}

// trait SRSTrait {}
// trait PolyCommitmentKeyTrait {}

// trait EvalVerifierKeyTrait {}

// trait PCProofTrait {}

// trait PolyCommitmentTrait {}

pub trait PolyCommitmentScheme<G: CurveGroup> {
  type SRS;
  type PolyCommitmentKey;
  type EvalVerifierKey;
  type Commitment: Sized
    + AppendToTranscript<G>
    + Sync
    + Debug
    + CanonicalSerialize
    + CanonicalDeserialize
    + PartialEq;
  // The commitments should be compatible with a homomorphic vector commitment valued in G
  type VectorCommitment: VectorCommitmentTrait<G>;
  type Blinds: PCRandomness;
  type PolyCommitmentProof: Sync + CanonicalSerialize + CanonicalDeserialize + Debug;

  // Optionally takes `vector_comm` as a "hint" to speed up the commitment process if a
  // commitment to the vector of evaluations has already been computed
  fn commit(
    poly: &DensePolynomial<G::ScalarField>,
    ck: &Self::PolyCommitmentKey,
    vector_comm: Option<&Self::VectorCommitment>,
    vc_blinds: Option<&<Self::VectorCommitment as VectorCommitmentTrait<G>>::VCBlinds>,
    random_tape: &mut Option<RandomTape<G>>,
  ) -> (Self::Commitment, Option<Self::Blinds>);

  fn prove(
    poly: &DensePolynomial<G::ScalarField>,
    r: &[G::ScalarField],
    eval: &G::ScalarField,
    ck: &Self::PolyCommitmentKey,
    transcript: &mut Transcript,
    random_tape: &mut Option<RandomTape<G>>,
  ) -> Self::PolyCommitmentProof;

  #[allow(clippy::too_many_arguments)]
  fn prove_blinded(
    poly: &DensePolynomial<G::ScalarField>,
    r: &[G::ScalarField],
    eval: &G::ScalarField,
    ck: &Self::PolyCommitmentKey,
    transcript: &mut Transcript,
    random_tape: &mut Option<RandomTape<G>>,
    blinds: &Self::Blinds,
    blind_eval: &G::ScalarField,
  ) -> (Self::PolyCommitmentProof, G);

  fn verify(
    commitment: &Self::Commitment,
    proof: &Self::PolyCommitmentProof,
    ck: &Self::EvalVerifierKey,
    transcript: &mut Transcript,
    r: &[G::ScalarField],
    eval: &G::ScalarField,
  ) -> Result<(), ProofVerifyError>;

  fn verify_blinded(
    commitment: &Self::Commitment,
    proof: &Self::PolyCommitmentProof,
    ck: &Self::EvalVerifierKey,
    transcript: &mut Transcript,
    r: &[G::ScalarField],
    eval_commit: &G,
  ) -> Result<(), ProofVerifyError>;

  fn compatible_with_vector_commitment(
    commitment: &Self::Commitment,
    C: &Self::VectorCommitment,
  ) -> bool;

  // Generate a SRS using the provided RNG; this is just for testing purposes, since in reality
  // we need to perform a trusted setup ceremony and then read the SRS from a file.
  fn setup(max_poly_vars: usize, label: &'static [u8], rng: &mut impl RngCore) -> Self::SRS;

  //
  fn trim(
    srs: &Self::SRS,
    supported_degree: usize,
    supported_hiding_bound: usize,
    enforced_degree_bounds: Option<&[usize]>,
  ) -> (
    Self::PolyCommitmentKey,
    Self::EvalVerifierKey,
    <Self::VectorCommitment as VectorCommitmentTrait<G>>::CommitmentKey,
  );
}
