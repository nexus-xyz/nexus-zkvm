use ark_ec::CurveGroup;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use core::fmt::Debug;
use merlin::Transcript;

use crate::{
  dense_mlpoly::DensePolynomial, errors::ProofVerifyError, random::RandomTape,
  transcript::AppendToTranscript,
};

pub trait CommitmentKeyTrait<G: CurveGroup> {
  fn setup(num_poly_vars: usize, label: &'static [u8]) -> Self;
  // fn size(&self) -> usize;
  // fn main_gens(&self) -> Vec<G>;
  // fn blind_gen(&self) -> G;
}
pub trait BlindsTrait<G: CurveGroup> {}

pub trait VectorCommitmentTrait<G: CurveGroup>:
  AppendToTranscript<G> + Sized + Sync + CanonicalSerialize + CanonicalDeserialize
{
  type CommitmentKey: CommitmentKeyTrait<G>;
  type VCBlinds;
  fn commit(
    vec: &[G::ScalarField],
    blinds: Option<&Self::VCBlinds>,
    ck: &Self::CommitmentKey,
    random_tape: &mut Option<RandomTape<G>>,
  ) -> Self;

  // Commitment to the zero vector of length n
  fn zero(n: usize) -> Self;
}

pub trait PolyCommitmentScheme<G: CurveGroup>:
  Sized + AppendToTranscript<G> + Sync + CanonicalSerialize + CanonicalDeserialize + Debug
{
  type PolyCommitmentKey: CommitmentKeyTrait<G>;
  // The commitments should be compatible with a homomorphic vector commitment valued in G
  type VectorCommitment: VectorCommitmentTrait<G>;
  type Blinds;
  type PolyCommitmentProof: Sync + CanonicalSerialize + CanonicalDeserialize + Debug;

  // Optionally takes `vector_comm` as a "hint" to speed up the commitment process if a
  // commitment to the vector of evaluations has already been computed
  fn commit(
    poly: &DensePolynomial<G::ScalarField>,
    ck: &Self::PolyCommitmentKey,
    vector_comm: Option<&Self::VectorCommitment>,
    vc_blinds: Option<&<Self::VectorCommitment as VectorCommitmentTrait<G>>::VCBlinds>,
    random_tape: &mut Option<RandomTape<G>>,
  ) -> (Self, Option<Self::Blinds>);

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
    &self,
    proof: &Self::PolyCommitmentProof,
    ck: &Self::PolyCommitmentKey,
    transcript: &mut Transcript,
    r: &[G::ScalarField],
    eval: &G::ScalarField,
  ) -> Result<(), ProofVerifyError>;

  fn verify_blinded(
    &self,
    proof: &Self::PolyCommitmentProof,
    ck: &Self::PolyCommitmentKey,
    transcript: &mut Transcript,
    r: &[G::ScalarField],
    eval_commit: &G,
  ) -> Result<(), ProofVerifyError>;

  fn compatible_with_vector_commitment(&self, C: &Self::VectorCommitment) -> bool;

  // These functions are combined because the SRS of the vector commitment scheme and
  // polynomial commitment scheme need to be compatible
  fn setup(
    num_poly_vars: usize,
    label: &'static [u8],
  ) -> (
    Self::PolyCommitmentKey,
    <Self::VectorCommitment as VectorCommitmentTrait<G>>::CommitmentKey,
  );
}
