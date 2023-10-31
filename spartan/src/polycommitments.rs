use ark_ec::CurveGroup;
use merlin::Transcript;

use crate::{
  commitments::{Commitments, MultiCommitGens},
  dense_mlpoly::DensePolynomial,
  random::RandomTape,
};

pub use crate::dense_mlpoly::{
  PolyCommitment as HyraxCommitment, PolyCommitmentBlinds as HyraxBlinds,
  PolyCommitmentGens as HyraxKey, PolyEvalProof as HyraxProof,
};

pub trait CommitmentKeyTrait<G: CurveGroup> {
  // fn setup(n: usize, label: &'static [u8]) -> Self;
  // fn size(&self) -> usize;
  // fn main_gens(&self) -> Vec<G>;
  // fn blind_gen(&self) -> G;
}
pub trait BlindsTrait<G: CurveGroup> {}

pub trait VectorCommitmentTrait<G: CurveGroup> {
  type CommitmentKey: CommitmentKeyTrait<G>;
  fn commit(vec: &[G::ScalarField], blind: &G::ScalarField, ck: Self::CommitmentKey) -> Self;
}

pub trait PolyCommitmentScheme<G: CurveGroup>: Sized {
  type PolyCommitmentKey: CommitmentKeyTrait<G>;
  // The commitments should be compatible with a homomorphic vector commitment valued in G
  type VectorCommitment: VectorCommitmentTrait<G>;
  type Blinds;
  type PolyCommitmentProof;

  fn commit(
    poly: &DensePolynomial<G>,
    ck: &Self::PolyCommitmentKey,
    random_tape: Option<&mut RandomTape<G>>,
  ) -> (Self, Option<Self::Blinds>);

  fn prove(
    poly: &DensePolynomial<G>,
    r: &[G::ScalarField],
    eval: &G::ScalarField,
    ck: &Self::PolyCommitmentKey,
    transcript: &mut Transcript,
    random_tape: Option<&mut RandomTape<G>>,
  ) -> Self::PolyCommitmentProof;

  fn prove_blinded(
    &self,
    poly: &DensePolynomial<G>,
    r: &[G::ScalarField],
    eval: &G::ScalarField,
    ck: &Self::PolyCommitmentKey,
    transcript: &mut Transcript,
    random_tape: Option<&mut RandomTape<G>>,
    blinds: &Self::Blinds,
    blind_eval: &G::ScalarField,
  ) -> (Self::PolyCommitmentProof, Self::VectorCommitment);

  fn verify(
    &self,
    proof: &Self::PolyCommitmentProof,
    r: &[G::ScalarField],
    eval: &G::ScalarField,
    ck: &Self::PolyCommitmentKey,
    transcript: &mut Transcript,
  );

  fn verify_blinded(
    &self,
    proof: &Self::PolyCommitmentProof,
    r: &[G::ScalarField],
    eval_commit: &Self::VectorCommitment,
    ck: &Self::PolyCommitmentKey,
    transcript: &mut Transcript,
  );

  fn compatible_with_vector_commitment(&self, C: Self::VectorCommitment) -> bool;
}

impl<G: CurveGroup> CommitmentKeyTrait<G> for HyraxKey<G> {}

impl<G: CurveGroup> BlindsTrait<G> for HyraxBlinds<G> {}

impl<G: CurveGroup> PolyCommitmentScheme<G> for HyraxCommitment<G> {
  type PolyCommitmentKey = HyraxKey<G>;
  type VectorCommitment = Vec<G>;

  type Blinds = HyraxBlinds<G>;

  type PolyCommitmentProof = HyraxProof<G>;

  fn commit(
    poly: &DensePolynomial<G>,
    ck: &Self::PolyCommitmentKey,
    random_tape: Option<&mut RandomTape<G>>,
  ) -> (Self, Option<Self::Blinds>) {
    poly.commit(ck, random_tape)
  }

  fn prove(
    poly: &DensePolynomial<G>,
    r: &[<G>::ScalarField],
    eval: &<G>::ScalarField,
    ck: &Self::PolyCommitmentKey,
    transcript: &mut Transcript,
    random_tape: Option<&mut RandomTape<G>>,
  ) -> Self::PolyCommitmentProof {
    HyraxProof::prove(poly, None, r, eval, None, ck, transcript, random_tape)
  }

  fn prove_blinded(
    &self,
    poly: &DensePolynomial<G>,
    r: &[<G>::ScalarField],
    eval: &<G>::ScalarField,
    ck: &Self::PolyCommitmentKey,
    transcript: &mut Transcript,
    random_tape: Option<&mut RandomTape<G>>,
    blinds: &Self::Blinds,
    blind_eval: &<G>::ScalarField,
  ) -> (Self::PolyCommitmentProof, Self::VectorCommitment) {
    HyraxProof::prove(
      poly,
      Some(blinds),
      r,
      eval,
      Some(blind_eval),
      ck,
      transcript,
      random_tape,
    )
  }

  fn verify(
    &self,
    proof: &Self::PolyCommitmentProof,
    r: &[<G>::ScalarField],
    eval: &<G>::ScalarField,
    ck: &Self::PolyCommitmentKey,
    transcript: &mut Transcript,
  ) {
    proof.verify_plain(ck, transcript, r, eval, &self)
  }

  fn verify_blinded(
    &self,
    proof: &Self::PolyCommitmentProof,
    r: &[<G>::ScalarField],
    eval_commit: &Self::VectorCommitment,
    ck: &Self::PolyCommitmentKey,
    transcript: &mut Transcript,
  ) {
    proof.verify(ck, transcript, r, eval_commit, &self)
  }

  fn compatible_with_vector_commitment(&self, C: Self::VectorCommitment) -> bool {
    C == self.C
  }
}
