use ark_ec::CurveGroup;
use ark_ff::PrimeField;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use merlin::Transcript;

pub use crate::dense_mlpoly::{
  PolyCommitment as HyraxCommitment, PolyCommitmentBlinds as HyraxBlinds,
  PolyCommitmentGens as HyraxKey, PolyEvalProof as HyraxProof,
};

use crate::{
  dense_mlpoly::DensePolynomial,
  errors::ProofVerifyError,
  polycommitments::{CommitmentKeyTrait, PolyCommitmentScheme, VectorCommitmentTrait},
  random::RandomTape,
  transcript::{AppendToTranscript, ProofTranscript},
};

#[derive(CanonicalSerialize, CanonicalDeserialize, Debug, PartialEq, Eq)]
pub struct HyraxVectorCommitment<G: CurveGroup> {
  comm: Vec<G>,
}

impl<G: CurveGroup> AppendToTranscript<G> for HyraxVectorCommitment<G> {
  fn append_to_transcript(&self, label: &'static [u8], transcript: &mut Transcript) {
    transcript.append_message(label, b"hyrax_vector_commitment_begin");
    for i in 0..self.comm.len() {
      transcript.append_point(b"hyrax_vector_commitment_share", &self.comm[i]);
    }
    transcript.append_message(label, b"hyrax_vector_commitment_end");
  }
}

// impl<G: CurveGroup> CommitmentKeyTrait<G> for MultiCommitGens<G> {
//   fn setup(num_poly_vars: usize, label: &'static [u8]) -> Self {
//     MultiCommitGens::setup(num_poly_vars, label)
//   }
// }

impl<G: CurveGroup> VectorCommitmentTrait<G> for HyraxVectorCommitment<G> {
  type CommitmentKey = HyraxKey<G>;
  type VCBlinds = Vec<G::ScalarField>;
  // We implement the HyraxVectorCommitment directly as the HyraxCommitment of the MLE of the vector.
  fn commit(
    vec: &[G::ScalarField],
    _blinds: Option<&Self::VCBlinds>,
    ck: &Self::CommitmentKey,
    random_tape: &mut Option<RandomTape<G>>,
  ) -> Self {
    let poly_vec = DensePolynomial::new(vec.to_vec());
    let (poly_comm, _) = <HyraxCommitment<G> as PolyCommitmentScheme<G>>::commit(
      &poly_vec,
      ck,
      None,
      None,
      random_tape,
    );
    Self { comm: poly_comm.C }
  }

  fn zero(n: usize) -> Self {
    Self {
      comm: vec![G::zero(); n],
    }
  }
}

impl<G: CurveGroup> CommitmentKeyTrait<G> for HyraxKey<G> {
  fn setup(num_poly_vars: usize, label: &'static [u8]) -> Self {
    HyraxKey::new(num_poly_vars, label)
  }
}

impl<F: PrimeField> HyraxBlinds<F> {
  fn from_vec(vec: Vec<F>) -> Self {
    Self { blinds: vec }
  }
}

impl<G: CurveGroup> PolyCommitmentScheme<G> for HyraxCommitment<G> {
  type PolyCommitmentKey = HyraxKey<G>;
  type VectorCommitment = HyraxVectorCommitment<G>;

  type Blinds = HyraxBlinds<G::ScalarField>;

  type PolyCommitmentProof = HyraxProof<G>;

  fn commit(
    poly: &DensePolynomial<G::ScalarField>,
    ck: &Self::PolyCommitmentKey,
    vector_comm: Option<&Self::VectorCommitment>,
    vc_blinds: Option<&<Self::VectorCommitment as VectorCommitmentTrait<G>>::VCBlinds>,
    random_tape: &mut Option<RandomTape<G>>,
  ) -> (Self, Option<Self::Blinds>) {
    if let Some(vc) = vector_comm {
      let comm = HyraxCommitment {
        C: (*vc.comm).to_vec(),
      };
      debug_assert!(comm.compatible_with_vector_commitment(vc));
      let blinds = vc_blinds.map(|vcb| HyraxBlinds::from_vec((*vcb).clone()));
      (comm, blinds)
    } else {
      let (comm, blinds) = poly.commit(ck, random_tape.into());
      (comm, Some(blinds))
    }
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
    let (proof, _) = HyraxProof::prove(poly, None, r, eval, None, ck, transcript, random_tape);
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
    ck: &Self::PolyCommitmentKey,
    transcript: &mut Transcript,
    r: &[<G>::ScalarField],
    eval: &<G>::ScalarField,
  ) -> Result<(), ProofVerifyError> {
    proof.verify_plain(ck, transcript, r, eval, self)
  }

  fn verify_blinded(
    &self,
    proof: &Self::PolyCommitmentProof,
    ck: &Self::PolyCommitmentKey,
    transcript: &mut Transcript,
    r: &[<G>::ScalarField],
    eval_commit: &G,
  ) -> Result<(), ProofVerifyError> {
    proof.verify(ck, transcript, r, eval_commit, self)
  }

  fn compatible_with_vector_commitment(&self, C: &Self::VectorCommitment) -> bool {
    C.comm == self.C
  }

  fn setup(
    num_poly_vars: usize,
    label: &'static [u8],
  ) -> (
    Self::PolyCommitmentKey,
    <Self::VectorCommitment as VectorCommitmentTrait<G>>::CommitmentKey,
  ) {
    let gens_pc = HyraxKey::new(num_poly_vars, label);
    let gens_vc = gens_pc.clone();
    (gens_pc, gens_vc)
  }
}
