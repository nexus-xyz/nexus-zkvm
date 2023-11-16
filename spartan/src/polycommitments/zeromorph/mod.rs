use super::{CommitmentKeyTrait, PolyCommitmentScheme, VectorCommitmentTrait};
use crate::dense_mlpoly::DensePolynomial;
use crate::math::Math;
use crate::random::RandomTape;
use crate::transcript::{AppendToTranscript, ProofTranscript};
use ark_crypto_primitives::sponge::{Absorb, CryptographicSponge};
use ark_ec::CurveGroup;
use ark_ff::{Field, PrimeField, Zero};
use ark_poly::{DenseUVPolynomial, Polynomial};
use ark_poly_commit::challenge::ChallengeGenerator;
use ark_poly_commit::{
  LabeledCommitment, LabeledPolynomial, PCRandomness, PCUniversalParams,
  PolynomialCommitment as UnivarPCS,
};
use merlin::Transcript;
use transcript_utils::PolyCommitmentTranscript;
// use ark_poly_commit::{
//   PCCommitment as UnivarCommitment, PCCommitterKey as UnivarCommitmentKey, PCRandomness,
//   PCUniversalParams, PCVerifierKey};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{
  iter::Sum,
  ops::{Add, Mul, Sub},
  rand::RngCore,
  {marker::PhantomData, vec::Vec},
};
use std::fmt::Debug;

use super::transcript_utils;
mod algebra;
mod data_structures;

use algebra::*;

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
    self.comm.append_to_transcript(label, transcript);
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
#[derive(Debug, CanonicalSerialize, CanonicalDeserialize)]
struct ZeromorphProof<
  G: CurveGroup,
  P: DenseUVPolynomial<G::ScalarField>,
  U: UnivarPCS<G::ScalarField, P, PolyCommitmentTranscript>,
> where
  U::Commitment: Debug + CanonicalSerialize + CanonicalDeserialize,
  U::Proof: Debug + CanonicalSerialize + CanonicalDeserialize,
{
  proof: U::Proof,
  commitments: Vec<U::Commitment>,
}

impl<G, P, U> PolyCommitmentScheme<G> for Zeromorph<G, P, U>
where
  G: CurveGroup,
  P: DenseUVPolynomial<G::ScalarField> + Sum + Sub<P>,
  U: UnivarPCS<G::ScalarField, P, PolyCommitmentTranscript> + Debug,
  U::Commitment: PartialEq
    + AppendToTranscript<G>
    + Debug
    + CanonicalSerialize
    + CanonicalDeserialize
    + Mul<G::ScalarField, Output = U::Commitment>
    + Add<U::Commitment, Output = U::Commitment>
    + Sum
    + Sub<U::Commitment, Output = U::Commitment>,
  U::Proof: Debug + CanonicalSerialize + CanonicalDeserialize,
{
  type PolyCommitmentKey = U::CommitterKey;

  type EvalVerifierKey = U::VerifierKey;

  type Commitment = U::Commitment;

  type SRS = U::UniversalParams;

  type PolyCommitmentProof = ZeromorphProof<G, P, U>;

  fn commit(
    poly: &DensePolynomial<<G>::ScalarField>,
    ck: &Self::PolyCommitmentKey,
    random_tape: &mut Option<RandomTape<G>>,
  ) -> Self::Commitment {
    let uni_poly = multilinear_to_univar(poly.clone());
    let labeled_poly = LabeledPolynomial::new("poly".to_string(), uni_poly, None, None);
    let rt = random_tape.as_mut().map(|rt| rt as &mut dyn RngCore);
    let (labeled_commitment_vec, _blinds) = U::commit(ck, vec![&labeled_poly], rt).unwrap();
    labeled_commitment_vec[0].commitment().clone()
  }

  fn prove(
    poly: &DensePolynomial<<G>::ScalarField>,
    u: &[<G>::ScalarField],
    eval: &<G>::ScalarField,
    ck: &Self::PolyCommitmentKey,
    transcript: &mut Transcript,
    random_tape: &mut Option<RandomTape<G>>,
  ) -> Self::PolyCommitmentProof {
    <Transcript as ProofTranscript<G>>::append_protocol_name(transcript, b"Zeromorph_eval_proof");
    <Transcript as ProofTranscript<G>>::append_scalar(transcript, b"eval_claim", eval);
    <Transcript as ProofTranscript<G>>::append_scalars(transcript, b"eval_point", u);
    let uni_poly: P = multilinear_to_univar(poly.clone());
    let uni_poly_labeled =
      LabeledPolynomial::new("uni_poly".to_string(), uni_poly.clone(), None, None);
    let rt = random_tape.as_mut().map(|rt| rt as &mut dyn RngCore);
    let (_C, _) = U::commit(ck, vec![&uni_poly_labeled], rt).unwrap();
    let C = _C[0].commitment().clone();
    // First, we calculate the quotients 'q_k' in the identity (poly - eval) = sum_{k=0}^{n-1} (x_k - r_k) q_k,
    // where q_k is a multilinear polynomial in x_0, ..., x_{k-1}.
    let quotients = get_quotients(poly, u);
    let num_vars = poly.get_num_vars();
    assert_eq!(quotients.len(), poly.get_num_vars());

    // Now, we use the commitment interface for 'LabeledPolynomial's provided by U to commit to each of the quotients,
    // while also proving the corresponding degree bound.
    let labeled_quotients: Vec<_> = quotients
      .clone()
      .into_iter()
      .map(|q| multilinear_to_univar::<_, P>(q))
      .zip((0..num_vars).map(Math::pow2))
      .map(|(q, m)| LabeledPolynomial::new(format!("quotient {:}", m), q, Some(m), None))
      .collect();
    let labeled_quotients_refs = (0..labeled_quotients.len()).map(|k| &labeled_quotients[k]);
    let (commitments, _blinds) = U::commit(
      ck,
      labeled_quotients_refs,
      random_tape.as_mut().map(|rt| rt as &mut dyn RngCore),
    )
    .unwrap();

    // Next, we send each of these commitments to the verifier and extract a challenge
    commitments.clone().into_iter().for_each(|c| {
      <LabeledCommitment<U::Commitment> as AppendToTranscript<G>>::append_to_transcript(
        &c,
        b"quotients",
        transcript,
      )
    });

    let x = <Transcript as ProofTranscript<G>>::challenge_scalar(transcript, b"x");

    let cyclo_poly: P = univar_of_constant(x, num_vars);
    let labeled_cyclo_poly = LabeledPolynomial::new(
      format!("{}th cyclo_poly", num_vars),
      cyclo_poly.clone(),
      Some(num_vars.pow2() as usize),
      None,
    );
    let (labeled_C_vx, _blinds) = U::commit(ck, [&labeled_cyclo_poly], None).unwrap();
    let C_vx = labeled_C_vx[0].commitment().clone();

    let truncated_quotients: Vec<P> = quotients
      .into_iter()
      .zip(0..num_vars)
      .map(|(q, k)| truncate(multilinear_to_univar::<_, P>(q), Math::pow2(k)))
      .collect();
    let Z_x_0 = uni_poly
      .coeffs()
      .iter()
      .zip(cyclo_poly.coeffs().iter())
      .zip(
        (0..num_vars)
          .map(|k| scale(&truncated_quotients[k], get_Zx_coefficients(x, u)[k]))
          .sum::<P>()
          .coeffs()
          .iter(),
      )
      .map(|((a, b), c)| *a - *b - *c)
      .collect::<Vec<_>>();
    let Z_x = P::from_coefficients_vec(Z_x_0);
    let Z_x_labeled = LabeledPolynomial::new("Z_x".to_string(), Z_x, None, None);
    let C_Z_x_0: U::Commitment = C
      - C_vx
      - (commitments
        .clone()
        .into_iter()
        .zip(get_Zx_coefficients(x, u))
        .map(|(C, s)| C.commitment().clone() * s)
        .sum::<U::Commitment>());
    let C_Z_x = LabeledCommitment::new("C_Z_x".to_string(), C_Z_x_0, None);
    let rt = random_tape.as_mut().map(|rt| rt as &mut dyn RngCore);
    let mut pc_transcript = PolyCommitmentTranscript::from(transcript.clone());
    let mut challenge_generator = ChallengeGenerator::new_univariate(&mut pc_transcript);
    Self::PolyCommitmentProof {
      proof: U::open(
        ck,
        vec![&Z_x_labeled],
        vec![&C_Z_x],
        &x,
        &mut challenge_generator,
        vec![&U::Randomness::empty()],
        rt,
      )
      .unwrap(),
      commitments: commitments
        .into_iter()
        .map(|c| c.commitment().clone())
        .collect(),
    }
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

  fn setup(max_num_poly_vars: usize, label: &'static [u8], rng: &mut impl RngCore) -> Self::SRS {
    U::setup(max_num_poly_vars.pow2() as usize, None, rng).unwrap()
  }
  fn trim(
    srs: &Self::SRS,
    supported_degree: usize,
    supported_hiding_bound: usize,
    enforced_degree_bounds: Option<&[usize]>,
  ) -> (Self::PolyCommitmentKey, Self::EvalVerifierKey) {
    U::trim(
      srs,
      supported_degree,
      supported_hiding_bound,
      enforced_degree_bounds,
    )
    .unwrap()
  }
}
