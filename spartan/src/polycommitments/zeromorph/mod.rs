use super::{CommitmentKeyTrait, PolyCommitmentScheme, VectorCommitmentTrait};
use crate::dense_mlpoly::DensePolynomial;
use crate::math::Math;
use crate::random::RandomTape;
use crate::transcript::{AppendToTranscript, ProofTranscript};
use ark_crypto_primitives::sponge::{Absorb, CryptographicSponge};
use ark_ec::{
  pairing::Pairing, scalar_mul::fixed_base::FixedBase, AffineRepr, CurveGroup, VariableBaseMSM,
};
use ark_ff::{Field, PrimeField};
use ark_poly::{DenseUVPolynomial, Polynomial};
use ark_poly_commit::{
  challenge::ChallengeGenerator,
  error::Error,
  kzg10::{
    Commitment as KZGCommitment, Powers, Proof as KZGProof, UniversalParams,
    VerifierKey as KZGVerifierKey, KZG10,
  },
  LabeledCommitment, LabeledPolynomial, PCRandomness, PCUniversalParams,
  PolynomialCommitment as UnivarPCS,
};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{
  collections::BTreeMap,
  end_timer,
  iter::Sum,
  marker::PhantomData,
  ops::{Add, Div, Mul, Sub},
  rand::RngCore,
  start_timer,
  vec::Vec,
  One, UniformRand, Zero,
};
use merlin::Transcript;
use std::fmt::Debug;
use transcript_utils::PolyCommitmentTranscript;

use super::transcript_utils;
mod algebra;
mod data_structures;

use algebra::*;

// impl<U: UnivarCommitment, G: CurveGroup> AppendToTranscript<E::G1> for U {
//   fn append_to_transcript(&self, label: &'static [u8], transcript: &mut Transcript) {
//     transcript.append_message(label, b"univar_commitment_begin");
//     transcript.append_message(b"univar_commitment_params", &self.params);
//     transcript.append_point(b"univar_commitment_commitment", &self.comm);
//     transcript.append_message(b"univar_commitment_end", b"univar_commitment_end");
//   }
// }

struct Zeromorph<E, P>
where
  E: Pairing,
  P: DenseUVPolynomial<E::ScalarField>,
{
  _phantom: PhantomData<E>,
  _phantom2: PhantomData<P>,
}

#[derive(Debug, CanonicalSerialize, CanonicalDeserialize)]
struct ZeromorphProof<E>
where
  E: Pairing,
{
  proof: KZGProof<E>,
  commitments: Vec<KZGCommitment<E>>,
}

impl<E, P> PolyCommitmentScheme<E::G1> for Zeromorph<E, P>
where
  E: Pairing,
  P: DenseUVPolynomial<E::ScalarField>,
  for<'a, 'b> &'a P: Div<&'b P, Output = P>,
{
  type PolyCommitmentKey<'a> = Powers<'a, E>;

  type EvalVerifierKey = KZGVerifierKey<E>;

  type Commitment = KZGCommitment<E>;

  type SRS = UniversalParams<E>;

  type PolyCommitmentProof = ZeromorphProof<E>;

  fn commit<'a>(
    poly: &DensePolynomial<E::ScalarField>,
    ck: &Self::PolyCommitmentKey<'a>,
    random_tape: &mut Option<RandomTape<E::G1>>,
  ) -> Self::Commitment {
    let uni_poly: P = multilinear_to_univar(poly.clone());
    let rt = random_tape.as_mut().map(|rt| rt as &mut dyn RngCore);
    let (commitment, _blinds) = KZG10::commit(ck, &uni_poly, None, rt).unwrap();
    commitment
  }

  fn prove<'a>(
    poly: &DensePolynomial<E::ScalarField>,
    u: &[E::ScalarField],
    eval: &E::ScalarField,
    ck: &Self::PolyCommitmentKey<'a>,
    transcript: &mut Transcript,
    random_tape: &mut Option<RandomTape<E::G1>>,
  ) -> Self::PolyCommitmentProof {
    <Transcript as ProofTranscript<E::G1>>::append_protocol_name(
      transcript,
      b"Zeromorph_eval_proof",
    );
    <Transcript as ProofTranscript<E::G1>>::append_scalar(transcript, b"eval_claim", eval);
    <Transcript as ProofTranscript<E::G1>>::append_scalars(transcript, b"eval_point", u);
    //    let uni_poly: P = multilinear_to_univar(poly.clone());
    //    let rt = random_tape.as_mut().map(|rt| rt as &mut dyn RngCore);
    //    let (C, _blinds) = KZG10::commit(ck, &uni_poly, None, rt).unwrap();
    // First, we calculate the quotients 'q_k' in the identity (poly - eval) = sum_{k=0}^{n-1} (x_k - r_k) q_k,
    // where q_k is a multilinear polynomial in x_0, ..., x_{k-1}.
    let truncated_quotients: Vec<P> = get_truncated_quotients(poly, u);
    let num_vars = poly.get_num_vars();
    assert_eq!(truncated_quotients.len(), num_vars);
    //
    //    // Now, we use the commitment interface for 'LabeledPolynomial's provided by U to commit to each of the quotients,
    //    // while also proving the corresponding degree bound.
    //    let labeled_quotients: Vec<_> = quotients
    //      .clone()
    //      .into_iter()
    //      .map(|q| multilinear_to_univar::<_, P>(q))
    //      .zip((0..num_vars).map(Math::pow2))
    //      .map(|(q, m)| LabeledPolynomial::new(format!("quotient {:}", m), q, Some(m), None))
    //      .collect();
    //    let labeled_quotients_refs = (0..labeled_quotients.len()).map(|k| &labeled_quotients[k]);
    //    let (commitments, _blinds) = KZG10::batch_commit(
    //      ck,
    //      labeled_quotients_refs,
    //      random_tape.as_mut().map(|rt| rt as &mut dyn RngCore),
    //    )
    //    .unwrap();
    //
    //    // Next, we send each of these commitments to the verifier and extract a challenge
    //    commitments.clone().into_iter().for_each(|c| {
    //      <LabeledCommitment<U::Commitment> as AppendToTranscript<E::G1>>::append_to_transcript(
    //        &c,
    //        b"quotients",
    //        transcript,
    //      )
    //    });
    //
    //    let x = <Transcript as ProofTranscript<E::G1>>::challenge_scalar(transcript, b"x");
    //
    //    let cyclo_poly: P = univar_of_constant(x, num_vars);
    //    let labeled_cyclo_poly = LabeledPolynomial::new(
    //      format!("{}th cyclo_poly", num_vars),
    //      cyclo_poly.clone(),
    //      Some(num_vars.pow2() as usize),
    //      None,
    //    );
    //    let (labeled_C_vx, _blinds) = U::commit(ck, [&labeled_cyclo_poly], None).unwrap();
    //    let C_vx = labeled_C_vx[0].commitment().clone();
    //
    //    let truncated_quotients: Vec<P> = quotients
    //      .into_iter()
    //      .zip(0..num_vars)
    //      .map(|(q, k)| truncate(multilinear_to_univar::<_, P>(q), Math::pow2(k)))
    //      .collect();
    //    let Z_x_0 = uni_poly
    //      .coeffs()
    //      .iter()
    //      .zip(cyclo_poly.coeffs().iter())
    //      .zip(
    //        (0..num_vars)
    //          .map(|k| scale(&truncated_quotients[k], get_Zx_coefficients(x, u)[k]))
    //          .sum::<P>()
    //          .coeffs()
    //          .iter(),
    //      )
    //      .map(|((a, b), c)| *a - *b - *c)
    //      .collect::<Vec<_>>();
    //    let Z_x = P::from_coefficients_vec(Z_x_0);
    //    let Z_x_labeled = LabeledPolynomial::new("Z_x".to_string(), Z_x, None, None);
    //    let C_Z_x_0: U::Commitment = C
    //      - C_vx
    //      - (commitments
    //        .clone()
    //        .into_iter()
    //        .zip(get_Zx_coefficients(x, u))
    //        .map(|(C, s)| C.commitment().clone() * s)
    //        .sum::<U::Commitment>());
    //    let C_Z_x = LabeledCommitment::new("C_Z_x".to_string(), C_Z_x_0, None);
    //    let rt = random_tape.as_mut().map(|rt| rt as &mut dyn RngCore);
    //    let mut pc_transcript = PolyCommitmentTranscript::from(transcript.clone());
    //    let mut challenge_generator = ChallengeGenerator::new_univariate(&mut pc_transcript);
    //    Self::PolyCommitmentProof {
    //      proof: U::open(
    //        ck,
    //        vec![&Z_x_labeled],
    //        vec![&C_Z_x],
    //        &x,
    //        &mut challenge_generator,
    //        vec![&U::Randomness::empty()],
    //        rt,
    //      )
    //      .unwrap(),
    //      commitments: commitments
    //        .into_iter()
    //        .map(|c| c.commitment().clone())
    //        .collect(),
    //    }
    Self::PolyCommitmentProof {
      proof: KZGProof {
        w: E::G1Affine::zero(),
        random_v: None,
      },
      commitments: vec![],
    }
  }
  fn verify(
    commitment: &Self::Commitment,
    proof: &Self::PolyCommitmentProof,
    ck: &Self::EvalVerifierKey,
    transcript: &mut Transcript,
    r: &[E::ScalarField],
    eval: &E::ScalarField,
  ) -> Result<(), crate::errors::ProofVerifyError> {
    todo!()
  }

  fn setup(
    max_num_poly_vars: usize,
    label: &'static [u8],
    rng: &mut impl RngCore,
  ) -> Result<Self::SRS, Error> {
    {
      let max_degree = Math::pow2(max_num_poly_vars);
      if max_degree < 1 {
        return Err(Error::DegreeIsZero);
      }
      let setup_time = start_timer!(|| format!("KZG10::Setup with degree {}", max_degree));
      let beta = E::ScalarField::rand(rng);
      let g = E::G1::rand(rng);
      let gamma_g = E::G1::rand(rng);
      let h = E::G2::rand(rng);
      let mut powers_of_beta = vec![E::ScalarField::one()];

      let mut cur = beta;
      for _ in 0..max_degree {
        powers_of_beta.push(cur);
        cur *= &beta;
      }

      let window_size = FixedBase::get_mul_window_size(max_degree + 1);

      let scalar_bits = E::ScalarField::MODULUS_BIT_SIZE as usize;
      let g_time = start_timer!(|| "Generating powers of G");
      let g_table = FixedBase::get_window_table(scalar_bits, window_size, g);
      let powers_of_g =
        FixedBase::msm::<E::G1>(scalar_bits, window_size, &g_table, &powers_of_beta);
      end_timer!(g_time);
      let gamma_g_time = start_timer!(|| "Generating powers of gamma * G");
      let gamma_g_table = FixedBase::get_window_table(scalar_bits, window_size, gamma_g);
      let mut powers_of_gamma_g =
        FixedBase::msm::<E::G1>(scalar_bits, window_size, &gamma_g_table, &powers_of_beta);
      // Add an additional power of gamma_g, because we want to be able to support
      // up to D queries.
      powers_of_gamma_g.push(powers_of_gamma_g.last().unwrap().mul(&beta));
      end_timer!(gamma_g_time);

      let powers_of_g = E::G1::normalize_batch(&powers_of_g);
      let powers_of_gamma_g = E::G1::normalize_batch(&powers_of_gamma_g)
        .into_iter()
        .enumerate()
        .collect();

      let powers_of_h_time = start_timer!(|| "Generating powers of h in G2");
      let powers_of_h = {
        let mut powers_of_beta = vec![E::ScalarField::one()];
        let mut cur = E::ScalarField::one() / &beta;
        for _ in 0..max_degree {
          powers_of_beta.push(cur);
          cur *= &beta;
        }

        let h_table = FixedBase::get_window_table(scalar_bits, window_size, h);
        let powers_of_h =
          FixedBase::msm::<E::G2>(scalar_bits, window_size, &h_table, &powers_of_beta);

        let affines = E::G2::normalize_batch(&powers_of_h);
        let mut affines_map = BTreeMap::new();
        affines.into_iter().enumerate().for_each(|(i, a)| {
          affines_map.insert(i, a);
        });
        affines_map
      };

      end_timer!(powers_of_h_time);

      let h = h.into_affine();
      let beta_h = h.mul(beta).into_affine();
      let prepared_h = h.into();
      let prepared_beta_h = beta_h.into();

      let pp = UniversalParams {
        powers_of_g,
        powers_of_gamma_g,
        h,
        beta_h,
        neg_powers_of_h: powers_of_h,
        prepared_h,
        prepared_beta_h,
      };
      end_timer!(setup_time);
      Ok(pp)
    }
  }
  fn trim<'a>(
    srs: &Self::SRS,
    supported_degree: usize,
    supported_hiding_bound: usize,
    enforced_degree_bounds: Option<&[usize]>,
  ) -> (Self::PolyCommitmentKey<'a>, Self::EvalVerifierKey) {
    todo!()
    //KZG10::trim(
    //  srs,
    //  supported_degree,
    //  supported_hiding_bound,
    //  enforced_degree_bounds,
    //)
    //.unwrap()
  }
}
