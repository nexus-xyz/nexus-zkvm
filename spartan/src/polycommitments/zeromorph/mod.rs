use super::PolyCommitmentScheme;
use crate::dense_mlpoly::DensePolynomial;
use crate::math::Math;
use crate::random::RandomTape;
use crate::transcript::{AppendToTranscript, ProofTranscript};
use ark_ec::{pairing::Pairing, scalar_mul::fixed_base::FixedBase, AffineRepr, CurveGroup};
use ark_ff::PrimeField;
use ark_poly::{univariate::DensePolynomial as DenseUnivarPolynomial, DenseUVPolynomial};
use ark_poly_commit::{
  error::Error,
  kzg10::{
    Commitment as KZGCommitment, Powers, Randomness as KZG10Randomness, UniversalParams,
    VerifierKey as KZGVerifierKey, KZG10,
  },
  PCRandomness, PCUniversalParams,
};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{
  collections::BTreeMap, end_timer, marker::PhantomData, ops::Mul, rand::RngCore, start_timer,
  vec::Vec, One, UniformRand, Zero,
};
use merlin::Transcript;
use std::fmt::Debug;

mod algebra;
mod data_structures;
use super::error::PCSError;
use algebra::*;

struct Zeromorph<E>
where
  E: Pairing,
{
  _phantom: PhantomData<E>,
}

#[derive(Debug, CanonicalSerialize, CanonicalDeserialize)]
struct ZeromorphProof<E>
where
  E: Pairing,
{
  proof: KZGCommitment<E>,
  quotient_commitments: Vec<KZGCommitment<E>>,
  combined_shifted_commitment: KZGCommitment<E>,
}

impl<E> PolyCommitmentScheme<E::G1> for Zeromorph<E>
where
  E: Pairing,
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
    let uni_poly: DenseUnivarPolynomial<E::ScalarField> = multilinear_to_univar(&poly);
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

    // First, we calculate the commitment to `poly` and send it to the verifier.
    let C = <Self as PolyCommitmentScheme<E::G1>>::commit(poly, ck, random_tape);
    C.append_to_transcript(b"commitment", transcript);

    // First, we calculate the quotients 'q_k' arising from the identity (poly - eval) = sum_{k=0}^{n-1} (x_k - r_k) q_k,
    // where q_k is a multilinear polynomial in x_0, ..., x_{k-1}. In the notation of the paper, `truncated_quotients[k]` is U_n(q_k)^{<2^k}.
    let truncated_quotients = get_truncated_quotients(poly, u);
    let num_vars = poly.get_num_vars();
    assert_eq!(truncated_quotients.len(), num_vars);

    // Now, we commit to these truncated quotients, send the commitments to the verifier, and extract a challenge.
    let commitments: Vec<KZGCommitment<E>> = truncated_quotients
      .as_slice()
      .iter()
      .map(|q| KZG10::commit(ck, q, None, None).unwrap().0)
      .collect();
    // Next, we send each of these commitments to the verifier and extract a challenge
    commitments.iter().for_each(|c| {
      <KZGCommitment<E> as AppendToTranscript<E::G1>>::append_to_transcript(
        &c,
        b"quotients",
        transcript,
      )
    });
    let y = <Transcript as ProofTranscript<E::G1>>::challenge_scalar(transcript, b"y");

    // Next, using the challenge y, we calculate the batched shifted polynomial \sum_(k=0)^(n-1) y^k X^(2^n - 2^k) U_n(q_k)^{<2^k} and its commitment.
    let q_hat = shift_and_combine_with_powers(&truncated_quotients, y, num_vars);
    let (C_q_hat, _blinds) = KZG10::commit(ck, &q_hat, None, None).unwrap();

    // We send this commitment to the verifier and extract another two challenges.
    C_q_hat.append_to_transcript(b"C_q_hat", transcript);
    let x = <Transcript as ProofTranscript<E::G1>>::challenge_scalar(transcript, b"x");
    let z: E::ScalarField =
      <Transcript as ProofTranscript<E::G1>>::challenge_scalar(transcript, b"z");

    // x will be zero with with vanishingly low probability, but as we need x to be nonzero for correctness, we include this check for completeness.
    let mut j = 0;
    let mut x0 = x;
    while x == E::ScalarField::zero() {
      let label: &'static [u8] = Box::leak(format!("x.{}", j).into_boxed_str()).as_bytes();

      x0 = <Transcript as ProofTranscript<E::G1>>::challenge_scalar(transcript, label);
      j += 1;
    }
    let x = x0;

    // Compute the polynomial Z_x = f(X) - v Phi_n(x) - \sum_{k=0}^{n-1} (x^{2^k}Phi_(n-k-1)(x^{2^{k+1}}) - u_k Phi_(n-k)(x^{2^k})) U_n(q_k)^{<2^k}(X)
    let uni_poly = multilinear_to_univar(&poly);
    let constant_term = *eval * eval_generalized_cyclotomic_polynomial(num_vars, 0, x);
    let Z_x = &(&uni_poly - &DenseUnivarPolynomial::from_coefficients_slice(&[constant_term]))
      - &truncated_quotients.iter().enumerate().fold(
        DenseUnivarPolynomial::from_coefficients_vec(vec![]),
        |sum, (k, q)| sum + q * get_Zx_coefficients(x, u)[k],
      );
    // Compute the polynomial zeta_x(X) = \sum_{k=0}^{n-1} y^k X^{2^n - 2^k} U_n(q_k)^{<2^k}(X) - \sum_{k=0}^{n-1} y^k x^{2^n - 2^k} U_n(q_k)^{<2^k}(X)
    let zeta_x = &shift_and_combine_with_powers(&truncated_quotients, y, num_vars)
      - &truncated_quotients.iter().enumerate().fold(
        DenseUnivarPolynomial::from_coefficients_vec(vec![]),
        |sum, (k, q)| sum + q * get_zeta_x_coefficients(x, y, num_vars)[k],
      );

    // Compute the quotient polynomials q_zeta = zeta_x/(X-x) and q_Z = Z_x/(X-x)
    let q_Z = KZG10::<E, DenseUnivarPolynomial<E::ScalarField>>::compute_witness_polynomial(
      &Z_x,
      x,
      &KZG10Randomness::empty(),
    )
    .unwrap()
    .0;
    let q_zeta = KZG10::<E, DenseUnivarPolynomial<E::ScalarField>>::compute_witness_polynomial(
      &zeta_x,
      x,
      &KZG10Randomness::empty(),
    )
    .unwrap()
    .0;
    let q_zeta_Z = &q_zeta + &(&q_Z * z);
    // Unlike the paper, we do not shift q_zeta_Z here: we assume that the number of polynomial variables in the polynomial `poly` is the max supported by the SRS.
    let (pi, _blinds) = KZG10::commit(ck, &q_zeta_Z, None, None).unwrap();
    ZeromorphProof {
      quotient_commitments: commitments,
      combined_shifted_commitment: C_q_hat,
      proof: pi,
    }
  }
  fn verify(
    commitment: &Self::Commitment,
    proof: &Self::PolyCommitmentProof,
    vk: &Self::EvalVerifierKey,
    transcript: &mut Transcript,
    u: &[E::ScalarField],
    eval: &E::ScalarField,
  ) -> Result<(), PCSError> {
    let ZeromorphProof {
      quotient_commitments,
      combined_shifted_commitment,
      proof,
    } = proof;
    let num_vars = u.len();
    // We absorb the public inputs into the transcript
    <Transcript as ProofTranscript<E::G1>>::append_protocol_name(
      transcript,
      b"Zeromorph_eval_proof",
    );
    <Transcript as ProofTranscript<E::G1>>::append_scalar(transcript, b"eval_claim", eval);
    <Transcript as ProofTranscript<E::G1>>::append_scalars(transcript, b"eval_point", u);
    commitment.append_to_transcript(b"commitment", transcript);

    // Next, we absorb the quotient commitments and extract a challenge
    quotient_commitments.iter().for_each(|c| {
      <KZGCommitment<E> as AppendToTranscript<E::G1>>::append_to_transcript(
        &c,
        b"quotients",
        transcript,
      )
    });
    let y = <Transcript as ProofTranscript<E::G1>>::challenge_scalar(transcript, b"y");

    // Next, we absorb the combined shifted commitment and extract two challenges
    combined_shifted_commitment.append_to_transcript(b"C_q_hat", transcript);

    let x = <Transcript as ProofTranscript<E::G1>>::challenge_scalar(transcript, b"x");
    let z: E::ScalarField =
      <Transcript as ProofTranscript<E::G1>>::challenge_scalar(transcript, b"z");
    // x will be zero with with vanishingly low probability, but as we need x to be nonzero for correctness, we include this check for completeness.
    let mut j = 0;
    let mut x0 = x;
    while x == E::ScalarField::zero() {
      let label: &'static [u8] = Box::leak(format!("x.{}", j).into_boxed_str()).as_bytes();

      x0 = <Transcript as ProofTranscript<E::G1>>::challenge_scalar(transcript, label);
      j += 1;
    }
    let x = x0;

    // Compute the commitment to the constant term U_n(`eval`) = `eval` * Phi_n(x); `eval` is called `v` in the paper.
    let v_phi_x = *eval * eval_generalized_cyclotomic_polynomial(num_vars, 0, x);
    let C_vx = &vk.g.mul(v_phi_x);

    // Compute the commitment to the combined polynomial Z_x.
    let C_Z_x = commitment.0.into_group()
      - (C_vx)
      - quotient_commitments
        .iter()
        .enumerate()
        .fold(E::G1Affine::zero(), |sum, (k, q)| {
          (sum + q.0.into_group() * get_Zx_coefficients(x, u)[k]).into()
        });

    // Comptue the commimtment to the batched shifted polynomial zeta_x.
    let C_zeta_x = combined_shifted_commitment.0.into_group()
      - quotient_commitments
        .iter()
        .enumerate()
        .fold(E::G1Affine::zero(), |sum, (k, q)| {
          (sum + q.0.into_group() * get_zeta_x_coefficients(x, y, num_vars)[k]).into()
        });

    let C_zeta_Z = C_zeta_x + C_Z_x * z;
    let lhs = E::pairing(C_zeta_Z, vk.h);
    let rhs = E::pairing(proof.0, vk.beta_h.into_group() - vk.h.mul(x));
    if lhs != rhs {
      return Err(PCSError::EvalVerifierFailure);
    } else {
      Ok(())
    }
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
    supported_num_vars: usize,
    _supported_hiding_bound: usize,
    _enforced_degree_bounds: Option<&[usize]>,
  ) -> (Self::PolyCommitmentKey<'a>, Self::EvalVerifierKey) {
    let mut supported_degree = Math::pow2(supported_num_vars) - 1;
    if supported_degree > srs.max_degree() {
      panic!("Unsupported degree");
    } else if supported_degree == 1 {
      supported_degree += 1;
    }
    let powers_of_g = srs.powers_of_g[..=supported_degree].to_vec();
    let powers_of_gamma_g = (0..=supported_degree)
      .map(|i| srs.powers_of_gamma_g[&i])
      .collect();
    let powers = Powers {
      powers_of_g: ark_std::borrow::Cow::Owned(powers_of_g),
      powers_of_gamma_g: ark_std::borrow::Cow::Owned(powers_of_gamma_g),
    };
    let vk = KZGVerifierKey {
      g: srs.powers_of_g[0],
      gamma_g: srs.powers_of_gamma_g[&0],
      h: srs.h,
      beta_h: srs.beta_h,
      prepared_h: srs.prepared_h.clone(),
      prepared_beta_h: srs.prepared_beta_h.clone(),
    };
    (powers, vk)
  }
}
