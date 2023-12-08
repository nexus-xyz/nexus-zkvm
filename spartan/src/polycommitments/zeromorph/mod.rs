use ark_ec::{pairing::Pairing, scalar_mul::fixed_base::FixedBase, AffineRepr, CurveGroup};
use ark_ff::PrimeField;
use ark_poly::{univariate::DensePolynomial as DenseUnivarPolynomial, DenseUVPolynomial};
use ark_poly_commit::{
  error::Error,
  kzg10::{Commitment as KZGCommitment, KZG10},
  PCUniversalParams,
};
use ark_std::{
  collections::BTreeMap, end_timer, marker::PhantomData, ops::Mul, rand::RngCore, start_timer,
  vec::Vec, One, UniformRand, Zero,
};
use merlin::Transcript;

use super::super::timer::Timer;
use super::{PCSKeys, PolyCommitmentScheme};
use crate::{
  dense_mlpoly::DensePolynomial,
  math::Math,
  transcript::{AppendToTranscript, ProofTranscript},
};

mod algebra;
mod data_structures;
use super::error::PCSError;
use algebra::*;
use data_structures::*;

pub struct Zeromorph<E>
where
  E: Pairing,
{
  _phantom: PhantomData<E>,
}

impl<E> PolyCommitmentScheme<E::G1> for Zeromorph<E>
where
  E: Pairing,
{
  type PolyCommitmentKey = ZeromorphCommitterKey<E>;

  type EvalVerifierKey = ZeromorphVerifierKey<E>;

  type Commitment = ZeromorphCommitment<E>;

  type SRS = ZeromorphSRS<E>;

  type PolyCommitmentProof = ZeromorphProof<E>;

  fn commit(
    poly: &DensePolynomial<E::ScalarField>,
    ck: &Self::PolyCommitmentKey,
  ) -> Self::Commitment {
    let uni_poly: DenseUnivarPolynomial<E::ScalarField> = multilinear_to_univar(poly);
    let (commitment, _blinds) = KZG10::commit(&ck.powers(), &uni_poly, None, None).unwrap();
    ZeromorphCommitment { commitment }
  }

  fn prove(
    C: Option<&Self::Commitment>,
    poly: &DensePolynomial<E::ScalarField>,
    u: &[E::ScalarField],
    eval: &E::ScalarField,
    ck: &Self::PolyCommitmentKey,
    transcript: &mut Transcript,
  ) -> Self::PolyCommitmentProof {
    // First, we send the claimed evaluation, opening point, and commitment to the verifier.
    <Transcript as ProofTranscript<E::G1>>::append_protocol_name(
      transcript,
      b"Zeromorph_eval_proof",
    );
    <Transcript as ProofTranscript<E::G1>>::append_scalar(transcript, b"eval_claim", eval);
    <Transcript as ProofTranscript<E::G1>>::append_scalars(transcript, b"eval_point", u);

    // Skip committing to `poly` if it has been provided already as an argument.
    let C = match C {
      Some(C_ref) => *C_ref,
      None => {
        let timer_commit = Timer::new("commit to poly");
        let C = Zeromorph::<E>::commit(poly, ck);
        timer_commit.stop();
        C
      }
    };

    C.append_to_transcript(b"commitment", transcript);

    // Next, we calculate the quotients 'q_k' arising from the identity (poly - eval) = sum_{k=0}^{n-1} (x_k - r_k) q_k,
    // where q_k is a multilinear polynomial in x_0, ..., x_{k-1}. In the notation of the paper, `truncated_quotients[k]` is U_n(q_k)^{<2^k}.
    let timer_quotients = Timer::new("calculate_quotients");
    let truncated_quotients = get_truncated_quotients(poly, u);
    timer_quotients.stop();

    let num_vars = poly.get_num_vars();
    // Make sure that the SRS has been trimmed to support the number of variables in `poly`.
    assert_eq!(num_vars, ck.supported_num_vars());
    assert_eq!(truncated_quotients.len(), num_vars);

    // Now, we commit to these truncated quotients, send the commitments to the verifier, and extract a challenge.
    let timer_quotient_commitments = Timer::new("commit_to_quotients");
    let commitments: Vec<KZGCommitment<E>> = truncated_quotients
      .as_slice()
      .iter()
      .map(|q| KZG10::commit(&ck.powers(), q, None, None).unwrap().0)
      .collect();
    timer_quotient_commitments.stop();

    // Next, we send each of these commitments to the verifier and extract a challenge
    commitments
      .iter()
      .for_each(|c| c.append_to_transcript(b"quotients", transcript));
    let y = <Transcript as ProofTranscript<E::G1>>::challenge_scalar(transcript, b"y");

    // Next, using the challenge y, we calculate the batched shifted polynomial \sum_(k=0)^(n-1) y^k X^(2^n - 2^k) U_n(q_k)^{<2^k} and its commitment.
    let timer_shift = Timer::new("shift_and_combine_with_powers");
    let q_hat = shift_and_combine_with_powers(&truncated_quotients, y, num_vars);
    timer_shift.stop();

    let timer_shift_commitment = Timer::new("commit_to_shifted_polynomial");
    let (C_q_hat, _blinds) = KZG10::commit(&ck.powers(), &q_hat, None, None).unwrap();
    timer_shift_commitment.stop();

    // We send this commitment to the verifier and extract another two challenges.
    let timer_challenges = Timer::new("compute challenges");
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
    timer_challenges.stop();

    // Compute the polynomial Z_x = f(X) - v Phi_n(x) - \sum_{k=0}^{n-1} (x^{2^k}Phi_(n-k-1)(x^{2^{k+1}}) - u_k Phi_(n-k)(x^{2^k})) U_n(q_k)^{<2^k}(X)
    let timer_Zx = Timer::new("compute_Zx");
    let uni_poly = multilinear_to_univar(poly);
    let constant_term = *eval * eval_generalized_cyclotomic_polynomial(num_vars, 0, x);
    let Z_x = &(&uni_poly - &DenseUnivarPolynomial::from_coefficients_slice(&[constant_term]))
      - &truncated_quotients.iter().enumerate().fold(
        DenseUnivarPolynomial::from_coefficients_vec(vec![]),
        |sum, (k, q)| sum + q * get_Zx_coefficients(x, u)[k],
      );
    timer_Zx.stop();

    // Compute the polynomial zeta_x(X) = \sum_{k=0}^{n-1} y^k X^{2^n - 2^k} U_n(q_k)^{<2^k}(X) - \sum_{k=0}^{n-1} y^k x^{2^n - 2^k} U_n(q_k)^{<2^k}(X)
    let timer_zeta_x = Timer::new("compute_zeta_x");
    let zeta_x = &shift_and_combine_with_powers(&truncated_quotients, y, num_vars)
      - &truncated_quotients.iter().enumerate().fold(
        DenseUnivarPolynomial::from_coefficients_vec(vec![]),
        |sum, (k, q)| sum + q * get_zeta_x_coefficients(x, y, num_vars)[k],
      );
    timer_zeta_x.stop();

    // Compute the quotient polynomials q_zeta = zeta_x/(X-x) and q_Z = Z_x/(X-x)
    let timer_divide = Timer::new("poly_division");
    let q_Z = quotient_univar_by_linear_factor(&Z_x, x);
    let q_zeta = quotient_univar_by_linear_factor(&zeta_x, x);
    let q_zeta_Z = &q_zeta + &(&q_Z * z);
    timer_divide.stop();

    let timer_commit_q_zeta_Z = Timer::new("commit_to_q_zeta_Z");
    let (pi, _blinds) = KZG10::commit(&ck.shifted_powers(), &q_zeta_Z, None, None).unwrap();
    timer_commit_q_zeta_Z.stop();

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
    assert_eq!(num_vars, vk.supported_num_vars);
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
        c,
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
    let C_Z_x = commitment.commitment.0.into_group()
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
    // This is e(C_zeta_Z, [tau_h^(N_max - 2^num_vars + 1)]_2)
    let lhs = E::pairing(C_zeta_Z, vk.shifted_tau_h.into_group());
    let rhs = E::pairing(proof.0, vk.tau_h.into_group() - vk.h.mul(x));
    if lhs != rhs {
      Err(PCSError::EvalVerifierFailure)
    } else {
      Ok(())
    }
  }

  fn setup(
    max_num_poly_vars: usize,
    _label: &'static [u8],
    rng: &mut impl RngCore,
  ) -> Result<Self::SRS, Error> {
    {
      let max_degree = Math::pow2(max_num_poly_vars) - 1;
      if max_degree < 1 {
        return Err(Error::DegreeIsZero);
      }
      let setup_time = start_timer!(|| format!(
        "Zeromorph::Setup for max number of variables {}",
        max_num_poly_vars
      ));
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

      let powers_of_h_time = start_timer!(|| "Generating powers of h in G2");
      let shift_powers_of_tau_h = {
        let mut shift_powers_of_beta = vec![powers_of_beta[max_degree] * beta];
        for n in 1..=max_num_poly_vars {
          // powers_of_beta[k] = beta^k and N_max = max_degree + 1; we want shift_powers_of_beta[n] = beta^(N_max - 2^n + 1)
          shift_powers_of_beta.push(powers_of_beta[max_degree + 1 - Math::pow2(n) + 1]);
        }
        let window_size = FixedBase::get_mul_window_size(max_num_poly_vars + 1);
        let h_table = FixedBase::get_window_table(scalar_bits, window_size, h);
        let powers_of_h =
          FixedBase::msm::<E::G2>(scalar_bits, window_size, &h_table, &shift_powers_of_beta);

        let affines = E::G2::normalize_batch(&powers_of_h);
        let mut affines_map = BTreeMap::new();
        affines.into_iter().enumerate().for_each(|(i, a)| {
          affines_map.insert(i, a);
        });
        affines_map
      };

      end_timer!(powers_of_h_time);

      let h = h.into_affine();

      let pp = ZeromorphSRS {
        max_num_vars: max_num_poly_vars,
        powers_of_tau_g: powers_of_g,
        h,
        shift_powers_of_tau_h,
      };
      end_timer!(setup_time);
      Ok(pp)
    }
  }
  fn trim(srs: &Self::SRS, supported_num_vars: usize) -> PCSKeys<E::G1, Self> {
    let max_degree = srs.max_degree();
    let supported_degree = Math::pow2(supported_num_vars) - 1;
    if supported_degree > max_degree {
      panic!("Unsupported degree");
    }
    let powers_of_tau_g = srs.powers_of_tau_g[..=supported_degree].to_vec();
    let shifted_powers_of_tau_g =
      srs.powers_of_tau_g[(max_degree - supported_degree + 1)..].to_vec();
    let ck = ZeromorphCommitterKey {
      powers_of_tau_g,
      shifted_powers_of_tau_g,
      num_vars: supported_num_vars,
      N_max: max_degree,
    };
    println!("{}", srs.shift_powers_of_tau_h.len());
    let vk = ZeromorphVerifierKey {
      supported_num_vars,
      g: srs.powers_of_tau_g[0],
      h: srs.h,
      tau_h: srs.shift_powers_of_tau_h[&(srs.shift_powers_of_tau_h.len() - 1)],
      shifted_tau_h: srs.shift_powers_of_tau_h[&supported_num_vars],
    };
    PCSKeys { ck, vk }
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  use crate::{math::Math, random::RandomTape};
  use ark_bls12_381::Bls12_381;
  use ark_ec::pairing::Pairing;
  use ark_std::test_rng;
  fn end_to_end_test_helper<E: Pairing>() {
    let mut rng = test_rng();
    let SRS = Zeromorph::<E>::setup(9, b"test", &mut rng).unwrap();
    for n in 1..10 {
      let PCSKeys { ck, vk } = Zeromorph::<E>::trim(&SRS, n);
      let mut rt = RandomTape::<E::G1>::new(b"test");
      let evals = rt.random_vector(b"evals", Math::pow2(n));
      let poly = DensePolynomial::<E::ScalarField>::new(evals);
      let commitment = Zeromorph::<E>::commit(&poly, &ck);
      let u: Vec<E::ScalarField> = rt.random_vector(b"eval_point", n);
      let eval = poly.evaluate::<E::G1>(u.as_slice());
      let mut transcript_prover = Transcript::new(b"test");
      let mut transcript_verifier = Transcript::new(b"test");
      let proof_correct = Zeromorph::<E>::prove(
        Some(&commitment),
        &poly,
        &u,
        &eval,
        &ck,
        &mut transcript_prover,
      );
      Zeromorph::<E>::verify(
        &commitment,
        &proof_correct,
        &vk,
        &mut transcript_verifier,
        &u,
        &eval,
      )
      .unwrap_or_else(|e| {
        panic!(
          "Error verifying proof of correct statement with n = {}: {:?}",
          n, e
        )
      });
      let wrong_eval = E::ScalarField::rand(&mut rng);
      let proof_wrong = Zeromorph::<E>::prove(
        Some(&commitment),
        &poly,
        &u,
        &wrong_eval,
        &ck,
        &mut transcript_prover,
      );
      Zeromorph::<E>::verify(
        &commitment,
        &proof_wrong,
        &vk,
        &mut transcript_verifier,
        &u,
        &eval,
      )
      .expect_err(format!("Verifier accepts proof of wrong statement with n = {}", n).as_str());
    }
  }
  #[test]
  fn end_to_end_test() {
    end_to_end_test_helper::<Bls12_381>();
  }
}
