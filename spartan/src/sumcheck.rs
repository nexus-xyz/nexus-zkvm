#![allow(clippy::too_many_arguments)]
#![allow(clippy::type_complexity)]
use super::commitments::{Commitments, MultiCommitGens};
use super::dense_mlpoly::DensePolynomial;
use super::errors::ProofVerifyError;
use super::nizk::DotProductProof;
use super::random::RandomTape;
use super::transcript::{AppendToTranscript, ProofTranscript};
use super::unipoly::{CompressedUniPoly, UniPoly};
use ark_ec::CurveGroup;
use ark_ec::VariableBaseMSM;
use ark_ff::PrimeField;
use ark_serialize::*;
use ark_std::{One, Zero};

use itertools::izip;
use merlin::Transcript;

#[derive(CanonicalSerialize, CanonicalDeserialize, Debug)]
pub struct SumcheckInstanceProof<F: PrimeField> {
  compressed_polys: Vec<CompressedUniPoly<F>>,
}

impl<F: PrimeField> SumcheckInstanceProof<F> {
  pub fn new(compressed_polys: Vec<CompressedUniPoly<F>>) -> SumcheckInstanceProof<F> {
    SumcheckInstanceProof { compressed_polys }
  }

  pub fn verify<G>(
    &self,
    claim: F,
    num_rounds: usize,
    degree_bound: usize,
    transcript: &mut Transcript,
  ) -> Result<(F, Vec<F>), ProofVerifyError>
  where
    G: CurveGroup<ScalarField = F>,
  {
    let mut e = claim;
    let mut r: Vec<F> = Vec::new();

    // verify that there is a univariate polynomial for each round
    assert_eq!(self.compressed_polys.len(), num_rounds);
    for i in 0..self.compressed_polys.len() {
      let poly = self.compressed_polys[i].decompress(&e);

      // verify degree bound
      assert_eq!(poly.degree(), degree_bound);

      // check if G_k(0) + G_k(1) = e
      assert_eq!(poly.eval_at_zero() + poly.eval_at_one(), e);

      // append the prover's message to the transcript
      <UniPoly<F> as AppendToTranscript<G>>::append_to_transcript(&poly, b"poly", transcript);

      //derive the verifier's challenge for the next round
      let r_i =
        <Transcript as ProofTranscript<G>>::challenge_scalar(transcript, b"challenge_nextround");

      r.push(r_i);

      // evaluate the claimed degree-ell polynomial at r_i
      e = poly.evaluate(&r_i);
    }

    Ok((e, r))
  }
}

#[derive(CanonicalSerialize, CanonicalDeserialize, Debug)]
pub struct ZKSumcheckInstanceProof<G: CurveGroup> {
  comm_polys: Vec<G>,
  comm_evals: Vec<G>,
  proofs: Vec<DotProductProof<G>>,
}

impl<G: CurveGroup> ZKSumcheckInstanceProof<G> {
  pub fn new(comm_polys: Vec<G>, comm_evals: Vec<G>, proofs: Vec<DotProductProof<G>>) -> Self {
    ZKSumcheckInstanceProof {
      comm_polys,
      comm_evals,
      proofs,
    }
  }

  pub fn verify(
    &self,
    comm_claim: &G,
    num_rounds: usize,
    degree_bound: usize,
    gens_1: &MultiCommitGens<G>,
    gens_n: &MultiCommitGens<G>,
    transcript: &mut Transcript,
  ) -> Result<(G, Vec<G::ScalarField>), ProofVerifyError> {
    // verify degree bound
    assert_eq!(gens_n.n, degree_bound + 1);

    // verify that there is a univariate polynomial for each round
    assert_eq!(self.comm_polys.len(), num_rounds);
    assert_eq!(self.comm_evals.len(), num_rounds);

    let mut r: Vec<G::ScalarField> = Vec::new();
    for i in 0..self.comm_polys.len() {
      let comm_poly = &self.comm_polys[i];

      // append the prover's polynomial to the transcript
      <Transcript as ProofTranscript<G>>::append_point(transcript, b"comm_poly", comm_poly);

      //derive the verifier's challenge for the next round
      let r_i =
        <Transcript as ProofTranscript<G>>::challenge_scalar(transcript, b"challenge_nextround");

      // verify the proof of sum-check and evals
      let res = {
        let comm_claim_per_round = if i == 0 {
          comm_claim
        } else {
          &self.comm_evals[i - 1]
        };
        let comm_eval = &self.comm_evals[i];

        // add two claims to transcript
        <Transcript as ProofTranscript<G>>::append_point(
          transcript,
          b"comm_claim_per_round",
          comm_claim_per_round,
        );
        <Transcript as ProofTranscript<G>>::append_point(transcript, b"comm_eval", comm_eval);

        // produce two weights
        let w = <Transcript as ProofTranscript<G>>::challenge_vector(
          transcript,
          b"combine_two_claims_to_one",
          2,
        );

        // compute a weighted sum of the RHS
        let bases = vec![comm_claim_per_round.into_affine(), comm_eval.into_affine()];

        let comm_target = VariableBaseMSM::msm(bases.as_ref(), w.as_ref()).unwrap();

        let a = {
          // the vector to use to decommit for sum-check test
          let a_sc = {
            let mut a = vec![G::ScalarField::one(); degree_bound + 1];
            a[0] += G::ScalarField::one();
            a
          };

          // the vector to use to decommit for evaluation
          let a_eval = {
            let mut a = vec![G::ScalarField::one(); degree_bound + 1];
            for j in 1..a.len() {
              a[j] = a[j - 1] * r_i;
            }
            a
          };

          // take weighted sum of the two vectors using w
          assert_eq!(a_sc.len(), a_eval.len());
          (0..a_sc.len())
            .map(|i| w[0] * a_sc[i] + w[1] * a_eval[i])
            .collect::<Vec<G::ScalarField>>()
        };

        self.proofs[i]
          .verify(
            gens_1,
            gens_n,
            transcript,
            &a,
            &self.comm_polys[i],
            &comm_target,
          )
          .is_ok()
      };
      if !res {
        return Err(ProofVerifyError::InternalError);
      }

      r.push(r_i);
    }

    Ok((self.comm_evals[self.comm_evals.len() - 1], r))
  }
}

impl<F: PrimeField> SumcheckInstanceProof<F> {
  pub fn prove_cubic<Func, G>(
    claim: &F,
    num_rounds: usize,
    poly_A: &mut DensePolynomial<F>,
    poly_B: &mut DensePolynomial<F>,
    poly_C: &mut DensePolynomial<F>,
    comb_func: Func,
    transcript: &mut Transcript,
  ) -> (Self, Vec<F>, Vec<F>)
  where
    Func: Fn(&F, &F, &F) -> F,
    G: CurveGroup<ScalarField = F>,
  {
    let mut e = *claim;
    let mut r: Vec<F> = Vec::new();
    let mut cubic_polys: Vec<CompressedUniPoly<F>> = Vec::new();
    for _j in 0..num_rounds {
      let mut eval_point_0 = F::zero();
      let mut eval_point_2 = F::zero();
      let mut eval_point_3 = F::zero();

      let len = poly_A.len() / 2;
      for i in 0..len {
        // eval 0: bound_func is A(low)
        eval_point_0 += comb_func(&poly_A[i], &poly_B[i], &poly_C[i]);

        // eval 2: bound_func is -A(low) + 2*A(high)
        let poly_A_bound_point = poly_A[len + i] + poly_A[len + i] - poly_A[i];
        let poly_B_bound_point = poly_B[len + i] + poly_B[len + i] - poly_B[i];
        let poly_C_bound_point = poly_C[len + i] + poly_C[len + i] - poly_C[i];
        eval_point_2 += comb_func(
          &poly_A_bound_point,
          &poly_B_bound_point,
          &poly_C_bound_point,
        );

        // eval 3: bound_func is -2A(low) + 3A(high); computed incrementally with bound_func applied to eval(2)
        let poly_A_bound_point = poly_A_bound_point + poly_A[len + i] - poly_A[i];
        let poly_B_bound_point = poly_B_bound_point + poly_B[len + i] - poly_B[i];
        let poly_C_bound_point = poly_C_bound_point + poly_C[len + i] - poly_C[i];

        eval_point_3 += comb_func(
          &poly_A_bound_point,
          &poly_B_bound_point,
          &poly_C_bound_point,
        );
      }

      let evals = vec![eval_point_0, e - eval_point_0, eval_point_2, eval_point_3];
      let poly = UniPoly::from_evals(&evals);

      // append the prover's message to the transcript
      <UniPoly<F> as AppendToTranscript<G>>::append_to_transcript(&poly, b"poly", transcript);

      //derive the verifier's challenge for the next round
      let r_j =
        <Transcript as ProofTranscript<G>>::challenge_scalar(transcript, b"challenge_nextround");

      r.push(r_j);
      // bound all tables to the verifier's challenge
      poly_A.bound_poly_var_top(&r_j);
      poly_B.bound_poly_var_top(&r_j);
      poly_C.bound_poly_var_top(&r_j);
      e = poly.evaluate(&r_j);
      cubic_polys.push(poly.compress());
    }

    (
      SumcheckInstanceProof::new(cubic_polys),
      r,
      vec![poly_A[0], poly_B[0], poly_C[0]],
    )
  }

  pub fn prove_cubic_batched<Func, G>(
    claim: &F,
    num_rounds: usize,
    poly_vec_par: (
      &mut Vec<&mut DensePolynomial<F>>,
      &mut Vec<&mut DensePolynomial<F>>,
      &mut DensePolynomial<F>,
    ),
    poly_vec_seq: (
      &mut Vec<&mut DensePolynomial<F>>,
      &mut Vec<&mut DensePolynomial<F>>,
      &mut Vec<&mut DensePolynomial<F>>,
    ),
    coeffs: &[F],
    comb_func: Func,
    transcript: &mut Transcript,
  ) -> (Self, Vec<F>, (Vec<F>, Vec<F>, F), (Vec<F>, Vec<F>, Vec<F>))
  where
    Func: Fn(&F, &F, &F) -> F,
    G: CurveGroup<ScalarField = F>,
  {
    let (poly_A_vec_par, poly_B_vec_par, poly_C_par) = poly_vec_par;
    let (poly_A_vec_seq, poly_B_vec_seq, poly_C_vec_seq) = poly_vec_seq;

    //let (poly_A_vec_seq, poly_B_vec_seq, poly_C_vec_seq) = poly_vec_seq;
    let mut e = *claim;
    let mut r: Vec<F> = Vec::new();
    let mut cubic_polys: Vec<CompressedUniPoly<F>> = Vec::new();

    for _j in 0..num_rounds {
      let mut evals: Vec<(F, F, F)> = Vec::new();

      for (poly_A, poly_B) in poly_A_vec_par.iter().zip(poly_B_vec_par.iter()) {
        let mut eval_point_0 = F::zero();
        let mut eval_point_2 = F::zero();
        let mut eval_point_3 = F::zero();

        let len = poly_A.len() / 2;
        for i in 0..len {
          // eval 0: bound_func is A(low)
          eval_point_0 += comb_func(&poly_A[i], &poly_B[i], &poly_C_par[i]);

          // eval 2: bound_func is -A(low) + 2*A(high)
          let poly_A_bound_point = poly_A[len + i] + poly_A[len + i] - poly_A[i];
          let poly_B_bound_point = poly_B[len + i] + poly_B[len + i] - poly_B[i];
          let poly_C_bound_point = poly_C_par[len + i] + poly_C_par[len + i] - poly_C_par[i];
          eval_point_2 += comb_func(
            &poly_A_bound_point,
            &poly_B_bound_point,
            &poly_C_bound_point,
          );

          // eval 3: bound_func is -2A(low) + 3A(high); computed incrementally with bound_func applied to eval(2)
          let poly_A_bound_point = poly_A_bound_point + poly_A[len + i] - poly_A[i];
          let poly_B_bound_point = poly_B_bound_point + poly_B[len + i] - poly_B[i];
          let poly_C_bound_point = poly_C_bound_point + poly_C_par[len + i] - poly_C_par[i];

          eval_point_3 += comb_func(
            &poly_A_bound_point,
            &poly_B_bound_point,
            &poly_C_bound_point,
          );
        }

        evals.push((eval_point_0, eval_point_2, eval_point_3));
      }

      for (poly_A, poly_B, poly_C) in izip!(
        poly_A_vec_seq.iter(),
        poly_B_vec_seq.iter(),
        poly_C_vec_seq.iter()
      ) {
        let mut eval_point_0 = F::zero();
        let mut eval_point_2 = F::zero();
        let mut eval_point_3 = F::zero();
        let len = poly_A.len() / 2;
        for i in 0..len {
          // eval 0: bound_func is A(low)
          eval_point_0 += comb_func(&poly_A[i], &poly_B[i], &poly_C[i]);
          // eval 2: bound_func is -A(low) + 2*A(high)
          let poly_A_bound_point = poly_A[len + i] + poly_A[len + i] - poly_A[i];
          let poly_B_bound_point = poly_B[len + i] + poly_B[len + i] - poly_B[i];
          let poly_C_bound_point = poly_C[len + i] + poly_C[len + i] - poly_C[i];
          eval_point_2 += comb_func(
            &poly_A_bound_point,
            &poly_B_bound_point,
            &poly_C_bound_point,
          );
          // eval 3: bound_func is -2A(low) + 3A(high); computed incrementally with bound_func applied to eval(2)
          let poly_A_bound_point = poly_A_bound_point + poly_A[len + i] - poly_A[i];
          let poly_B_bound_point = poly_B_bound_point + poly_B[len + i] - poly_B[i];
          let poly_C_bound_point = poly_C_bound_point + poly_C[len + i] - poly_C[i];
          eval_point_3 += comb_func(
            &poly_A_bound_point,
            &poly_B_bound_point,
            &poly_C_bound_point,
          );
        }
        evals.push((eval_point_0, eval_point_2, eval_point_3));
      }

      let evals_combined_0 = (0..evals.len()).map(|i| evals[i].0 * coeffs[i]).sum();
      let evals_combined_2 = (0..evals.len()).map(|i| evals[i].1 * coeffs[i]).sum();
      let evals_combined_3 = (0..evals.len()).map(|i| evals[i].2 * coeffs[i]).sum();

      let evals = vec![
        evals_combined_0,
        e - evals_combined_0,
        evals_combined_2,
        evals_combined_3,
      ];
      let poly = UniPoly::from_evals(&evals);

      // append the prover's message to the transcript
      <UniPoly<F> as AppendToTranscript<G>>::append_to_transcript(&poly, b"poly", transcript);

      //derive the verifier's challenge for the next round
      let r_j =
        <Transcript as ProofTranscript<G>>::challenge_scalar(transcript, b"challenge_nextround");
      r.push(r_j);

      // bound all tables to the verifier's challenge
      for (poly_A, poly_B) in poly_A_vec_par.iter_mut().zip(poly_B_vec_par.iter_mut()) {
        poly_A.bound_poly_var_top(&r_j);
        poly_B.bound_poly_var_top(&r_j);
      }
      poly_C_par.bound_poly_var_top(&r_j);

      for (poly_A, poly_B, poly_C) in izip!(
        poly_A_vec_seq.iter_mut(),
        poly_B_vec_seq.iter_mut(),
        poly_C_vec_seq.iter_mut()
      ) {
        poly_A.bound_poly_var_top(&r_j);
        poly_B.bound_poly_var_top(&r_j);
        poly_C.bound_poly_var_top(&r_j);
      }

      e = poly.evaluate(&r_j);
      cubic_polys.push(poly.compress());
    }

    let poly_A_par_final = (0..poly_A_vec_par.len())
      .map(|i| poly_A_vec_par[i][0])
      .collect();
    let poly_B_par_final = (0..poly_B_vec_par.len())
      .map(|i| poly_B_vec_par[i][0])
      .collect();
    let claims_prod = (poly_A_par_final, poly_B_par_final, poly_C_par[0]);

    let poly_A_seq_final = (0..poly_A_vec_seq.len())
      .map(|i| poly_A_vec_seq[i][0])
      .collect();
    let poly_B_seq_final = (0..poly_B_vec_seq.len())
      .map(|i| poly_B_vec_seq[i][0])
      .collect();
    let poly_C_seq_final = (0..poly_C_vec_seq.len())
      .map(|i| poly_C_vec_seq[i][0])
      .collect();
    let claims_dotp = (poly_A_seq_final, poly_B_seq_final, poly_C_seq_final);

    (
      SumcheckInstanceProof::new(cubic_polys),
      r,
      claims_prod,
      claims_dotp,
    )
  }
}

impl<G: CurveGroup> ZKSumcheckInstanceProof<G> {
  pub fn prove_quad<Func>(
    claim: &G::ScalarField,
    blind_claim: &G::ScalarField,
    num_rounds: usize,
    poly_A: &mut DensePolynomial<G::ScalarField>,
    poly_B: &mut DensePolynomial<G::ScalarField>,
    comb_func: Func,
    gens_1: &MultiCommitGens<G>,
    gens_n: &MultiCommitGens<G>,
    transcript: &mut Transcript,
    random_tape: &mut RandomTape<G>,
  ) -> (
    Self,
    Vec<G::ScalarField>,
    Vec<G::ScalarField>,
    G::ScalarField,
  )
  where
    Func: Fn(&G::ScalarField, &G::ScalarField) -> G::ScalarField,
  {
    let (blinds_poly, blinds_evals) = (
      random_tape.random_vector(b"blinds_poly", num_rounds),
      random_tape.random_vector(b"blinds_evals", num_rounds),
    );
    let mut claim_per_round = *claim;
    let mut comm_claim_per_round = claim_per_round.commit(blind_claim, gens_1);

    let mut r: Vec<G::ScalarField> = Vec::new();
    let mut comm_polys: Vec<G> = Vec::new();
    let mut comm_evals: Vec<G> = Vec::new();
    let mut proofs: Vec<DotProductProof<G>> = Vec::new();

    for j in 0..num_rounds {
      let (poly, comm_poly) = {
        let mut eval_point_0 = G::ScalarField::zero();
        let mut eval_point_2 = G::ScalarField::zero();

        let len = poly_A.len() / 2;
        for i in 0..len {
          // eval 0: bound_func is A(low)
          eval_point_0 += comb_func(&poly_A[i], &poly_B[i]);

          // eval 2: bound_func is -A(low) + 2*A(high)
          let poly_A_bound_point = poly_A[len + i] + poly_A[len + i] - poly_A[i];
          let poly_B_bound_point = poly_B[len + i] + poly_B[len + i] - poly_B[i];
          eval_point_2 += comb_func(&poly_A_bound_point, &poly_B_bound_point);
        }

        let evals = vec![eval_point_0, claim_per_round - eval_point_0, eval_point_2];
        let poly = UniPoly::from_evals(&evals);
        let comm_poly = poly.commit(gens_n, &blinds_poly[j]);
        (poly, comm_poly)
      };

      // append the prover's message to the transcript
      <Transcript as ProofTranscript<G>>::append_point(transcript, b"comm_poly", &comm_poly);
      comm_polys.push(comm_poly);

      //derive the verifier's challenge for the next round
      let r_j =
        <Transcript as ProofTranscript<G>>::challenge_scalar(transcript, b"challenge_nextround");

      // bound all tables to the verifier's challenge
      poly_A.bound_poly_var_top(&r_j);
      poly_B.bound_poly_var_top(&r_j);

      // produce a proof of sum-check and of evaluation
      let (proof, claim_next_round, comm_claim_next_round) = {
        let eval = poly.evaluate(&r_j);
        let comm_eval = eval.commit(&blinds_evals[j], gens_1);

        // we need to prove the following under homomorphic commitments:
        // (1) poly(0) + poly(1) = claim_per_round
        // (2) poly(r_j) = eval

        // Our technique is to leverage dot product proofs:
        // (1) we can prove: <poly_in_coeffs_form, (2, 1, 1, 1)> = claim_per_round
        // (2) we can prove: <poly_in_coeffs_form, (1, r_j, r^2_j, ..) = eval
        // for efficiency we batch them using random weights

        // add two claims to transcript
        <Transcript as ProofTranscript<G>>::append_point(
          transcript,
          b"comm_claim_per_round",
          &comm_claim_per_round,
        );
        <Transcript as ProofTranscript<G>>::append_point(transcript, b"comm_eval", &comm_eval);

        // produce two weights
        let w = <Transcript as ProofTranscript<G>>::challenge_vector(
          transcript,
          b"combine_two_claims_to_one",
          2,
        );

        // compute a weighted sum of the RHS
        let target = w[0] * claim_per_round + w[1] * eval;

        let bases = vec![comm_claim_per_round.into_affine(), comm_eval.into_affine()];
        let comm_target = VariableBaseMSM::msm(bases.as_ref(), w.as_ref()).unwrap();

        let blind = {
          let blind_sc = if j == 0 {
            blind_claim
          } else {
            &blinds_evals[j - 1]
          };

          let blind_eval = &blinds_evals[j];

          w[0] * blind_sc + w[1] * blind_eval
        };
        assert_eq!(target.commit(&blind, gens_1), comm_target);

        let a = {
          // the vector to use to decommit for sum-check test
          let a_sc = {
            let mut a = vec![G::ScalarField::one(); poly.degree() + 1];
            a[0] += G::ScalarField::one();
            a
          };

          // the vector to use to decommit for evaluation
          let a_eval = {
            let mut a = vec![G::ScalarField::one(); poly.degree() + 1];
            for j in 1..a.len() {
              a[j] = a[j - 1] * r_j;
            }
            a
          };

          // take weighted sum of the two vectors using w
          assert_eq!(a_sc.len(), a_eval.len());
          (0..a_sc.len())
            .map(|i| w[0] * a_sc[i] + w[1] * a_eval[i])
            .collect::<Vec<G::ScalarField>>()
        };

        let (proof, _comm_poly, _comm_sc_eval) = DotProductProof::prove(
          gens_1,
          gens_n,
          transcript,
          random_tape,
          &poly.as_vec(),
          &blinds_poly[j],
          &a,
          &target,
          &blind,
        );

        (proof, eval, comm_eval)
      };

      claim_per_round = claim_next_round;
      comm_claim_per_round = comm_claim_next_round;

      proofs.push(proof);
      r.push(r_j);
      comm_evals.push(comm_claim_per_round);
    }

    (
      ZKSumcheckInstanceProof::new(comm_polys, comm_evals, proofs),
      r,
      vec![poly_A[0], poly_B[0]],
      blinds_evals[num_rounds - 1],
    )
  }

  pub fn prove_cubic_with_additive_term<Func>(
    claim: &G::ScalarField,
    blind_claim: &G::ScalarField,
    num_rounds: usize,
    poly_A: &mut DensePolynomial<G::ScalarField>,
    poly_B: &mut DensePolynomial<G::ScalarField>,
    poly_C: &mut DensePolynomial<G::ScalarField>,
    poly_D: &mut DensePolynomial<G::ScalarField>,
    comb_func: Func,
    gens_1: &MultiCommitGens<G>,
    gens_n: &MultiCommitGens<G>,
    transcript: &mut Transcript,
    random_tape: &mut RandomTape<G>,
  ) -> (
    Self,
    Vec<G::ScalarField>,
    Vec<G::ScalarField>,
    G::ScalarField,
  )
  where
    Func: Fn(&G::ScalarField, &G::ScalarField, &G::ScalarField, &G::ScalarField) -> G::ScalarField,
  {
    let (blinds_poly, blinds_evals) = (
      random_tape.random_vector(b"blinds_poly", num_rounds),
      random_tape.random_vector(b"blinds_evals", num_rounds),
    );

    let mut claim_per_round = *claim;
    let mut comm_claim_per_round = claim_per_round.commit(blind_claim, gens_1);

    let mut r: Vec<G::ScalarField> = Vec::new();
    let mut comm_polys: Vec<G> = Vec::new();
    let mut comm_evals: Vec<G> = Vec::new();
    let mut proofs: Vec<DotProductProof<G>> = Vec::new();

    for j in 0..num_rounds {
      let (poly, comm_poly) = {
        let mut eval_point_0 = G::ScalarField::zero();
        let mut eval_point_2 = G::ScalarField::zero();
        let mut eval_point_3 = G::ScalarField::zero();

        let len = poly_A.len() / 2;
        for i in 0..len {
          // eval 0: bound_func is A(low)
          eval_point_0 += comb_func(&poly_A[i], &poly_B[i], &poly_C[i], &poly_D[i]);

          // eval 2: bound_func is -A(low) + 2*A(high)
          let poly_A_bound_point = poly_A[len + i] + poly_A[len + i] - poly_A[i];
          let poly_B_bound_point = poly_B[len + i] + poly_B[len + i] - poly_B[i];
          let poly_C_bound_point = poly_C[len + i] + poly_C[len + i] - poly_C[i];
          let poly_D_bound_point = poly_D[len + i] + poly_D[len + i] - poly_D[i];
          eval_point_2 += comb_func(
            &poly_A_bound_point,
            &poly_B_bound_point,
            &poly_C_bound_point,
            &poly_D_bound_point,
          );

          // eval 3: bound_func is -2A(low) + 3A(high); computed incrementally with bound_func applied to eval(2)
          let poly_A_bound_point = poly_A_bound_point + poly_A[len + i] - poly_A[i];
          let poly_B_bound_point = poly_B_bound_point + poly_B[len + i] - poly_B[i];
          let poly_C_bound_point = poly_C_bound_point + poly_C[len + i] - poly_C[i];
          let poly_D_bound_point = poly_D_bound_point + poly_D[len + i] - poly_D[i];
          eval_point_3 += comb_func(
            &poly_A_bound_point,
            &poly_B_bound_point,
            &poly_C_bound_point,
            &poly_D_bound_point,
          );
        }

        let evals = vec![
          eval_point_0,
          claim_per_round - eval_point_0,
          eval_point_2,
          eval_point_3,
        ];
        let poly = UniPoly::from_evals(&evals);
        let comm_poly = poly.commit(gens_n, &blinds_poly[j]);
        (poly, comm_poly)
      };

      // append the prover's message to the transcript
      <Transcript as ProofTranscript<G>>::append_point(transcript, b"comm_poly", &comm_poly);
      comm_polys.push(comm_poly);

      //derive the verifier's challenge for the next round
      let r_j =
        <Transcript as ProofTranscript<G>>::challenge_scalar(transcript, b"challenge_nextround");

      // bound all tables to the verifier's challenge
      poly_A.bound_poly_var_top(&r_j);
      poly_B.bound_poly_var_top(&r_j);
      poly_C.bound_poly_var_top(&r_j);
      poly_D.bound_poly_var_top(&r_j);

      // produce a proof of sum-check and of evaluation
      let (proof, claim_next_round, comm_claim_next_round) = {
        let eval = poly.evaluate(&r_j);
        let comm_eval = eval.commit(&blinds_evals[j], gens_1);

        // we need to prove the following under homomorphic commitments:
        // (1) poly(0) + poly(1) = claim_per_round
        // (2) poly(r_j) = eval

        // Our technique is to leverage dot product proofs:
        // (1) we can prove: <poly_in_coeffs_form, (2, 1, 1, 1)> = claim_per_round
        // (2) we can prove: <poly_in_coeffs_form, (1, r_j, r^2_j, ..) = eval
        // for efficiency we batch them using random weights

        // add two claims to transcript
        <Transcript as ProofTranscript<G>>::append_point(
          transcript,
          b"comm_claim_per_round",
          &comm_claim_per_round,
        );
        <Transcript as ProofTranscript<G>>::append_point(transcript, b"comm_eval", &comm_eval);

        // produce two weights
        let w = <Transcript as ProofTranscript<G>>::challenge_vector(
          transcript,
          b"combine_two_claims_to_one",
          2,
        );

        // compute a weighted sum of the RHS
        let target = w[0] * claim_per_round + w[1] * eval;

        let bases = vec![comm_claim_per_round.into_affine(), comm_eval.into_affine()];

        let comm_target = VariableBaseMSM::msm(bases.as_ref(), w.as_ref()).unwrap();

        let blind = {
          let blind_sc = if j == 0 {
            blind_claim
          } else {
            &blinds_evals[j - 1]
          };

          let blind_eval = &blinds_evals[j];

          w[0] * blind_sc + w[1] * blind_eval
        };

        assert_eq!(target.commit(&blind, gens_1), comm_target);

        let a = {
          // the vector to use to decommit for sum-check test
          let a_sc = {
            let mut a = vec![G::ScalarField::one(); poly.degree() + 1];
            a[0] += G::ScalarField::one();
            a
          };

          // the vector to use to decommit for evaluation
          let a_eval = {
            let mut a = vec![G::ScalarField::one(); poly.degree() + 1];
            for j in 1..a.len() {
              a[j] = a[j - 1] * r_j;
            }
            a
          };

          // take weighted sum of the two vectors using w
          assert_eq!(a_sc.len(), a_eval.len());
          (0..a_sc.len())
            .map(|i| w[0] * a_sc[i] + w[1] * a_eval[i])
            .collect::<Vec<G::ScalarField>>()
        };

        let (proof, _comm_poly, _comm_sc_eval) = DotProductProof::prove(
          gens_1,
          gens_n,
          transcript,
          random_tape,
          &poly.as_vec(),
          &blinds_poly[j],
          &a,
          &target,
          &blind,
        );

        (proof, eval, comm_eval)
      };

      proofs.push(proof);
      claim_per_round = claim_next_round;
      comm_claim_per_round = comm_claim_next_round;
      r.push(r_j);
      comm_evals.push(comm_claim_per_round);
    }

    (
      ZKSumcheckInstanceProof::new(comm_polys, comm_evals, proofs),
      r,
      vec![poly_A[0], poly_B[0], poly_C[0], poly_D[0]],
      blinds_evals[num_rounds - 1],
    )
  }
}
