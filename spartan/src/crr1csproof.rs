#![allow(clippy::too_many_arguments)]
#![allow(dead_code)]
use crate::polycommitments::PolyCommitmentScheme;
use crate::unipoly::{CompressedUniPoly, UniPoly};
use crate::{InputsAssignment, Instance, VarsAssignment};

use super::dense_mlpoly::{DensePolynomial, EqPolynomial};
use super::errors::ProofVerifyError;
use super::math::Math;
use super::random::RandomTape;
use super::sparse_mlpoly::{SparsePolyEntry, SparsePolynomial};
use super::sumcheck::SumcheckInstanceProof;
use super::timer::Timer;
use super::transcript::{AppendToTranscript, ProofTranscript};
use ark_ec::CurveGroup;
use ark_ff::PrimeField;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{cmp::max, One, Zero};
use merlin::Transcript;

pub struct CRR1CSKey<G: CurveGroup, PC: PolyCommitmentScheme<G>> {
  pc_commit_key: PC::PolyCommitmentKey,
  pc_verify_key: PC::EvalVerifierKey,
}

impl<G: CurveGroup, PC: PolyCommitmentScheme<G>> CRR1CSKey<G, PC> {
  pub fn new(SRS: &PC::SRS, num_cons: usize, num_vars: usize) -> Self {
    // Since we have commitments both to the witness and the error vectors
    // we need the commitment key to hold the larger of the two
    let n = max(num_cons, num_vars);
    let (pc_commit_key, pc_verify_key) = PC::trim(SRS, n);
    CRR1CSKey {
      pc_commit_key,
      pc_verify_key,
    }
  }
}

pub struct CRR1CSShape<F: PrimeField> {
  pub inst: Instance<F>,
}

impl<F: PrimeField> CRR1CSShape<F> {
  pub fn get_num_cons(&self) -> usize {
    self.inst.inst.get_num_cons()
  }
  pub fn get_num_vars(&self) -> usize {
    self.inst.inst.get_num_vars()
  }
  pub fn get_num_inputs(&self) -> usize {
    self.inst.inst.get_num_inputs()
  }
}

pub struct CRR1CSInstance<G: CurveGroup, PC: PolyCommitmentScheme<G>> {
  pub input: InputsAssignment<G::ScalarField>,
  pub u: G::ScalarField,
  pub comm_W: PC::Commitment,
  pub comm_E: PC::Commitment,
}

pub struct CRR1CSWitness<F: PrimeField> {
  pub W: VarsAssignment<F>,
  pub E: Vec<F>,
}

#[derive(CanonicalSerialize, CanonicalDeserialize, Debug)]
pub struct CRR1CSProof<G: CurveGroup, PC: PolyCommitmentScheme<G>> {
  /// Sumcheck proof for the polynomial g(x) = \sum eq(tau,x) * (~Az~(x) * ~Bz~(x) - u * ~Cz~(x) - ~E~(x))
  sc_proof_phase1: SumcheckInstanceProof<G::ScalarField>,
  /// Evaluation claims for ~Az~(rx), ~Bz~(rx), and ~Cz~(rx).
  claims_phase2: (G::ScalarField, G::ScalarField, G::ScalarField),
  /// Sumcheck proof for the polynomial F(x) = ~Z(x)~ * ~ABC~(x), where ABC(x) = \sum_t ~M~(t,x) eq(r,t)
  /// for M a random linear combination of A, B, and C.
  sc_proof_phase2: SumcheckInstanceProof<G::ScalarField>,
  /// The claimed evaluation ~Z~(ry)
  eval_vars_at_ry: G::ScalarField,
  /// A polynomial evaluation proof of the claimed evaluation ~Z~(ry) with respect to the commitment comm_W.
  proof_eval_vars_at_ry: PC::PolyCommitmentProof,
  /// The claimed evaluation ~E~(rx)
  eval_error_at_rx: G::ScalarField,
  /// A polynomial evaluation proof of the claimed evaluation ~E~(rx) with respect to the commitment comm_E.
  proof_eval_error_at_rx: PC::PolyCommitmentProof,
}

impl<F: PrimeField> SumcheckInstanceProof<F> {
  pub fn prove_quad<Func, G>(
    claim: &F,
    num_rounds: usize,
    poly_A: &mut DensePolynomial<F>,
    poly_B: &mut DensePolynomial<F>,
    comb_func: Func,
    transcript: &mut Transcript,
  ) -> (Self, Vec<F>, Vec<F>)
  where
    Func: Fn(&F, &F) -> F,
    G: CurveGroup<ScalarField = F>,
  {
    let mut e = *claim;
    let mut r: Vec<F> = Vec::new();
    let mut quad_polys: Vec<CompressedUniPoly<F>> = Vec::new();
    for _j in 0..num_rounds {
      let mut eval_point_0 = F::zero();
      let mut eval_point_2 = F::zero();

      let len = poly_A.len() / 2;
      for i in 0..len {
        // eval 0: bound_func is A(low)
        eval_point_0 += comb_func(&poly_A[i], &poly_B[i]);

        // eval 2: bound_func is -A(low) + 2*A(high)
        let poly_A_bound_point = poly_A[len + i] + poly_A[len + i] - poly_A[i];
        let poly_B_bound_point = poly_B[len + i] + poly_B[len + i] - poly_B[i];

        eval_point_2 += comb_func(&poly_A_bound_point, &poly_B_bound_point);
      }

      let evals = vec![eval_point_0, e - eval_point_0, eval_point_2];
      let poly = UniPoly::from_evals(&evals);

      // append the prover's message to the transcript
      <UniPoly<F> as AppendToTranscript<G>>::append_to_transcript(&poly, b"poly", transcript);

      //derive the verifier's challenge for the next round
      let r_j =
        <Transcript as ProofTranscript<G>>::challenge_scalar(transcript, b"challenge_nextround");

      r.push(r_j);
      // bound all tables to the verifier's challenege
      poly_A.bound_poly_var_top(&r_j);
      poly_B.bound_poly_var_top(&r_j);
      e = poly.evaluate(&r_j);
      quad_polys.push(poly.compress());
    }

    (
      SumcheckInstanceProof::new(quad_polys),
      r,
      vec![poly_A[0], poly_B[0]],
    )
  }
  pub fn prove_cubic_five_terms<Func, G>(
    claim: &F,
    num_rounds: usize,
    poly_A: &mut DensePolynomial<F>,
    poly_B: &mut DensePolynomial<F>,
    poly_C: &mut DensePolynomial<F>,
    poly_D: &mut DensePolynomial<F>,
    poly_E: &mut DensePolynomial<F>,
    comb_func: Func,
    transcript: &mut Transcript,
  ) -> (Self, Vec<F>, Vec<F>)
  where
    Func: Fn(&F, &F, &F, &F, &F) -> F,
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
        eval_point_0 += comb_func(&poly_A[i], &poly_B[i], &poly_C[i], &poly_D[i], &poly_E[i]);

        // eval 2: bound_func is -A(low) + 2*A(high)
        let poly_A_bound_point = poly_A[len + i] + poly_A[len + i] - poly_A[i];
        let poly_B_bound_point = poly_B[len + i] + poly_B[len + i] - poly_B[i];
        let poly_C_bound_point = poly_C[len + i] + poly_C[len + i] - poly_C[i];
        let poly_D_bound_point = poly_D[len + i] + poly_D[len + i] - poly_D[i];
        let poly_E_bound_point = poly_E[len + i] + poly_E[len + i] - poly_E[i];

        eval_point_2 += comb_func(
          &poly_A_bound_point,
          &poly_B_bound_point,
          &poly_C_bound_point,
          &poly_D_bound_point,
          &poly_E_bound_point,
        );

        // eval 3: bound_func is -2A(low) + 3A(high); computed incrementally with bound_func applied to eval(2)
        let poly_A_bound_point = poly_A_bound_point + poly_A[len + i] - poly_A[i];
        let poly_B_bound_point = poly_B_bound_point + poly_B[len + i] - poly_B[i];
        let poly_C_bound_point = poly_C_bound_point + poly_C[len + i] - poly_C[i];
        let poly_D_bound_point = poly_D_bound_point + poly_D[len + i] - poly_D[i];
        let poly_E_bound_point = poly_E_bound_point + poly_E[len + i] - poly_E[i];

        eval_point_3 += comb_func(
          &poly_A_bound_point,
          &poly_B_bound_point,
          &poly_C_bound_point,
          &poly_D_bound_point,
          &poly_E_bound_point,
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
      // bound all tables to the verifier's challenege
      poly_A.bound_poly_var_top(&r_j);
      poly_B.bound_poly_var_top(&r_j);
      poly_C.bound_poly_var_top(&r_j);
      poly_D.bound_poly_var_top(&r_j);
      poly_E.bound_poly_var_top(&r_j);
      e = poly.evaluate(&r_j);
      cubic_polys.push(poly.compress());
    }
    (
      SumcheckInstanceProof::new(cubic_polys),
      r,
      vec![poly_A[0], poly_B[0], poly_C[0], poly_D[0], poly_E[0]],
    )
  }
}

impl<G: CurveGroup, PC: PolyCommitmentScheme<G>> CRR1CSProof<G, PC> {
  #[allow(clippy::type_complexity)]
  /// Generates the sumcheck proof that sum_s evals_tau(s) * (evals_Az(s) * evals_Bz(s) - u * evals_Cz(s) - E(s)) == 0.
  /// Note that this proof does not use blinding factors, so this is not zero-knowledge.
  fn prove_phase_one(
    num_rounds: usize,
    evals_tau: &mut DensePolynomial<G::ScalarField>,
    evals_Az: &mut DensePolynomial<G::ScalarField>,
    evals_Bz: &mut DensePolynomial<G::ScalarField>,
    evals_Cz: &mut DensePolynomial<G::ScalarField>,
    evals_E: &mut DensePolynomial<G::ScalarField>,
    u: &G::ScalarField,
    transcript: &mut Transcript,
  ) -> (
    SumcheckInstanceProof<G::ScalarField>,
    Vec<G::ScalarField>,
    Vec<G::ScalarField>,
  ) {
    let relaxed_comb_func =
      |poly_tau: &G::ScalarField,
       poly_A: &G::ScalarField,
       poly_B: &G::ScalarField,
       poly_C: &G::ScalarField,
       poly_E: &G::ScalarField|
       -> G::ScalarField { (*poly_A * *poly_B - *u * *poly_C - *poly_E) * *poly_tau };

    let (sc_proof_phase_one, r, claims) = SumcheckInstanceProof::prove_cubic_five_terms::<_, G>(
      &G::ScalarField::zero(), // claim is zero
      num_rounds,
      evals_tau,
      evals_Az,
      evals_Bz,
      evals_Cz,
      evals_E,
      relaxed_comb_func,
      transcript,
    );

    (sc_proof_phase_one, r, claims)
  }

  /// Generates the sumcheck proof that `claim` = sum_{s,t} eq(r, t) evals_ABC(t, s) evals_z(s)
  #[allow(clippy::type_complexity)]
  fn prove_phase_two(
    num_rounds: usize,
    claim: &G::ScalarField,
    evals_z: &mut DensePolynomial<G::ScalarField>,
    evals_ABC: &mut DensePolynomial<G::ScalarField>,
    transcript: &mut Transcript,
  ) -> (
    SumcheckInstanceProof<G::ScalarField>,
    Vec<G::ScalarField>,
    Vec<G::ScalarField>,
  ) {
    let comb_func = |poly_A_comp: &G::ScalarField,
                     poly_B_comp: &G::ScalarField|
     -> G::ScalarField { *poly_A_comp * *poly_B_comp };
    let (sc_proof_phase_two, r, claims) = SumcheckInstanceProof::prove_quad::<_, G>(
      claim, num_rounds, evals_z, evals_ABC, comb_func, transcript,
    );

    (sc_proof_phase_two, r, claims)
  }

  fn protocol_name() -> &'static [u8] {
    b"CRR1CS proof"
  }
  #[allow(clippy::type_complexity)]
  pub fn prove(
    shape: &CRR1CSShape<G::ScalarField>,
    instance: &CRR1CSInstance<G, PC>,
    witness: &CRR1CSWitness<G::ScalarField>,
    key: &CRR1CSKey<G, PC>,
    transcript: &mut Transcript,
    random_tape: &mut Option<RandomTape<G>>,
  ) -> (CRR1CSProof<G, PC>, Vec<G::ScalarField>, Vec<G::ScalarField>) {
    let timer_prove = Timer::new("CRR1CSProof::prove");
    <Transcript as ProofTranscript<G>>::append_protocol_name(
      transcript,
      CRR1CSProof::<G, PC>::protocol_name(),
    );

    let _inst = &shape.inst.inst;
    let CRR1CSInstance {
      input: _input,
      u,
      comm_W,
      comm_E,
    } = instance;

    let CRR1CSWitness { W: _vars, E } = witness;

    let (inst, input, vars) = (
      &_inst,
      _input.assignment.as_slice(),
      _vars.assignment.clone(),
    );

    // we currently require the number of |inputs| + 1 to be at most number of vars
    assert!(input.len() < vars.len());
    <Transcript as ProofTranscript<G>>::append_scalars(transcript, b"input", input);
    <Transcript as ProofTranscript<G>>::append_scalar(transcript, b"u", u);
    comm_W.append_to_transcript(b"comm_W", transcript);
    comm_E.append_to_transcript(b"comm_E", transcript);
    // create a multilinear polynomial using the supplied assignment for variables
    let poly_vars = DensePolynomial::<G::ScalarField>::new(vars.clone());
    // create a multilinear polynomial from the error vector
    let poly_error = DensePolynomial::<G::ScalarField>::new(E.clone());

    let timer_sc_proof_phase1 = Timer::new("prove_sc_phase_one");

    // append input to variables to create a single vector z
    let z = {
      let num_inputs = input.len();
      let num_vars = vars.len();
      let mut z = vars;
      z.extend(vec![u]); // add relaxed constant term in z
      z.extend(input);
      z.extend(&vec![G::ScalarField::zero(); num_vars - num_inputs - 1]); // we will pad with zeros
      z
    };

    // derive the verifier's challenge tau
    let (num_rounds_x, num_rounds_y) = (inst.get_num_cons().log_2(), z.len().log_2());
    let tau = <Transcript as ProofTranscript<G>>::challenge_vector(
      transcript,
      b"challenge_tau",
      num_rounds_x,
    );
    // compute the initial evaluation table for R(\tau, x)
    let mut poly_tau = DensePolynomial::new(EqPolynomial::new(tau).evals());
    let (mut poly_Az, mut poly_Bz, mut poly_Cz) =
      inst.multiply_vec(inst.get_num_cons(), z.len(), &z);

    let mut poly_E_final = poly_error.clone();

    let (sc_proof_phase1, rx, _claims_phase1) = CRR1CSProof::<G, PC>::prove_phase_one(
      num_rounds_x,
      &mut poly_tau,
      &mut poly_Az,
      &mut poly_Bz,
      &mut poly_Cz,
      &mut poly_E_final,
      u,
      transcript,
    );
    assert_eq!(poly_tau.len(), 1);
    assert_eq!(poly_Az.len(), 1);
    assert_eq!(poly_Bz.len(), 1);
    assert_eq!(poly_Cz.len(), 1);
    assert_eq!(poly_E_final.len(), 1);
    timer_sc_proof_phase1.stop();

    let (_, Az_claim, Bz_claim, Cz_claim, E_claim) = (
      &poly_tau[0],
      &poly_Az[0],
      &poly_Bz[0],
      &poly_Cz[0],
      &poly_E_final[0],
    );

    <Transcript as ProofTranscript<G>>::append_scalar(transcript, b"Az_claim", Az_claim);
    <Transcript as ProofTranscript<G>>::append_scalar(transcript, b"Bz_claim", Bz_claim);
    <Transcript as ProofTranscript<G>>::append_scalar(transcript, b"Cz_claim", Cz_claim);
    <Transcript as ProofTranscript<G>>::append_scalar(transcript, b"E_claim", E_claim);

    let timer_sc_proof_phase2 = Timer::new("prove_sc_phase_two");
    // combine the three claims into a single claim
    let r_A = <Transcript as ProofTranscript<G>>::challenge_scalar(transcript, b"challenege_Az");
    let r_B = <Transcript as ProofTranscript<G>>::challenge_scalar(transcript, b"challenege_Bz");
    let r_C = <Transcript as ProofTranscript<G>>::challenge_scalar(transcript, b"challenege_Cz");
    let claim_phase2 = r_A * Az_claim + r_B * Bz_claim + r_C * Cz_claim;

    let evals_ABC = {
      // compute the initial evaluation table for R(\tau, x)
      let evals_rx = EqPolynomial::new(rx.clone()).evals();
      let (evals_A, evals_B, evals_C) =
        inst.compute_eval_table_sparse(inst.get_num_cons(), z.len(), &evals_rx);

      assert_eq!(evals_A.len(), evals_B.len());
      assert_eq!(evals_A.len(), evals_C.len());
      (0..evals_A.len())
        .map(|i| r_A * evals_A[i] + r_B * evals_B[i] + r_C * evals_C[i])
        .collect::<Vec<G::ScalarField>>()
    };

    // another instance of the sum-check protocol
    let (sc_proof_phase2, ry, _claims_phase2) = CRR1CSProof::<G, PC>::prove_phase_two(
      num_rounds_y,
      &claim_phase2,
      &mut DensePolynomial::new(z),
      &mut DensePolynomial::new(evals_ABC),
      transcript,
    );
    timer_sc_proof_phase2.stop();

    let timer_polyeval = Timer::new("polyeval");
    let eval_vars_at_ry = poly_vars.evaluate::<G>(&ry[1..]);
    let proof_eval_vars_at_ry = {
      PC::prove(
        &poly_vars,
        &ry[1..],
        &eval_vars_at_ry,
        &key.pc_commit_key,
        transcript,
        random_tape,
      )
    };

    let proof_eval_error_at_rx = {
      PC::prove(
        &poly_error,
        &rx,
        E_claim,
        &key.pc_commit_key,
        transcript,
        random_tape,
      )
    };

    timer_polyeval.stop();

    timer_prove.stop();

    (
      CRR1CSProof {
        sc_proof_phase1,
        claims_phase2: (*Az_claim, *Bz_claim, *Cz_claim),
        sc_proof_phase2,
        eval_vars_at_ry,
        proof_eval_vars_at_ry,
        eval_error_at_rx: *E_claim,
        proof_eval_error_at_rx,
      },
      rx,
      ry,
    )
  }

  #[allow(clippy::type_complexity)]
  pub fn verify(
    &self,
    num_vars: usize,
    num_cons: usize,
    instance: &CRR1CSInstance<G, PC>,
    evals: &(G::ScalarField, G::ScalarField, G::ScalarField),
    transcript: &mut Transcript,
    key: &CRR1CSKey<G, PC>,
  ) -> Result<(Vec<G::ScalarField>, Vec<G::ScalarField>), ProofVerifyError> {
    <Transcript as ProofTranscript<G>>::append_protocol_name(
      transcript,
      CRR1CSProof::<G, PC>::protocol_name(),
    );

    let CRR1CSInstance {
      input: _input,
      u,
      comm_W,
      comm_E,
    } = instance;

    let input = _input.assignment.as_slice();

    <Transcript as ProofTranscript<G>>::append_scalars(transcript, b"input", input);
    <Transcript as ProofTranscript<G>>::append_scalar(transcript, b"u", u);
    comm_W.append_to_transcript(b"comm_W", transcript);
    comm_E.append_to_transcript(b"comm_E", transcript);

    let n = num_vars;

    let (num_rounds_x, num_rounds_y) = (num_cons.log_2(), (2 * num_vars).log_2());

    // derive the verifier's challenge tau
    let tau = <Transcript as ProofTranscript<G>>::challenge_vector(
      transcript,
      b"challenge_tau",
      num_rounds_x,
    );

    // verify the first sum-check instance
    let claim_phase1 = G::ScalarField::zero();
    let (claim_post_phase1, rx) =
      self
        .sc_proof_phase1
        .verify::<G>(claim_phase1, num_rounds_x, 3, transcript)?;

    // perform the intermediate sum-check test with claimed Az, Bz, Cz, and E
    let (Az_claim, Bz_claim, Cz_claim) = self.claims_phase2;
    let E_claim = &self.eval_error_at_rx;

    <Transcript as ProofTranscript<G>>::append_scalar(transcript, b"Az_claim", &Az_claim);
    <Transcript as ProofTranscript<G>>::append_scalar(transcript, b"Bz_claim", &Bz_claim);
    <Transcript as ProofTranscript<G>>::append_scalar(transcript, b"Cz_claim", &Cz_claim);
    <Transcript as ProofTranscript<G>>::append_scalar(transcript, b"E_claim", E_claim);

    let taus_bound_rx: G::ScalarField = (0..rx.len())
      .map(|i| rx[i] * tau[i] + (G::ScalarField::one() - rx[i]) * (G::ScalarField::one() - tau[i]))
      .product();

    let expected_claim_post_phase1 =
      (Az_claim * Bz_claim - *u * Cz_claim - E_claim) * taus_bound_rx;
    assert_eq!(expected_claim_post_phase1, claim_post_phase1);

    // derive three public challenges and then derive a joint claim
    let r_A = <Transcript as ProofTranscript<G>>::challenge_scalar(transcript, b"challenege_Az");
    let r_B = <Transcript as ProofTranscript<G>>::challenge_scalar(transcript, b"challenege_Bz");
    let r_C = <Transcript as ProofTranscript<G>>::challenge_scalar(transcript, b"challenege_Cz");

    // r_A * Az_claim + r_B * Bz_claim + r_C * Cz_claim;
    let claim_phase2 = r_A * Az_claim + r_B * Bz_claim + r_C * Cz_claim;

    // verify the joint claim with a sum-check protocol
    let (claim_post_phase2, ry) =
      self
        .sc_proof_phase2
        .verify::<G>(claim_phase2, num_rounds_y, 2, transcript)?;

    // verify Z(ry) proof against the initial commitment `comm_W`
    PC::verify(
      comm_W,
      &self.proof_eval_vars_at_ry,
      &key.pc_verify_key,
      transcript,
      &ry[1..],
      &self.eval_vars_at_ry,
    )
    .map_err(|_| ProofVerifyError::InternalError)?;

    // verify E(rx) proof against the initial commitment `comm_E`
    PC::verify(
      comm_E,
      &self.proof_eval_error_at_rx,
      &key.pc_verify_key,
      transcript,
      &rx,
      &self.eval_error_at_rx,
    )
    .map_err(|_| ProofVerifyError::InternalError)?;

    let poly_input_eval = {
      // constant term
      let mut input_as_sparse_poly_entries = vec![SparsePolyEntry::new(0, *u)];
      //remaining inputs
      input_as_sparse_poly_entries.extend(
        (0..input.len())
          .map(|i| SparsePolyEntry::new(i + 1, input[i]))
          .collect::<Vec<SparsePolyEntry<G::ScalarField>>>(),
      );
      SparsePolynomial::new(n.log_2(), input_as_sparse_poly_entries).evaluate(&ry[1..])
    };

    // compute eval_Z_at_ry = (F::one() - ry[0]) * self.eval_vars_at_ry + ry[0] * poly_input_eval
    let eval_Z_at_ry =
      (G::ScalarField::one() - ry[0]) * self.eval_vars_at_ry + ry[0] * poly_input_eval;

    // perform the final check in the second sum-check protocol
    let (eval_A_r, eval_B_r, eval_C_r) = evals;
    let expected_claim_post_phase2 =
      eval_Z_at_ry * (r_A * eval_A_r + r_B * eval_B_r + r_C * eval_C_r);

    assert_eq!(expected_claim_post_phase2, claim_post_phase2);

    Ok((rx, ry))
  }
}

#[cfg(test)]
mod tests {
  use crate::polycommitments::{hyrax::Hyrax, VectorCommitmentTrait};

  use crate::r1csinstance::R1CSInstance;

  use super::*;
  use ark_bls12_381::Fr;
  use ark_bls12_381::G1Projective;
  use ark_ff::PrimeField;
  use ark_std::{test_rng, UniformRand};

  fn produce_tiny_r1cs<F: PrimeField>() -> (R1CSInstance<F>, Vec<F>, Vec<F>) {
    // three constraints over five variables Z1, Z2, Z3, Z4, and Z5
    // rounded to the nearest power of two
    let num_cons = 128;
    let num_vars = 256;
    let num_inputs = 2;

    // encode the above constraints into three matrices
    let mut A: Vec<(usize, usize, F)> = Vec::new();
    let mut B: Vec<(usize, usize, F)> = Vec::new();
    let mut C: Vec<(usize, usize, F)> = Vec::new();

    let one = F::one();
    // constraint 0 entries
    // (Z1 + Z2) * I0 - Z3 = 0;
    A.push((0, 0, one));
    A.push((0, 1, one));
    B.push((0, num_vars + 1, one));
    C.push((0, 2, one));

    // constraint 1 entries
    // (Z1 + I1) * (Z3) - Z4 = 0
    A.push((1, 0, one));
    A.push((1, num_vars + 2, one));
    B.push((1, 2, one));
    C.push((1, 3, one));
    // constraint 3 entries
    // Z5 * 1 - 0 = 0
    A.push((2, 4, one));
    B.push((2, num_vars, one));

    let inst = R1CSInstance::new(num_cons, num_vars, num_inputs, &A, &B, &C);

    // compute a satisfying assignment
    let mut prng = test_rng();
    let i0 = F::rand(&mut prng);
    let i1 = F::rand(&mut prng);
    let z1 = F::rand(&mut prng);
    let z2 = F::rand(&mut prng);
    let z3 = (z1 + z2) * i0; // constraint 1: (Z1 + Z2) * I0 - Z3 = 0;
    let z4 = (z1 + i1) * z3; // constraint 2: (Z1 + I1) * (Z3) - Z4 = 0
    let z5 = F::zero(); //constraint 3

    let mut vars = vec![F::zero(); num_vars];
    vars[0] = z1;
    vars[1] = z2;
    vars[2] = z3;
    vars[3] = z4;
    vars[4] = z5;

    let mut input = vec![F::zero(); num_inputs];
    input[0] = i0;
    input[1] = i1;

    (inst, vars, input)
  }
  #[allow(clippy::type_complexity)]
  // This produces a random satisfying structure, instance, witness, and public parameters for testing and benchmarking purposes.
  pub fn produce_synthetic_crr1cs<G: CurveGroup, PC: PolyCommitmentScheme<G>>(
    num_cons: usize,
    num_vars: usize,
    num_inputs: usize,
  ) -> (
    CRR1CSShape<G::ScalarField>,
    CRR1CSInstance<G, PC>,
    CRR1CSWitness<G::ScalarField>,
    CRR1CSKey<G, PC>,
  ) {
    // compute random satisfying assignment for r1cs
    let (inst, vars, inputs) = Instance::produce_synthetic_r1cs(num_cons, num_vars, num_inputs);
    // the `Instance` initializer may have padded the variable lengths
    let (num_cons, num_vars, num_inputs) = (
      inst.inst.get_num_cons(),
      inst.inst.get_num_vars(),
      inst.inst.get_num_inputs(),
    );
    assert_eq!(num_vars, vars.assignment.len());
    assert_eq!(num_inputs, inputs.assignment.len());
    let shape = CRR1CSShape { inst };

    // Note that `produce_synthetic_r1cs` produces a satisfying assignment for Z = [vars, 1, inputs].
    let mut Z = vars.assignment.clone();
    Z.extend(&vec![G::ScalarField::one()]);
    Z.extend(inputs.assignment.clone());

    // Choose a random u and set Z[num_vars] = u.
    let u = G::ScalarField::rand(&mut test_rng());
    Z[num_vars] = u;

    let (poly_A, poly_B, poly_C) =
      shape
        .inst
        .inst
        .multiply_vec(num_cons, num_vars + num_inputs + 1, Z.as_slice());

    // Compute the error vector E = (AZ * BZ) - (u * CZ)
    let mut E = vec![G::ScalarField::zero(); num_cons];
    for i in 0..num_cons {
      let AB_val = poly_A[i] * poly_B[i];
      let C_val = poly_C[i];
      E[i] = AB_val - u * C_val;
    }

    // compute commitments to the vectors `vars` and `E`.
    let n = max(num_cons, num_vars);
    let mut rng = test_rng();
    let SRS = PC::setup(n.log_2(), b"test-SRS", &mut rng).unwrap();
    let key = CRR1CSKey::<G, PC>::new(&SRS, num_cons, num_vars);
    let mut random_tape = None;
    let comm_W = <PC as VectorCommitmentTrait<G>>::commit(
      vars.assignment.as_slice(),
      &key.pc_commit_key,
      &mut random_tape,
    );
    let comm_E =
      <PC as VectorCommitmentTrait<G>>::commit(E.as_slice(), &key.pc_commit_key, &mut random_tape);
    (
      shape,
      CRR1CSInstance::<G, PC> {
        input: inputs,
        u,
        comm_W,
        comm_E,
      },
      CRR1CSWitness::<G::ScalarField> {
        W: vars.clone(),
        E: E.clone(),
      },
      key,
    )
  }

  #[test]
  fn test_tiny_r1cs() {
    test_tiny_r1cs_helper::<Fr>()
  }

  fn test_tiny_r1cs_helper<F: PrimeField>() {
    let (inst, vars, input) = tests::produce_tiny_r1cs::<F>();
    let is_sat = inst.is_sat(&vars, &input);
    assert!(is_sat);
  }

  #[test]
  fn test_synthetic_r1cs() {
    test_synthetic_r1cs_helper::<Fr>()
  }

  fn test_synthetic_r1cs_helper<F: PrimeField>() {
    let (inst, vars, input) = R1CSInstance::<F>::produce_synthetic_r1cs(1024, 1024, 10);
    let is_sat = inst.is_sat(&vars, &input);
    assert!(is_sat);
  }

  #[test]
  pub fn check_crr1cs_proof() {
    check_crr1cs_proof_helper::<G1Projective, Hyrax<G1Projective>>()
  }
  fn check_crr1cs_proof_helper<G: CurveGroup, PC: PolyCommitmentScheme<G>>() {
    let num_vars = 1024;
    let num_cons = num_vars;
    let num_inputs = 10;
    let (shape, instance, witness, key) =
      produce_synthetic_crr1cs::<G, PC>(num_cons, num_vars, num_inputs);
    let (num_cons, num_vars, _num_inputs) = (
      shape.get_num_cons(),
      shape.get_num_vars(),
      shape.get_num_inputs(),
    );

    let mut random_tape = None;
    let mut prover_transcript = Transcript::new(b"example");

    let (proof, rx, ry) = CRR1CSProof::prove(
      &shape,
      &instance,
      &witness,
      &key,
      &mut prover_transcript,
      &mut random_tape,
    );

    let inst_evals = shape.inst.inst.evaluate(&rx, &ry);

    let mut verifier_transcript = Transcript::new(b"example");
    assert!(proof
      .verify(
        num_vars,
        num_cons,
        &instance,
        &inst_evals,
        &mut verifier_transcript,
        &key,
      )
      .is_ok());
  }
}
