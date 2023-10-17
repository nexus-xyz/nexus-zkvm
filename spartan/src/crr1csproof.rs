#![allow(clippy::too_many_arguments)]
use crate::r1csproof::R1CSSumcheckGens;
use crate::unipoly::{CompressedUniPoly, UniPoly};
use crate::{InputsAssignment, Instance, VarsAssignment};

use super::dense_mlpoly::{
  DensePolynomial, EqPolynomial, PolyCommitment, PolyCommitmentGens, PolyEvalProof,
};
use super::errors::ProofVerifyError;
use super::math::Math;
use super::r1csinstance::R1CSInstance;
use super::random::RandomTape;
//use super::snark_traits::CommittedRelaxedR1CSSNARKTrait;
use super::sparse_mlpoly::{SparsePolyEntry, SparsePolynomial};
use super::sumcheck::SumcheckInstanceProof;
use super::timer::Timer;
use super::transcript::{AppendToTranscript, ProofTranscript};
use ark_ec::CurveGroup;
use ark_ff::PrimeField;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{One, Zero};
use merlin::Transcript;

pub struct CRR1CSGens<G> {
  gens_sc: R1CSSumcheckGens<G>,
  gens_pc: PolyCommitmentGens<G>,
}

impl<G: CurveGroup> CRR1CSGens<G> {
  pub fn new(label: &'static [u8], _num_cons: usize, num_vars: usize) -> Self {
    let num_poly_vars = num_vars.log_2() as usize;
    let gens_pc = PolyCommitmentGens::new(num_poly_vars, label);
    let gens_sc = R1CSSumcheckGens::new(label, &gens_pc.gens.gens_1);
    CRR1CSGens { gens_sc, gens_pc }
  }
}
pub struct CRR1CSInstance<G: CurveGroup> {
  pub inst: Instance<G::ScalarField>,
  pub input: InputsAssignment<G::ScalarField>,
  pub u: G::ScalarField,
  pub comm_W: G,
  pub comm_E: G,
}

pub struct CRR1CSWitness<F: PrimeField> {
  pub W: VarsAssignment<F>,
  pub E: Vec<F>,
}

#[derive(CanonicalSerialize, CanonicalDeserialize, Debug)]
pub struct CRR1CSProof<G: CurveGroup> {
  sc_proof_phase1: SumcheckInstanceProof<G::ScalarField>,
  claims_phase2: (
    G::ScalarField,
    G::ScalarField,
    G::ScalarField,
    G::ScalarField,
  ),
  sc_proof_phase2: SumcheckInstanceProof<G::ScalarField>,
  eval_vars_at_ry: G::ScalarField,
  proof_eval_vars_at_ry: PolyEvalProof<G>,
  eval_error_at_rx: G::ScalarField,
  proof_eval_error_at_rx: PolyEvalProof<G>,
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

impl<G: CurveGroup> CRR1CSProof<G> {
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
    let relaxed_comb_func = |poly_A_comp: &G::ScalarField,
                             poly_B_comp: &G::ScalarField,
                             poly_C_comp: &G::ScalarField,
                             poly_D_comp: &G::ScalarField,
                             poly_E_comp: &G::ScalarField|
     -> G::ScalarField {
      *poly_A_comp * (*poly_B_comp * *poly_C_comp - *u * *poly_D_comp - *poly_E_comp)
    };

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
    b"R1CS proof"
  }

  pub fn prove(
    instance: &CRR1CSInstance<G>,
    witness: &CRR1CSWitness<G::ScalarField>,
    gens: &CRR1CSGens<G>,
    transcript: &mut Transcript,
    random_tape: &mut RandomTape<G>,
  ) -> (CRR1CSProof<G>, Vec<G::ScalarField>, Vec<G::ScalarField>) {
    let timer_prove = Timer::new("R1CSProof::prove");
    <Transcript as ProofTranscript<G>>::append_protocol_name(
      transcript,
      CRR1CSProof::<G>::protocol_name(),
    );

    let CRR1CSInstance {
      inst: _inst,
      input: _input,
      u,
      comm_W,
      comm_E,
    } = instance;

    let CRR1CSWitness { W: _vars, E } = witness;

    let (inst, input, vars) = (
      &_inst.inst,
      _input.assignment.as_slice(),
      _vars.assignment.clone(),
    );

    // we currently require the number of |inputs| + 1 to be at most number of vars
    assert!(input.len() < vars.len());
    <Transcript as ProofTranscript<G>>::append_scalars(transcript, b"input", input);
    <Transcript as ProofTranscript<G>>::append_scalar(transcript, b"u", u);
    transcript.append_point(b"comm_W", comm_W);
    transcript.append_point(b"comm_E", comm_E);

    let poly_vars = DensePolynomial::<G::ScalarField>::new(vars.clone());

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
    let (num_rounds_x, num_rounds_y) = (
      inst.get_num_cons().log_2() as usize,
      z.len().log_2() as usize,
    );
    let tau = <Transcript as ProofTranscript<G>>::challenge_vector(
      transcript,
      b"challenge_tau",
      num_rounds_x,
    );

    // compute the initial evaluation table for R(\tau, x)
    let mut poly_tau = DensePolynomial::new(EqPolynomial::new(tau).evals());
    let (mut poly_Az, mut poly_Bz, mut poly_Cz) =
      inst.multiply_vec(inst.get_num_cons(), z.len(), &z);

    let poly_E_start = DensePolynomial::new(E.clone());
    let mut poly_E_final = poly_E_start.clone();

    let (sc_proof_phase1, rx, _claims_phase1) = CRR1CSProof::<G>::prove_phase_one(
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
    assert_eq!(poly_E_start.len(), inst.get_num_cons());
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
    let (sc_proof_phase2, ry, _claims_phase2) = CRR1CSProof::<G>::prove_phase_two(
      num_rounds_y,
      &claim_phase2,
      &mut DensePolynomial::new(z),
      &mut DensePolynomial::new(evals_ABC),
      transcript,
    );
    timer_sc_proof_phase2.stop();

    let timer_polyeval = Timer::new("polyeval");
    let eval_vars_at_ry = poly_vars.evaluate::<G>(&ry[1..]);
    //let blind_eval = random_tape.random_scalar(b"blind_eval");
    let (proof_eval_vars_at_ry, comm_vars_at_ry) = PolyEvalProof::prove(
      &poly_vars,
      None,
      &ry[1..],
      &eval_vars_at_ry,
      None,
      &gens.gens_pc,
      transcript,
      random_tape,
    );
    assert_eq!(comm_vars_at_ry, *comm_W);

    let (proof_eval_error_at_rx, comm_error_at_rx) = PolyEvalProof::prove(
      &poly_E_start,
      None,
      &rx,
      E_claim,
      None,
      &gens.gens_pc,
      transcript,
      random_tape,
    );

    assert_eq!(comm_error_at_rx, *comm_E);

    timer_polyeval.stop();

    timer_prove.stop();

    (
      CRR1CSProof {
        sc_proof_phase1,
        claims_phase2: (*Az_claim, *Bz_claim, *Cz_claim, *E_claim),
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
    input: &[G::ScalarField],
    u: &G::ScalarField,
    comm_W: &G,
    comm_E: &G,
    evals: &(G::ScalarField, G::ScalarField, G::ScalarField),
    transcript: &mut Transcript,
    gens: &CRR1CSGens<G>,
  ) -> Result<(Vec<G::ScalarField>, Vec<G::ScalarField>), ProofVerifyError> {
    <Transcript as ProofTranscript<G>>::append_protocol_name(
      transcript,
      CRR1CSProof::<G>::protocol_name(),
    );

    <Transcript as ProofTranscript<G>>::append_scalars(transcript, b"input", input);
    <Transcript as ProofTranscript<G>>::append_scalar(transcript, b"u", u);
    transcript.append_point(b"comm_W", comm_W);
    transcript.append_point(b"comm_E", comm_E);
    let n = num_vars;

    let (num_rounds_x, num_rounds_y) = (num_cons.log_2() as usize, (2 * num_vars).log_2() as usize);

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
    let (Az_claim, Bz_claim, Cz_claim, E_claim) = &self.claims_phase2;

    <Transcript as ProofTranscript<G>>::append_scalar(transcript, b"Az_claim", Az_claim);
    <Transcript as ProofTranscript<G>>::append_scalar(transcript, b"Bz_claim", Bz_claim);
    <Transcript as ProofTranscript<G>>::append_scalar(transcript, b"Cz_claim", Cz_claim);
    <Transcript as ProofTranscript<G>>::append_scalar(transcript, b"E_claim", E_claim);

    let taus_bound_rx: G::ScalarField = (0..rx.len())
      .map(|i| rx[i] * tau[i] + (G::ScalarField::one() - rx[i]) * (G::ScalarField::one() - tau[i]))
      .product();
    let expected_claim_post_phase1 =
      (*Az_claim * *Bz_claim - *u * Cz_claim - E_claim) * taus_bound_rx;

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
    self.proof_eval_vars_at_ry.verify_plain(
      &gens.gens_pc,
      transcript,
      &ry[1..],
      &self.eval_vars_at_ry,
      &PolyCommitment { C: vec![*comm_W] },
    )?;

    // verify E(rx) proof against the initial commitment `comm_E`
    self.proof_eval_error_at_rx.verify_plain(
      &gens.gens_pc,
      transcript,
      &rx,
      &self.eval_error_at_rx,
      &PolyCommitment { C: vec![*comm_E] },
    )?;

    let poly_input_eval = {
      // constant term
      let mut input_as_sparse_poly_entries = vec![SparsePolyEntry::new(0, *u)];
      //remaining inputs
      input_as_sparse_poly_entries.extend(
        (0..input.len())
          .map(|i| SparsePolyEntry::new(i + 1, input[i]))
          .collect::<Vec<SparsePolyEntry<G::ScalarField>>>(),
      );
      SparsePolynomial::new(n.log_2() as usize, input_as_sparse_poly_entries).evaluate(&ry[1..])
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
