#![allow(clippy::too_many_arguments)]
use super::commitments::{Commitments, MultiCommitGens};
use super::dense_mlpoly::{
  DensePolynomial, EqPolynomial, PolyCommitment, PolyCommitmentGens, PolyEvalProof,
};
use super::errors::ProofVerifyError;
use super::math::Math;
use super::nizk::{EqualityProof, KnowledgeProof, ProductProof};
use super::r1csinstance::R1CSInstance;
use super::random::RandomTape;
use super::sparse_mlpoly::{SparsePolyEntry, SparsePolynomial};
use super::sumcheck::ZKSumcheckInstanceProof;
use super::timer::Timer;
use super::transcript::{AppendToTranscript, ProofTranscript};
use ark_ec::CurveGroup;
use ark_ec::VariableBaseMSM;
use ark_serialize::*;
use ark_std::{One, Zero};
use merlin::Transcript;

#[derive(CanonicalSerialize, CanonicalDeserialize, Debug)]
pub struct R1CSProof<G: CurveGroup> {
  comm_vars: PolyCommitment<G>,
  sc_proof_phase1: ZKSumcheckInstanceProof<G>,
  claims_phase2: (G, G, G, G),
  pok_claims_phase2: (KnowledgeProof<G>, ProductProof<G>),
  proof_eq_sc_phase1: EqualityProof<G>,
  sc_proof_phase2: ZKSumcheckInstanceProof<G>,
  comm_vars_at_ry: G,
  proof_eval_vars_at_ry: PolyEvalProof<G>,
  proof_eq_sc_phase2: EqualityProof<G>,
}

pub struct R1CSSumcheckGens<G>
where
  G: CurveGroup,
{
  gens_1: MultiCommitGens<G>,
  gens_3: MultiCommitGens<G>,
  gens_4: MultiCommitGens<G>,
}

// TODO: fix passing gens_1_ref
impl<G: CurveGroup> R1CSSumcheckGens<G> {
  pub fn new(label: &'static [u8], gens_1_ref: &MultiCommitGens<G>) -> Self {
    let gens_1 = gens_1_ref.clone();
    let gens_3 = MultiCommitGens::new(3, label);
    let gens_4 = MultiCommitGens::new(4, label);

    R1CSSumcheckGens {
      gens_1,
      gens_3,
      gens_4,
    }
  }
}

pub struct R1CSGens<G>
where
  G: CurveGroup,
{
  gens_sc: R1CSSumcheckGens<G>,
  gens_pc: PolyCommitmentGens<G>,
}

impl<G: CurveGroup> R1CSGens<G> {
  pub fn new(label: &'static [u8], _num_cons: usize, num_vars: usize) -> Self {
    let num_poly_vars = num_vars.log_2();
    let gens_pc = PolyCommitmentGens::new(num_poly_vars, label);
    let gens_sc = R1CSSumcheckGens::new(label, &gens_pc.gens.gens_1);
    R1CSGens { gens_sc, gens_pc }
  }
}

impl<G: CurveGroup> R1CSProof<G> {
  #[allow(clippy::type_complexity)]
  fn prove_phase_one(
    num_rounds: usize,
    evals_tau: &mut DensePolynomial<G::ScalarField>,
    evals_Az: &mut DensePolynomial<G::ScalarField>,
    evals_Bz: &mut DensePolynomial<G::ScalarField>,
    evals_Cz: &mut DensePolynomial<G::ScalarField>,
    gens: &R1CSSumcheckGens<G>,
    transcript: &mut Transcript,
    random_tape: &mut RandomTape<G>,
  ) -> (
    ZKSumcheckInstanceProof<G>,
    Vec<G::ScalarField>,
    Vec<G::ScalarField>,
    G::ScalarField,
  ) {
    let comb_func =
      |poly_A_comp: &G::ScalarField,
       poly_B_comp: &G::ScalarField,
       poly_C_comp: &G::ScalarField,
       poly_D_comp: &G::ScalarField|
       -> G::ScalarField { *poly_A_comp * (*poly_B_comp * *poly_C_comp - *poly_D_comp) };

    let (sc_proof_phase_one, r, claims, blind_claim_postsc) =
      ZKSumcheckInstanceProof::prove_cubic_with_additive_term(
        &G::ScalarField::zero(), // claim is zero
        &G::ScalarField::zero(), // blind for claim is also zero
        num_rounds,
        evals_tau,
        evals_Az,
        evals_Bz,
        evals_Cz,
        comb_func,
        &gens.gens_1,
        &gens.gens_4,
        transcript,
        random_tape,
      );

    (sc_proof_phase_one, r, claims, blind_claim_postsc)
  }

  #[allow(clippy::type_complexity)]
  fn prove_phase_two(
    num_rounds: usize,
    claim: &G::ScalarField,
    blind_claim: &G::ScalarField,
    evals_z: &mut DensePolynomial<G::ScalarField>,
    evals_ABC: &mut DensePolynomial<G::ScalarField>,
    gens: &R1CSSumcheckGens<G>,
    transcript: &mut Transcript,
    random_tape: &mut RandomTape<G>,
  ) -> (
    ZKSumcheckInstanceProof<G>,
    Vec<G::ScalarField>,
    Vec<G::ScalarField>,
    G::ScalarField,
  ) {
    let comb_func = |poly_A_comp: &G::ScalarField,
                     poly_B_comp: &G::ScalarField|
     -> G::ScalarField { *poly_A_comp * *poly_B_comp };
    let (sc_proof_phase_two, r, claims, blind_claim_postsc) = ZKSumcheckInstanceProof::prove_quad(
      claim,
      blind_claim,
      num_rounds,
      evals_z,
      evals_ABC,
      comb_func,
      &gens.gens_1,
      &gens.gens_3,
      transcript,
      random_tape,
    );

    (sc_proof_phase_two, r, claims, blind_claim_postsc)
  }

  fn protocol_name() -> &'static [u8] {
    b"R1CS proof"
  }

  pub fn prove(
    inst: &R1CSInstance<G::ScalarField>,
    vars: Vec<G::ScalarField>,
    input: &[G::ScalarField],
    gens: &R1CSGens<G>,
    transcript: &mut Transcript,
    random_tape: &mut RandomTape<G>,
  ) -> (R1CSProof<G>, Vec<G::ScalarField>, Vec<G::ScalarField>) {
    let timer_prove = Timer::new("R1CSProof::prove");
    <Transcript as ProofTranscript<G>>::append_protocol_name(
      transcript,
      R1CSProof::<G>::protocol_name(),
    );

    // we currently require the number of |inputs| + 1 to be at most number of vars
    assert!(input.len() < vars.len());
    <Transcript as ProofTranscript<G>>::append_scalars(transcript, b"input", input);
    let timer_commit = Timer::new("polycommit");
    let (poly_vars, comm_vars, blinds_vars) = {
      // create a multilinear polynomial using the supplied assignment for variables
      let poly_vars = DensePolynomial::<G::ScalarField>::new(vars.clone());

      // produce a commitment to the satisfying assignment
      let (comm_vars, blinds_vars) = poly_vars.commit(&gens.gens_pc, Some(random_tape));

      // add the commitment to the prover's transcript
      comm_vars.append_to_transcript(b"poly_commitment", transcript);
      (poly_vars, comm_vars, blinds_vars)
    };
    timer_commit.stop();

    let timer_sc_proof_phase1 = Timer::new("prove_sc_phase_one");

    // append input to variables to create a single vector z
    let z = {
      let num_inputs = input.len();
      let num_vars = vars.len();
      let mut z = vars;
      z.extend(&vec![G::ScalarField::one()]); // add constant term in z
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

    let (sc_proof_phase1, rx, _claims_phase1, blind_claim_postsc1) = R1CSProof::prove_phase_one(
      num_rounds_x,
      &mut poly_tau,
      &mut poly_Az,
      &mut poly_Bz,
      &mut poly_Cz,
      &gens.gens_sc,
      transcript,
      random_tape,
    );
    assert_eq!(poly_tau.len(), 1);
    assert_eq!(poly_Az.len(), 1);
    assert_eq!(poly_Bz.len(), 1);
    assert_eq!(poly_Cz.len(), 1);
    timer_sc_proof_phase1.stop();

    let (tau_claim, Az_claim, Bz_claim, Cz_claim) =
      (&poly_tau[0], &poly_Az[0], &poly_Bz[0], &poly_Cz[0]);
    let (Az_blind, Bz_blind, Cz_blind, prod_Az_Bz_blind) = (
      random_tape.random_scalar(b"Az_blind"),
      random_tape.random_scalar(b"Bz_blind"),
      random_tape.random_scalar(b"Cz_blind"),
      random_tape.random_scalar(b"prod_Az_Bz_blind"),
    );

    let (pok_Cz_claim, comm_Cz_claim) = {
      KnowledgeProof::prove(
        &gens.gens_sc.gens_1,
        transcript,
        random_tape,
        Cz_claim,
        &Cz_blind,
      )
    };

    let (proof_prod, comm_Az_claim, comm_Bz_claim, comm_prod_Az_Bz_claims) = {
      let prod = *Az_claim * *Bz_claim;
      ProductProof::prove(
        &gens.gens_sc.gens_1,
        transcript,
        random_tape,
        Az_claim,
        &Az_blind,
        Bz_claim,
        &Bz_blind,
        &prod,
        &prod_Az_Bz_blind,
      )
    };

    <Transcript as ProofTranscript<G>>::append_point(transcript, b"comm_Az_claim", &comm_Az_claim);
    <Transcript as ProofTranscript<G>>::append_point(transcript, b"comm_Bz_claim", &comm_Bz_claim);
    <Transcript as ProofTranscript<G>>::append_point(transcript, b"comm_Cz_claim", &comm_Cz_claim);
    <Transcript as ProofTranscript<G>>::append_point(
      transcript,
      b"comm_prod_Az_Bz_claims",
      &comm_prod_Az_Bz_claims,
    );

    // prove the final step of sum-check #1
    let taus_bound_rx = tau_claim;
    let blind_expected_claim_postsc1 = *taus_bound_rx * (prod_Az_Bz_blind - Cz_blind);
    let claim_post_phase1 = (*Az_claim * *Bz_claim - *Cz_claim) * *taus_bound_rx;
    let (proof_eq_sc_phase1, _C1, _C2) = EqualityProof::prove(
      &gens.gens_sc.gens_1,
      transcript,
      random_tape,
      &claim_post_phase1,
      &blind_expected_claim_postsc1,
      &claim_post_phase1,
      &blind_claim_postsc1,
    );

    let timer_sc_proof_phase2 = Timer::new("prove_sc_phase_two");
    // combine the three claims into a single claim
    let r_A = <Transcript as ProofTranscript<G>>::challenge_scalar(transcript, b"challenege_Az");
    let r_B = <Transcript as ProofTranscript<G>>::challenge_scalar(transcript, b"challenege_Bz");
    let r_C = <Transcript as ProofTranscript<G>>::challenge_scalar(transcript, b"challenege_Cz");
    let claim_phase2 = r_A * Az_claim + r_B * Bz_claim + r_C * Cz_claim;
    let blind_claim_phase2 = r_A * Az_blind + r_B * Bz_blind + r_C * Cz_blind;

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
    let (sc_proof_phase2, ry, claims_phase2, blind_claim_postsc2) = R1CSProof::prove_phase_two(
      num_rounds_y,
      &claim_phase2,
      &blind_claim_phase2,
      &mut DensePolynomial::new(z),
      &mut DensePolynomial::new(evals_ABC),
      &gens.gens_sc,
      transcript,
      random_tape,
    );
    timer_sc_proof_phase2.stop();

    let timer_polyeval = Timer::new("polyeval");
    let eval_vars_at_ry = poly_vars.evaluate::<G>(&ry[1..]);
    let blind_eval = random_tape.random_scalar(b"blind_eval");
    let (proof_eval_vars_at_ry, comm_vars_at_ry) = PolyEvalProof::prove(
      &poly_vars,
      Some(&blinds_vars),
      &ry[1..],
      &eval_vars_at_ry,
      Some(&blind_eval),
      &gens.gens_pc,
      transcript,
      random_tape,
    );
    timer_polyeval.stop();

    // prove the final step of sum-check #2
    let blind_eval_Z_at_ry = (G::ScalarField::one() - ry[0]) * blind_eval;
    let blind_expected_claim_postsc2 = claims_phase2[1] * blind_eval_Z_at_ry;
    let claim_post_phase2 = claims_phase2[0] * claims_phase2[1];
    let (proof_eq_sc_phase2, _C1, _C2) = EqualityProof::prove(
      &gens.gens_pc.gens.gens_1,
      transcript,
      random_tape,
      &claim_post_phase2,
      &blind_expected_claim_postsc2,
      &claim_post_phase2,
      &blind_claim_postsc2,
    );

    timer_prove.stop();

    (
      R1CSProof {
        comm_vars,
        sc_proof_phase1,
        claims_phase2: (
          comm_Az_claim,
          comm_Bz_claim,
          comm_Cz_claim,
          comm_prod_Az_Bz_claims,
        ),
        pok_claims_phase2: (pok_Cz_claim, proof_prod),
        proof_eq_sc_phase1,
        sc_proof_phase2,
        comm_vars_at_ry,
        proof_eval_vars_at_ry,
        proof_eq_sc_phase2,
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
    evals: &(G::ScalarField, G::ScalarField, G::ScalarField),
    transcript: &mut Transcript,
    gens: &R1CSGens<G>,
  ) -> Result<(Vec<G::ScalarField>, Vec<G::ScalarField>), ProofVerifyError> {
    <Transcript as ProofTranscript<G>>::append_protocol_name(
      transcript,
      R1CSProof::<G>::protocol_name(),
    );

    <Transcript as ProofTranscript<G>>::append_scalars(transcript, b"input", input);

    let n = num_vars;
    // add the commitment to the verifier's transcript
    self
      .comm_vars
      .append_to_transcript(b"poly_commitment", transcript);

    let (num_rounds_x, num_rounds_y) = (num_cons.log_2(), (2 * num_vars).log_2());

    // derive the verifier's challenge tau
    let tau = <Transcript as ProofTranscript<G>>::challenge_vector(
      transcript,
      b"challenge_tau",
      num_rounds_x,
    );

    // verify the first sum-check instance
    let claim_phase1 = G::ScalarField::zero().commit(&G::ScalarField::zero(), &gens.gens_sc.gens_1);

    let (comm_claim_post_phase1, rx) = self.sc_proof_phase1.verify(
      &claim_phase1,
      num_rounds_x,
      3,
      &gens.gens_sc.gens_1,
      &gens.gens_sc.gens_4,
      transcript,
    )?;
    // perform the intermediate sum-check test with claimed Az, Bz, and Cz
    let (comm_Az_claim, comm_Bz_claim, comm_Cz_claim, comm_prod_Az_Bz_claims) = &self.claims_phase2;
    let (pok_Cz_claim, proof_prod) = &self.pok_claims_phase2;

    pok_Cz_claim.verify(&gens.gens_sc.gens_1, transcript, comm_Cz_claim)?;
    proof_prod.verify(
      &gens.gens_sc.gens_1,
      transcript,
      comm_Az_claim,
      comm_Bz_claim,
      comm_prod_Az_Bz_claims,
    )?;

    <Transcript as ProofTranscript<G>>::append_point(transcript, b"comm_Az_claim", comm_Az_claim);
    <Transcript as ProofTranscript<G>>::append_point(transcript, b"comm_Bz_claim", comm_Bz_claim);
    <Transcript as ProofTranscript<G>>::append_point(transcript, b"comm_Cz_claim", comm_Cz_claim);
    <Transcript as ProofTranscript<G>>::append_point(
      transcript,
      b"comm_prod_Az_Bz_claims",
      comm_prod_Az_Bz_claims,
    );

    let taus_bound_rx: G::ScalarField = (0..rx.len())
      .map(|i| rx[i] * tau[i] + (G::ScalarField::one() - rx[i]) * (G::ScalarField::one() - tau[i]))
      .product();
    let expected_claim_post_phase1 = (*comm_prod_Az_Bz_claims - *comm_Cz_claim) * taus_bound_rx;

    // verify proof that expected_claim_post_phase1 == claim_post_phase1
    self.proof_eq_sc_phase1.verify(
      &gens.gens_sc.gens_1,
      transcript,
      &expected_claim_post_phase1,
      &comm_claim_post_phase1,
    )?;

    // derive three public challenges and then derive a joint claim
    let r_A = <Transcript as ProofTranscript<G>>::challenge_scalar(transcript, b"challenege_Az");
    let r_B = <Transcript as ProofTranscript<G>>::challenge_scalar(transcript, b"challenege_Bz");
    let r_C = <Transcript as ProofTranscript<G>>::challenge_scalar(transcript, b"challenege_Cz");

    // r_A * comm_Az_claim + r_B * comm_Bz_claim + r_C * comm_Cz_claim;
    let scalars = vec![r_A, r_B, r_C];
    let bases = vec![*comm_Az_claim, *comm_Bz_claim, *comm_Cz_claim];

    let bases_affine = G::normalize_batch(bases.as_ref());

    let comm_claim_phase2 = VariableBaseMSM::msm(bases_affine.as_ref(), scalars.as_ref()).unwrap();

    // verify the joint claim with a sum-check protocol
    let (comm_claim_post_phase2, ry) = self.sc_proof_phase2.verify(
      &comm_claim_phase2,
      num_rounds_y,
      2,
      &gens.gens_sc.gens_1,
      &gens.gens_sc.gens_3,
      transcript,
    )?;

    // verify Z(ry) proof against the initial commitment
    self.proof_eval_vars_at_ry.verify(
      &gens.gens_pc,
      transcript,
      &ry[1..],
      &self.comm_vars_at_ry,
      &self.comm_vars,
    )?;

    let poly_input_eval = {
      // constant term
      let mut input_as_sparse_poly_entries = vec![SparsePolyEntry::new(0, G::ScalarField::one())];
      //remaining inputs
      input_as_sparse_poly_entries.extend(
        (0..input.len())
          .map(|i| SparsePolyEntry::new(i + 1, input[i]))
          .collect::<Vec<SparsePolyEntry<G::ScalarField>>>(),
      );
      SparsePolynomial::new(n.log_2(), input_as_sparse_poly_entries).evaluate(&ry[1..])
    };

    // compute commitment to eval_Z_at_ry = (F::one() - ry[0]) * self.eval_vars_at_ry + ry[0] * poly_input_eval
    let scalars = vec![(G::ScalarField::one() - ry[0]), ry[0]];

    let bases = vec![
      self.comm_vars_at_ry.into_affine(),
      poly_input_eval
        .commit(&G::ScalarField::zero(), &gens.gens_pc.gens.gens_1)
        .into_affine(),
    ];

    let comm_eval_Z_at_ry: G = VariableBaseMSM::msm(bases.as_ref(), scalars.as_ref()).unwrap();

    // perform the final check in the second sum-check protocol
    let (eval_A_r, eval_B_r, eval_C_r) = evals;
    let expected_claim_post_phase2 =
      comm_eval_Z_at_ry * (r_A * eval_A_r + r_B * eval_B_r + r_C * eval_C_r);

    // verify proof that expected_claim_post_phase1 == claim_post_phase1
    self.proof_eq_sc_phase2.verify(
      &gens.gens_sc.gens_1,
      transcript,
      &expected_claim_post_phase2,
      &comm_claim_post_phase2,
    )?;

    Ok((rx, ry))
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  use ark_bls12_381::Fr;
  use ark_bls12_381::G1Projective;
  use ark_ff::PrimeField;
  use ark_std::test_rng;

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
  pub fn check_r1cs_proof() {
    check_r1cs_proof_helper::<G1Projective>()
  }

  fn check_r1cs_proof_helper<G: CurveGroup>() {
    let num_vars = 1024;
    let num_cons = num_vars;
    let num_inputs = 10;
    let (inst, vars, input) =
      R1CSInstance::<G::ScalarField>::produce_synthetic_r1cs(num_cons, num_vars, num_inputs);

    let gens = R1CSGens::<G>::new(b"test-m", num_cons, num_vars);

    let mut random_tape = RandomTape::new(b"proof");
    let mut prover_transcript = Transcript::new(b"example");
    let (proof, rx, ry) = R1CSProof::prove(
      &inst,
      vars,
      &input,
      &gens,
      &mut prover_transcript,
      &mut random_tape,
    );

    let inst_evals = inst.evaluate(&rx, &ry);

    let mut verifier_transcript = Transcript::new(b"example");
    assert!(proof
      .verify(
        inst.get_num_vars(),
        inst.get_num_cons(),
        &input,
        &inst_evals,
        &mut verifier_transcript,
        &gens,
      )
      .is_ok());
  }
}
