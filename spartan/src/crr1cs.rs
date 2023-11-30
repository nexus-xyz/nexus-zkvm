use super::polycommitments::PolyCommitmentScheme;
use crate::{
  dense_mlpoly::DensePolynomial, errors::R1CSError, InputsAssignment, Instance, VarsAssignment,
};
use ark_ec::CurveGroup;
use ark_ff::PrimeField;
use ark_std::cmp::max;

pub struct CRR1CSKey<G: CurveGroup, PC: PolyCommitmentScheme<G>> {
  pub pc_commit_key: PC::PolyCommitmentKey,
  pub pc_verify_key: PC::EvalVerifierKey,
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

pub fn relaxed_r1cs_is_sat<G: CurveGroup, PC: PolyCommitmentScheme<G>>(
  shape: &CRR1CSShape<G::ScalarField>,
  instance: &CRR1CSInstance<G, PC>,
  witness: &CRR1CSWitness<G::ScalarField>,
) -> Result<bool, R1CSError> {
  let CRR1CSWitness { W, E } = witness;
  let CRR1CSInstance { input, u, .. } = instance;
  let CRR1CSShape { inst } = shape;

  if W.assignment.len() > inst.inst.get_num_vars() {
    return Err(R1CSError::InvalidNumberOfInputs);
  }

  if input.assignment.len() != inst.inst.get_num_inputs() {
    return Err(R1CSError::InvalidNumberOfInputs);
  }

  // we might need to pad variables
  let padded_vars = {
    let num_padded_vars = inst.inst.get_num_vars();
    let num_vars = W.assignment.len();
    if num_padded_vars > num_vars {
      W.pad(num_padded_vars)
    } else {
      W.clone()
    }
  };

  let (num_cons, num_vars, num_inputs) = (
    inst.inst.get_num_cons(),
    inst.inst.get_num_vars(),
    inst.inst.get_num_inputs(),
  );

  let z = {
    let mut z = padded_vars.assignment.to_vec();
    z.extend(&vec![*u]);
    z.extend(input.assignment.clone());
    z
  };

  // verify if Az * Bz - u * Cz = E
  let Az = inst
    .inst
    .A
    .multiply_vec(num_cons, num_vars + num_inputs + 1, &z);
  let Bz = inst
    .inst
    .B
    .multiply_vec(num_cons, num_vars + num_inputs + 1, &z);
  let Cz = inst
    .inst
    .C
    .multiply_vec(num_cons, num_vars + num_inputs + 1, &z);

  assert_eq!(Az.len(), num_cons);
  assert_eq!(Bz.len(), num_cons);
  assert_eq!(Cz.len(), num_cons);
  assert_eq!(E.len(), num_cons);
  let res: usize = (0..num_cons)
    .map(|i| {
      if Az[i] * Bz[i] == *u * Cz[i] + E[i] {
        0
      } else {
        1
      }
    })
    .sum();

  Ok(res == 0)
}

pub fn check_commitments<G: CurveGroup, PC: PolyCommitmentScheme<G>>(
  instance: &CRR1CSInstance<G, PC>,
  witness: &CRR1CSWitness<G::ScalarField>,
  key: &CRR1CSKey<G, PC>,
) -> bool {
  let CRR1CSWitness { W, E } = witness;
  let CRR1CSInstance { comm_W, comm_E, .. } = instance;

  let W = W.assignment.clone();
  let E = E.clone();

  let poly_W = DensePolynomial::new(W);
  let poly_E = DensePolynomial::new(E);

  let expected_comm_W = PC::commit(&poly_W, &key.pc_commit_key);
  let expected_comm_E = PC::commit(&poly_E, &key.pc_commit_key);

  expected_comm_W == *comm_W && expected_comm_E == *comm_E
}

pub fn is_sat<G: CurveGroup, PC: PolyCommitmentScheme<G>>(
  shape: &CRR1CSShape<G::ScalarField>,
  instance: &CRR1CSInstance<G, PC>,
  witness: &CRR1CSWitness<G::ScalarField>,
  key: &CRR1CSKey<G, PC>,
) -> Result<bool, R1CSError> {
  if !check_commitments(instance, witness, key) {
    return Ok(false);
  }
  relaxed_r1cs_is_sat(shape, instance, witness)
}
