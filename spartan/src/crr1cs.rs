use ark_ec::CurveGroup;
use ark_ff::PrimeField;
use ark_std::{cmp::max, test_rng, One, UniformRand, Zero};

use super::polycommitments::{PolyCommitmentScheme, VectorCommitmentScheme};
use crate::{
  committed_relaxed_snark::SNARKGens, dense_mlpoly::DensePolynomial, errors::R1CSError, math::Math,
  InputsAssignment, Instance, VarsAssignment,
};

pub struct CRR1CSKey<G: CurveGroup, PC: PolyCommitmentScheme<G>> {
  pub pc_commit_key: PC::PolyCommitmentKey,
  pub pc_verify_key: PC::EvalVerifierKey,
}

impl<G: CurveGroup, PC: PolyCommitmentScheme<G>> CRR1CSKey<G, PC> {
  pub fn new(SRS: &PC::SRS, num_cons: usize, num_vars: usize) -> Self {
    // Since we have commitments both to the witness and the error vectors
    // we need the commitment key to hold the larger of the two
    let n = max(num_cons, num_vars);
    let (pc_commit_key, pc_verify_key) = PC::trim(SRS, n.log_2());
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

#[derive(Clone)]
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

  // similarly we might need to pad the error vector
  let padded_E = {
    let num_padded_cons = inst.inst.get_num_cons();
    let num_cons = E.len();
    if num_padded_cons > num_cons {
      let mut padded_E = E.clone();
      padded_E.resize(num_padded_cons, G::ScalarField::zero());
      padded_E
    } else {
      E.clone()
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
  assert_eq!(padded_E.len(), num_cons);
  let res: usize = (0..num_cons)
    .map(|i| {
      if Az[i] * Bz[i] == *u * Cz[i] + padded_E[i] {
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
  SNARKGens<G, PC>,
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
  let gens = SNARKGens::<G, PC>::new(&SRS, num_cons, num_vars, num_inputs, num_cons);
  let comm_W = <PC as VectorCommitmentScheme<G>>::commit(
    vars.assignment.as_slice(),
    &gens.gens_r1cs_sat.pc_commit_key,
  );
  let comm_E =
    <PC as VectorCommitmentScheme<G>>::commit(E.as_slice(), &gens.gens_r1cs_sat.pc_commit_key);
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
    gens,
  )
}
