//! Common setup methods used for tests.

use ark_ec::short_weierstrass::{Projective, SWCurveConfig};
use ark_ff::PrimeField;
use ark_r1cs_std::{
    fields::{fp::FpVar, FieldVar},
    prelude::{AllocVar, EqGadget},
    R1CSVar,
};
use ark_relations::r1cs::{
    ConstraintSynthesizer, ConstraintSystem, ConstraintSystemRef, SynthesisError, SynthesisMode,
};
use ark_spartan::polycommitments::{PolyCommitmentScheme, PCSKeys};
use ark_std::rand::RngCore;

use super::{
    commitment::CommitmentScheme,
    r1cs::{R1CSInstance, R1CSShape, R1CSWitness},
    ccs::{CCSInstance, CCSShape, CCSWitness},
};

/// Circuit with a single public input `y`, which enforces `x**3 + x + 5 == y`.
struct CubicCircuit {
    x: u64,
}

impl<F: PrimeField> ConstraintSynthesizer<F> for CubicCircuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<F>) -> Result<(), SynthesisError> {
        let x_to_field = F::from(self.x);
        let x = FpVar::new_witness(ark_relations::ns!(cs, "x"), || Ok(x_to_field))?;
        let x_square = x.square()?;
        let x_cube = x_square * &x;

        let left: FpVar<F> = [&x_cube, &x, &FpVar::Constant(5u64.into())]
            .into_iter()
            .sum();

        let y = FpVar::new_input(ark_relations::ns!(cs, "y"), || left.value())?;
        left.enforce_equal(&y)?;

        Ok(())
    }
}

pub fn setup_test_r1cs<G, C>(
    x: u64,
    pp: Option<&C::PP>,
    aux: &C::SetupAux,
) -> (
    R1CSShape<Projective<G>>,
    R1CSInstance<Projective<G>, C>,
    R1CSWitness<Projective<G>>,
    C::PP,
)
where
    G: SWCurveConfig,
    G::BaseField: PrimeField,
    C: CommitmentScheme<Projective<G>>,
    C::Commitment: Into<Projective<G>>,
    C::PP: Clone,
{
    let circuit = CubicCircuit { x };

    let cs = ConstraintSystem::<G::ScalarField>::new_ref();
    cs.set_mode(SynthesisMode::Prove { construct_matrices: true });

    circuit.generate_constraints(cs.clone()).unwrap();
    assert!(cs.is_satisfied().unwrap());

    cs.finalize();
    let shape = R1CSShape::<Projective<G>>::from(cs.clone());

    let cs_borrow = cs.borrow().unwrap();
    let W = cs_borrow.witness_assignment.clone();
    let X = cs_borrow.instance_assignment.clone();
    let pp = pp.cloned().unwrap_or_else(|| {
        C::setup(
            cs_borrow.num_witness_variables + cs_borrow.num_constraints,
            aux,
        )
    });
    let w = R1CSWitness::<Projective<G>> { W };

    let commitment_W = w.commit::<C>(&pp);
    let u = R1CSInstance { commitment_W, X };

    assert!(shape.is_satisfied(&u, &w, &pp).is_ok());
    (shape, u, w, pp)
}

pub fn setup_test_ccs<G, C>(
    x: u64,
    ck: Option<&C::PolyCommitmentKey>,
    rng: Option<&mut impl RngCore>,
) -> (
    CCSShape<Projective<G>>,
    CCSInstance<Projective<G>, C>,
    CCSWitness<Projective<G>>,
    C::PolyCommitmentKey,
)
where
    G: SWCurveConfig,
    G::BaseField: PrimeField,
    C: PolyCommitmentScheme<Projective<G>>,
    C::PolyCommitmentKey: Clone,
{
    let circuit = CubicCircuit { x };

    let cs = ConstraintSystem::<G::ScalarField>::new_ref();
    cs.set_mode(SynthesisMode::Prove { construct_matrices: true });

    circuit.generate_constraints(cs.clone()).unwrap();
    assert!(cs.is_satisfied().unwrap());

    cs.finalize();
    let shape = CCSShape::from(R1CSShape::<Projective<G>>::from(cs.clone()));

    let cs_borrow = cs.borrow().unwrap();
    let W = cs_borrow.witness_assignment.clone();
    let X = cs_borrow.instance_assignment.clone();

    let num_vars = (W.len() + X.len()).next_power_of_two();
    let ck = ck.cloned().unwrap_or_else(|| {
        let SRS = C::setup(num_vars, b"test", rng.unwrap()).unwrap();
        let PCSKeys { ck, .. } = C::trim(&SRS, num_vars);
        ck
    });
    let w = CCSWitness::<Projective<G>> { W };

    let commitment_W = w.commit::<C>(&ck);
    let u = CCSInstance { commitment_W, X };

    assert!(shape.is_satisfied(&u, &w, &ck).is_ok());
    (shape, u, w, ck)
}
