#![allow(unused)]

use std::marker::PhantomData;

use ark_crypto_primitives::sponge::{Absorb, CryptographicSponge, FieldElementSize};
use ark_ec::{CurveGroup, PrimeGroup};
use ark_ff::{PrimeField, ToConstraintField};

use super::{
    absorb::{AbsorbNonNative, CryptographicSpongeExt},
    commitment::CommitmentScheme,
    r1cs::{self, R1CSInstance, R1CSShape, R1CSWitness, RelaxedR1CSInstance, RelaxedR1CSWitness},
};

pub const SQUEEZE_ELEMENTS_BIT_SIZE: FieldElementSize = FieldElementSize::Truncated(250);

pub struct NIFSProof<G: PrimeGroup, C: CommitmentScheme<G>, RO> {
    pub(crate) commitment_T: C::Commitment,
    _random_oracle: PhantomData<RO>,
}

impl<G: PrimeGroup, C: CommitmentScheme<G>, RO> NIFSProof<G, C, RO> {
    pub(crate) fn new() -> Self {
        Self {
            commitment_T: C::Commitment::default(),
            _random_oracle: PhantomData,
        }
    }
}

impl<G: PrimeGroup, C: CommitmentScheme<G>, RO> Clone for NIFSProof<G, C, RO> {
    fn clone(&self) -> Self {
        Self {
            commitment_T: self.commitment_T,
            _random_oracle: self._random_oracle,
        }
    }
}

impl<G, C, RO> NIFSProof<G, C, RO>
where
    G: CurveGroup + AbsorbNonNative<G::ScalarField>,
    C: CommitmentScheme<G, Commitment = G>,
    G::BaseField: PrimeField + Absorb,
    G::ScalarField: Absorb,
    G::Affine: Absorb + ToConstraintField<G::BaseField>,
    RO: CryptographicSponge,
{
    pub fn prove_with_relaxed(
        pp: &C::PP,
        random_oracle: &mut RO,
        shape: &R1CSShape<G>,
        (U1, W1): (&RelaxedR1CSInstance<G, C>, &RelaxedR1CSWitness<G>),
        (U2, W2): (&RelaxedR1CSInstance<G, C>, &RelaxedR1CSWitness<G>),
    ) -> Result<(Self, (RelaxedR1CSInstance<G, C>, RelaxedR1CSWitness<G>)), r1cs::Error> {
        random_oracle.absorb_non_native(&U1);
        random_oracle.absorb_non_native(&U2);

        let (T, commitment_T) = r1cs::commit_T_with_relaxed(shape, pp, U1, W1, U2, W2)?;

        random_oracle.absorb(&commitment_T.into_affine());

        let r = random_oracle.squeeze_field_elements_with_sizes(&[SQUEEZE_ELEMENTS_BIT_SIZE])[0];

        let U = U1.fold_with_relaxed(U2, &commitment_T, &r)?;
        let W = W1.fold_with_relaxed(W2, &T, &r)?;

        Ok((
            Self {
                commitment_T,
                _random_oracle: PhantomData,
            },
            (U, W),
        ))
    }

    #[cfg(test)]
    pub fn verify_with_relaxed(
        &self,
        random_oracle: &mut RO,
        U1: &RelaxedR1CSInstance<G, C>,
        U2: &RelaxedR1CSInstance<G, C>,
    ) -> Result<RelaxedR1CSInstance<G, C>, r1cs::Error> {
        random_oracle.absorb_non_native(&U1);
        random_oracle.absorb_non_native(&U2);

        random_oracle.absorb(&self.commitment_T.into_affine());

        let r = random_oracle.squeeze_field_elements_with_sizes(&[SQUEEZE_ELEMENTS_BIT_SIZE])[0];

        let U = U1.fold_with_relaxed(U2, &self.commitment_T, &r)?;

        Ok(U)
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::poseidon_config;
    use crate::{pedersen::PedersenCommitment, r1cs::*, utils::to_sparse};
    use ark_crypto_primitives::sponge::poseidon::PoseidonSponge;
    use ark_ec::short_weierstrass::{Projective, SWCurveConfig};
    use ark_ff::AdditiveGroup;
    use ark_r1cs_std::{
        fields::{fp::FpVar, FieldVar},
        prelude::{AllocVar, EqGadget},
        R1CSVar,
    };
    use ark_relations::r1cs::*;
    use ark_test_curves::bls12_381::{Fq as Base, Fr as Scalar, G1Projective as G};

    struct CubicEquation {
        x: u64,
    }

    impl<F: PrimeField> ConstraintSynthesizer<F> for CubicEquation {
        fn generate_constraints(self, cs: ConstraintSystemRef<F>) -> Result<()> {
            let x_to_field = F::from(F::BigInt::from(self.x));
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

    pub(crate) fn synthesize_r1cs<G, C>(
        x: u64,
        pp: Option<&C::PP>,
    ) -> (
        R1CSShape<Projective<G>>,
        R1CSInstance<Projective<G>, C>,
        R1CSWitness<Projective<G>>,
        C::PP,
    )
    where
        G: SWCurveConfig,
        G::BaseField: PrimeField,
        C: CommitmentScheme<Projective<G>, Commitment = Projective<G>>,
        C::PP: Clone,
    {
        let circuit = CubicEquation { x };

        let cs = ConstraintSystem::<G::ScalarField>::new_ref();
        circuit
            .generate_constraints(cs.clone())
            .expect("failed to generate constraints");
        let is_satisfied = cs.is_satisfied().expect("cs is in setup mode");

        assert!(is_satisfied);

        cs.finalize();
        let matrices = cs.to_matrices().expect("setup finished");

        let cs_borrow = cs.borrow().unwrap();
        let shape = R1CSShape::<Projective<G>>::new(
            cs_borrow.num_constraints,
            cs_borrow.num_witness_variables,
            cs_borrow.num_instance_variables,
            &to_sparse::<G::ScalarField>(&matrices.a),
            &to_sparse::<G::ScalarField>(&matrices.b),
            &to_sparse::<G::ScalarField>(&matrices.c),
        )
        .expect("shape is valid");

        let W = cs_borrow.witness_assignment.clone();
        let X = cs_borrow.instance_assignment.clone();

        let pp = pp.cloned().unwrap_or_else(|| {
            C::setup(cs_borrow.num_witness_variables + cs_borrow.num_instance_variables)
        });
        let commitment_W = C::commit(&pp, &W);

        let instance = R1CSInstance::new(&shape, &commitment_W, &X).expect("shape is valid");
        let witness = R1CSWitness::new(&shape, &W).expect("witness shape is valid");

        shape
            .is_satisfied(&instance, &witness, &pp)
            .expect("instance is satisfied");

        (shape, instance, witness, pp)
    }

    #[test]
    fn prove_verify() {
        let config = poseidon_config::<Base>();

        let (shape, U2, W2, pp) = synthesize_r1cs(3, None);

        let U1 = RelaxedR1CSInstance::<G, PedersenCommitment<G>>::new(&shape);
        let W1 = RelaxedR1CSWitness::zero(&shape);

        let U2 = RelaxedR1CSInstance::from(&U2);
        let W2 = RelaxedR1CSWitness::from_r1cs_witness(&shape, &W2);

        let mut random_oracle = PoseidonSponge::new(&config);

        let (proof, (folded_U, folded_W)) =
            NIFSProof::prove_with_relaxed(&pp, &mut random_oracle, &shape, (&U1, &W1), (&U2, &W2))
                .unwrap();

        let mut random_oracle = PoseidonSponge::new(&config);
        let v_folded_U = proof
            .verify_with_relaxed(&mut random_oracle, &U1, &U2)
            .unwrap();
        assert_eq!(folded_U, v_folded_U);

        assert!(shape
            .is_relaxed_satisfied(&folded_U, &folded_W, &pp)
            .is_ok());

        let U1 = folded_U;
        let W1 = folded_W;

        let (_, U2, W2, _) = synthesize_r1cs(5, Some(&pp));
        let U2 = RelaxedR1CSInstance::from(&U2);
        let W2 = RelaxedR1CSWitness::from_r1cs_witness(&shape, &W2);

        let mut random_oracle = PoseidonSponge::new(&config);
        let (proof, (folded_U, folded_W)) =
            NIFSProof::prove_with_relaxed(&pp, &mut random_oracle, &shape, (&U1, &W1), (&U2, &W2))
                .unwrap();

        let mut random_oracle = PoseidonSponge::new(&config);
        let v_folded_U = proof
            .verify_with_relaxed(&mut random_oracle, &U1, &U2)
            .unwrap();
        assert_eq!(folded_U, v_folded_U);

        assert!(shape
            .is_relaxed_satisfied(&folded_U, &folded_W, &pp)
            .is_ok());
    }
}
