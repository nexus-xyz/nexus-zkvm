use std::marker::PhantomData;

use ark_crypto_primitives::sponge::{Absorb, CryptographicSponge, FieldElementSize};
use ark_ec::{CurveGroup, Group};
use ark_ff::PrimeField;

use super::{
    commitment::CommitmentScheme,
    r1cs::{self, R1CSInstance, R1CSShape, R1CSWitness, RelaxedR1CSInstance, RelaxedR1CSWitness},
    utils,
};

pub const SQUEEZE_ELEMENTS_BIT_SIZE: FieldElementSize = FieldElementSize::Truncated(250);

pub struct NIFSProof<G: Group, C: CommitmentScheme<G>, RO> {
    pub(crate) commitment_T: C::Commitment,
    _random_oracle: PhantomData<RO>,
}

impl<G, C, RO> NIFSProof<G, C, RO>
where
    G: CurveGroup,
    C: CommitmentScheme<G, Commitment = G>,
    G::BaseField: PrimeField + Absorb,
    G::ScalarField: Absorb,
    G::Affine: Absorb,
    RO: CryptographicSponge,
{
    pub fn prove(
        pp: &C::PP,
        config: &RO::Config,
        pp_digest: &G::ScalarField,
        shape: &R1CSShape<G>,
        U1: &RelaxedR1CSInstance<G, C>,
        W1: &RelaxedR1CSWitness<G>,
        U2: &R1CSInstance<G, C>,
        W2: &R1CSWitness<G>,
    ) -> Result<(Self, (RelaxedR1CSInstance<G, C>, RelaxedR1CSWitness<G>)), r1cs::Error> {
        let mut random_oracle = RO::new(config);

        random_oracle.absorb(&utils::scalar_to_base::<G>(pp_digest));
        random_oracle.absorb(&U1);
        random_oracle.absorb(&U2);

        let (T, commitment_T) = r1cs::commit_T(shape, pp, U1, W1, U2, W2)?;

        random_oracle.absorb(&commitment_T.into_affine());

        let r = random_oracle.squeeze_field_elements_with_sizes(&[SQUEEZE_ELEMENTS_BIT_SIZE])[0];

        let U = U1.fold(U2, &commitment_T, &r)?;
        let W = W1.fold(W2, &T, &r)?;

        Ok((
            Self {
                commitment_T,
                _random_oracle: PhantomData,
            },
            (U, W),
        ))
    }

    pub fn verify(
        &self,
        config: &RO::Config,
        pp_digest: &G::ScalarField,
        U1: &RelaxedR1CSInstance<G, C>,
        U2: &R1CSInstance<G, C>,
    ) -> Result<RelaxedR1CSInstance<G, C>, r1cs::Error> {
        let mut random_oracle = RO::new(config);

        random_oracle.absorb(&utils::scalar_to_base::<G>(pp_digest));
        random_oracle.absorb(&U1);
        random_oracle.absorb(&U2);

        random_oracle.absorb(&self.commitment_T.into_affine());

        let r = random_oracle.squeeze_field_elements_with_sizes(&[SQUEEZE_ELEMENTS_BIT_SIZE])[0];

        let U = U1.fold(U2, &self.commitment_T, &r)?;

        Ok(U)
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::{pedersen::PedersenCommitment, r1cs::*};
    use ark_crypto_primitives::sponge::poseidon::{PoseidonConfig, PoseidonSponge};

    use ark_crypto_primitives::sponge::poseidon::find_poseidon_ark_and_mds;
    use ark_r1cs_std::{
        fields::{fp::FpVar, FieldVar},
        prelude::{AllocVar, EqGadget},
        R1CSVar,
    };
    use ark_relations::r1cs::*;
    use ark_test_curves::bls12_381::{Fq, Fr as Scalar, G1Projective as G};

    type CommitmentKey = <PedersenCommitment<G> as CommitmentScheme<G>>::PP;

    fn to_sparse<G: Group>(matrix: &Matrix<G::ScalarField>) -> SparseMatrix<G::ScalarField> {
        let mut sparse = SparseMatrix::new();

        for i in 0..matrix.len() {
            for &(value, j) in &matrix[i] {
                sparse.push((i, j, value));
            }
        }

        sparse
    }

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

    pub(crate) fn synthesize_r1cs(
        x: u64,
        pp: Option<&CommitmentKey>,
    ) -> (
        R1CSShape<G>,
        R1CSInstance<G, PedersenCommitment<G>>,
        R1CSWitness<G>,
        CommitmentKey,
    ) {
        let circuit = CubicEquation { x };

        let cs = ConstraintSystem::<Scalar>::new_ref();
        circuit
            .generate_constraints(cs.clone())
            .expect("failed to generate constraints");
        let is_satisfied = cs.is_satisfied().expect("cs is in setup mode");

        assert!(is_satisfied);

        cs.finalize();
        let matrices = cs.to_matrices().expect("setup finished");

        let cs_borrow = cs.borrow().unwrap();
        let shape = R1CSShape::<G>::new(
            cs_borrow.num_constraints,
            cs_borrow.num_witness_variables,
            cs_borrow.num_instance_variables,
            &to_sparse::<G>(&matrices.a),
            &to_sparse::<G>(&matrices.b),
            &to_sparse::<G>(&matrices.c),
        )
        .expect("shape is valid");

        let W = cs_borrow.witness_assignment.clone();
        let X = cs_borrow.instance_assignment.clone();

        let pp = pp
            .cloned()
            .unwrap_or_else(|| PedersenCommitment::<G>::setup(cs_borrow.num_instance_variables));
        let commitment_W = PedersenCommitment::<G>::commit(&pp, &W);

        let instance = R1CSInstance::<G, PedersenCommitment<G>>::new(&shape, &commitment_W, &X)
            .expect("shape is valid");
        let witness = R1CSWitness::<G>::new(&shape, &W).expect("witness shape is valid");

        shape
            .is_satisfied(&instance, &witness, &pp)
            .expect("instance is satisfied");

        (shape, instance, witness, pp)
    }

    #[test]
    fn prove_verify() {
        let (ark, mds) =
            find_poseidon_ark_and_mds::<Fq>(Fq::MODULUS.const_num_bits() as u64, 2, 8, 43, 0);
        let config = PoseidonConfig {
            full_rounds: 8,
            partial_rounds: 43,
            alpha: 5,
            ark,
            mds,
            rate: 2,
            capacity: 1,
        };
        const PP_DIGEST: Scalar = Scalar::ZERO;

        let (shape, U1, W1, pp) = synthesize_r1cs(3, None);

        let relaxed_U = RelaxedR1CSInstance::<G, PedersenCommitment<G>>::new(&shape);
        let relaxed_W = RelaxedR1CSWitness::zero(&shape);

        let (nifs, (folded_U, folded_W)) = NIFSProof::<_, _, PoseidonSponge<Fq>>::prove(
            &pp, &config, &PP_DIGEST, &shape, &relaxed_U, &relaxed_W, &U1, &W1,
        )
        .unwrap();

        let v_folded_U = nifs.verify(&config, &PP_DIGEST, &relaxed_U, &U1).unwrap();
        assert_eq!(folded_U, v_folded_U);

        assert!(shape
            .is_relaxed_satisfied(&folded_U, &folded_W, &pp)
            .is_ok());

        let U1 = folded_U;
        let W1 = folded_W;

        let (_, U2, W2, _) = synthesize_r1cs(5, Some(&pp));

        let (nifs, (folded_U, folded_W)) = NIFSProof::<_, _, PoseidonSponge<Fq>>::prove(
            &pp, &config, &PP_DIGEST, &shape, &U1, &W1, &U2, &W2,
        )
        .unwrap();

        let v_folded_U = nifs.verify(&config, &PP_DIGEST, &U1, &U2).unwrap();
        assert_eq!(folded_U, v_folded_U);

        assert!(shape
            .is_relaxed_satisfied(&folded_U, &folded_W, &pp)
            .is_ok());
    }
}
