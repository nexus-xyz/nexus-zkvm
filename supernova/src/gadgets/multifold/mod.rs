#![deny(unsafe_code)]

use ark_crypto_primitives::sponge::constraints::{CryptographicSpongeVar, SpongeWithGadget};
use ark_ec::short_weierstrass::{Projective, SWCurveConfig};
use ark_ff::PrimeField;
use ark_r1cs_std::{
    boolean::Boolean,
    eq::EqGadget,
    fields::{fp::FpVar, nonnative::NonNativeFieldVar},
    R1CSVar, ToBytesGadget, ToConstraintFieldGadget,
};
use ark_relations::r1cs::SynthesisError;

use crate::{commitment::CommitmentScheme, multifold::nimfs::SQUEEZE_ELEMENTS_BIT_SIZE};

mod nonnative;

pub(crate) mod primary;
pub(crate) mod secondary;

pub use nonnative::NonNativeAffineVar;

/// Mirror of [`cast_field_element_unique`](crate::utils::cast_field_element_unique) for allocated input.
pub fn cast_field_element_unique<F1, F2>(
    f1: &NonNativeFieldVar<F1, F2>,
) -> Result<Vec<FpVar<F2>>, SynthesisError>
where
    F1: PrimeField,
    F2: PrimeField,
{
    f1.to_bytes()?.to_constraint_field()
}

pub fn multifold<G1, G2, C1, C2, RO>(
    config: &<RO::Var as CryptographicSpongeVar<G1::ScalarField, RO>>::Parameters,
    vk: &FpVar<G1::ScalarField>,
    U: &primary::RelaxedR1CSInstanceVar<G1, C1>,
    U_secondary: &secondary::RelaxedR1CSInstanceVar<G2, C2>,
    u: &primary::R1CSInstanceVar<G1, C1>,
    commitment_T: &NonNativeAffineVar<G1>,
    proof_secondary: (&secondary::ProofVar<G2, C2>, &secondary::ProofVar<G2, C2>),
) -> Result<
    (
        primary::RelaxedR1CSInstanceVar<G1, C1>,
        secondary::RelaxedR1CSInstanceVar<G2, C2>,
    ),
    SynthesisError,
>
where
    G1: SWCurveConfig<BaseField = G2::ScalarField, ScalarField = G2::BaseField>,
    G2: SWCurveConfig,
    C1: CommitmentScheme<Projective<G1>, Commitment = Projective<G1>>,
    C2: CommitmentScheme<Projective<G2>, Commitment = Projective<G2>>,
    G1::BaseField: PrimeField,
    G2::BaseField: PrimeField,
    RO: SpongeWithGadget<G1::ScalarField>,
{
    let cs = U.cs();
    let mut random_oracle = RO::Var::new(cs.clone(), config);

    random_oracle.absorb(&vk)?;
    random_oracle.absorb(&U)?;
    random_oracle.absorb(&u)?;
    random_oracle.absorb(&U_secondary)?;
    random_oracle.absorb(&commitment_T)?;

    let (r_0, r_0_bits) = random_oracle
        .squeeze_nonnative_field_elements_with_sizes::<G2::ScalarField>(&[
            SQUEEZE_ELEMENTS_BIT_SIZE,
        ])?;
    let r_0 = &r_0[0];
    let r_0_bits = &r_0_bits[0];
    let r_0_scalar = Boolean::le_bits_to_fp_var(r_0_bits)?;

    let secondary::ProofVar {
        U: comm_E_proof,
        commitment_T: _commitment_T,
    } = &proof_secondary.0;
    let pub_io = comm_E_proof.parse_io::<G1>()?;
    pub_io.r.enforce_equal(r_0)?;
    pub_io.g1.enforce_equal(&U.commitment_E)?;
    pub_io.g2.enforce_equal(commitment_T)?;

    let commitment_E = pub_io.g_out;

    random_oracle.absorb(comm_E_proof)?;
    random_oracle.absorb(&_commitment_T)?;
    random_oracle.absorb(&r_0_scalar)?;

    let (r_1, r_1_bits) = random_oracle
        .squeeze_nonnative_field_elements_with_sizes::<G2::ScalarField>(&[
            SQUEEZE_ELEMENTS_BIT_SIZE,
        ])?;
    let r_1 = &r_1[0];
    let r_1_bits = &r_1_bits[0];

    let secondary::ProofVar {
        U: comm_W_proof,
        commitment_T: __commitment_T,
    } = &proof_secondary.1;
    let pub_io = comm_W_proof.parse_io::<G1>()?;
    pub_io.r.enforce_equal(r_0)?;
    pub_io.g1.enforce_equal(&U.commitment_W)?;
    pub_io.g2.enforce_equal(&u.commitment_W)?;

    let commitment_W = pub_io.g_out;
    random_oracle.absorb(comm_W_proof)?;
    random_oracle.absorb(&__commitment_T)?;
    random_oracle.absorb(&cast_field_element_unique::<G1::BaseField, G1::ScalarField>(r_1)?)?;

    let (r_2, r_2_bits) = random_oracle
        .squeeze_nonnative_field_elements_with_sizes::<G2::ScalarField>(&[
            SQUEEZE_ELEMENTS_BIT_SIZE,
        ])?;
    let r_2 = &r_2[0];
    let r_2_bits = &r_2_bits[0];

    let folded_U = primary::RelaxedR1CSInstanceVar::<G1, C1>::new(
        commitment_W,
        commitment_E,
        U.X.iter()
            .zip(&u.X)
            .map(|(a, b)| a + &r_0_scalar * b)
            .collect(),
    );

    let U_secondary = U_secondary.fold(&[
        (comm_E_proof, _commitment_T, r_1, r_1_bits),
        (comm_W_proof, __commitment_T, r_2, r_2_bits),
    ])?;

    Ok((folded_U, U_secondary))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        multifold::{
            nimfs::{NIMFSProof, RelaxedR1CSInstance, RelaxedR1CSWitness},
            secondary as multifold_secondary,
        },
        nifs::tests::synthesize_r1cs,
        pedersen::PedersenCommitment,
        poseidon_config,
    };
    use ark_crypto_primitives::sponge::{poseidon::PoseidonSponge, Absorb};

    use ark_ff::Field;
    use ark_r1cs_std::{fields::fp::FpVar, prelude::AllocVar, R1CSVar};
    use ark_relations::r1cs::ConstraintSystem;

    #[test]
    fn verify_in_circuit() {
        verify_in_circuit_with_cycle::<
            ark_pallas::PallasConfig,
            ark_vesta::VestaConfig,
            PedersenCommitment<ark_pallas::Projective>,
            PedersenCommitment<ark_vesta::Projective>,
        >()
        .unwrap();
    }

    fn verify_in_circuit_with_cycle<G1, G2, C1, C2>() -> Result<(), SynthesisError>
    where
        G1: SWCurveConfig<BaseField = G2::ScalarField, ScalarField = G2::BaseField>,
        G2: SWCurveConfig,
        C1: CommitmentScheme<Projective<G1>, Commitment = Projective<G1>>,
        C2: CommitmentScheme<Projective<G2>, Commitment = Projective<G2>>,
        G1::BaseField: PrimeField + Absorb,
        G2::BaseField: PrimeField + Absorb,
        C1::PP: Clone,
    {
        let config = poseidon_config();

        let vk = G1::ScalarField::ONE;

        let (shape, u, w, pp) = synthesize_r1cs::<G1, C1>(3, None);
        let shape_secondary = multifold_secondary::setup_shape::<G1, G2>()?;

        let pp_secondary = C2::setup(shape_secondary.num_vars + shape_secondary.num_constraints);

        let U = RelaxedR1CSInstance::<G1, C1>::new(&shape);
        let W = RelaxedR1CSWitness::<G1>::zero(&shape);

        let U_secondary = RelaxedR1CSInstance::<G2, C2>::new(&shape_secondary);
        let W_secondary = RelaxedR1CSWitness::<G2>::zero(&shape_secondary);

        let (proof, (folded_U, folded_W), (folded_U_secondary, folded_W_secondary)) =
            NIMFSProof::<_, _, _, _, PoseidonSponge<G1::ScalarField>>::prove(
                &pp,
                &pp_secondary,
                &config,
                &vk,
                (&shape, &shape_secondary),
                (&U, &W),
                (&U_secondary, &W_secondary),
                (&u, &w),
            )
            .unwrap();

        let cs = ConstraintSystem::<G1::ScalarField>::new_ref();
        let U_cs = primary::RelaxedR1CSInstanceVar::<G1, C1>::new_input(cs.clone(), || Ok(&U))?;
        let U_secondary_cs =
            secondary::RelaxedR1CSInstanceVar::<G2, C2>::new_input(cs.clone(), || {
                Ok(&U_secondary)
            })?;
        let u_cs = primary::R1CSInstanceVar::<G1, C1>::new_input(cs.clone(), || Ok(&u))?;

        let commitment_T_cs = NonNativeAffineVar::new_input(cs.clone(), || Ok(proof.commitment_T))?;

        let comm_E_proof = &proof.commitment_E_proof;
        let comm_W_proof = &proof.commitment_W_proof;

        let vk_cs = FpVar::new_input(cs.clone(), || Ok(vk))?;
        let comm_E_proof =
            secondary::ProofVar::<G2, C2>::new_input(cs.clone(), || Ok(comm_E_proof))?;
        let comm_W_proof =
            secondary::ProofVar::<G2, C2>::new_input(cs.clone(), || Ok(comm_W_proof))?;
        let proof_cs = (&comm_E_proof, &comm_W_proof);

        let (_U_cs, _U_secondary_cs) = multifold::<G1, G2, C1, C2, PoseidonSponge<G1::ScalarField>>(
            &config,
            &vk_cs,
            &U_cs,
            &U_secondary_cs,
            &u_cs,
            &commitment_T_cs,
            proof_cs,
        )?;

        let _U = _U_cs.value()?;
        let _U_secondary = _U_secondary_cs.value()?;

        assert_eq!(_U, folded_U);
        shape.is_relaxed_satisfied(&_U, &folded_W, &pp).unwrap();

        assert_eq!(_U_secondary, folded_U_secondary);
        shape_secondary
            .is_relaxed_satisfied(&_U_secondary, &folded_W_secondary, &pp_secondary)
            .unwrap();

        assert!(cs.is_satisfied().unwrap());

        // another round.
        let (_, u, w, _) = synthesize_r1cs::<G1, C1>(5, Some(&pp));

        let (proof, (folded_U_2, folded_W_2), (folded_U_secondary_2, folded_W_secondary_2)) =
            NIMFSProof::<_, _, _, _, PoseidonSponge<G1::ScalarField>>::prove(
                &pp,
                &pp_secondary,
                &config,
                &vk,
                (&shape, &shape_secondary),
                (&folded_U, &folded_W),
                (&folded_U_secondary, &folded_W_secondary),
                (&u, &w),
            )
            .unwrap();

        let cs = ConstraintSystem::<G1::ScalarField>::new_ref();
        let U_cs =
            primary::RelaxedR1CSInstanceVar::<G1, C1>::new_input(cs.clone(), || Ok(&folded_U))?;
        let U_secondary_cs =
            secondary::RelaxedR1CSInstanceVar::<G2, C2>::new_input(cs.clone(), || {
                Ok(&folded_U_secondary)
            })?;
        let u_cs = primary::R1CSInstanceVar::<G1, C1>::new_input(cs.clone(), || Ok(&u))?;

        let commitment_T_cs = NonNativeAffineVar::new_input(cs.clone(), || Ok(proof.commitment_T))?;

        let comm_E_proof = &proof.commitment_E_proof;
        let comm_W_proof = &proof.commitment_W_proof;

        let vk_cs = FpVar::new_input(cs.clone(), || Ok(vk))?;
        let comm_E_proof =
            secondary::ProofVar::<G2, C2>::new_input(cs.clone(), || Ok(comm_E_proof))?;
        let comm_W_proof =
            secondary::ProofVar::<G2, C2>::new_input(cs.clone(), || Ok(comm_W_proof))?;
        let proof_cs = (&comm_E_proof, &comm_W_proof);

        let (_U_cs, _U_secondary_cs) = multifold::<G1, G2, C1, C2, PoseidonSponge<G1::ScalarField>>(
            &config,
            &vk_cs,
            &U_cs,
            &U_secondary_cs,
            &u_cs,
            &commitment_T_cs,
            proof_cs,
        )?;

        let _U = _U_cs.value()?;
        let _U_secondary = _U_secondary_cs.value()?;

        assert_eq!(_U, folded_U_2);
        shape.is_relaxed_satisfied(&_U, &folded_W_2, &pp).unwrap();

        assert_eq!(_U_secondary, folded_U_secondary_2);
        shape_secondary
            .is_relaxed_satisfied(&_U_secondary, &folded_W_secondary_2, &pp_secondary)
            .unwrap();

        assert!(cs.is_satisfied().unwrap());

        Ok(())
    }
}
