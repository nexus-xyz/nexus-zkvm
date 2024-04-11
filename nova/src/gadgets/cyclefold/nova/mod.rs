#![deny(unsafe_code)]

use ark_crypto_primitives::sponge::constraints::{CryptographicSpongeVar, SpongeWithGadget};
use ark_ec::short_weierstrass::{Projective, SWCurveConfig};
use ark_ff::PrimeField;
use ark_r1cs_std::{
    boolean::Boolean,
    eq::EqGadget,
    fields::{fp::FpVar, FieldVar},
    groups::curves::short_weierstrass::ProjectiveVar,
    R1CSVar, ToBitsGadget,
};
use ark_relations::r1cs::SynthesisError;

pub(crate) mod primary;

use crate::{
    commitment::CommitmentScheme,
    folding::nova::cyclefold::nimfs::SQUEEZE_ELEMENTS_BIT_SIZE,
    gadgets::{
        cyclefold::secondary,
        nonnative::{cast_field_element_unique, short_weierstrass::NonNativeAffineVar},
    },
};

pub fn multifold<G1, G2, C1, C2, RO>(
    config: &<RO::Var as CryptographicSpongeVar<G1::ScalarField, RO>>::Parameters,
    vk: &FpVar<G1::ScalarField>,
    U: &primary::RelaxedR1CSInstanceVar<G1, C1>,
    U_secondary: &secondary::RelaxedR1CSInstanceVar<G2, C2>,
    u: &primary::R1CSInstanceVar<G1, C1>,
    commitment_T: &NonNativeAffineVar<G1>,
    proof_secondary: (&secondary::ProofVar<G2, C2>, &secondary::ProofVar<G2, C2>),
    should_enforce: &Boolean<G1::ScalarField>,
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
    C1: CommitmentScheme<Projective<G1>>,
    C2: CommitmentScheme<Projective<G2>>,
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
        .squeeze_nonnative_field_elements_with_sizes::<G1::BaseField>(&[
            SQUEEZE_ELEMENTS_BIT_SIZE,
        ])?;
    let r_0 = &r_0[0];
    let r_0_bits = &r_0_bits[0];
    let r_0_scalar = Boolean::le_bits_to_fp_var(r_0_bits)?;

    let secondary::ProofVar {
        U: comm_E_secondary_instance,
        commitment_T: _commitment_T,
    } = &proof_secondary.0;

    // The rest of the secondary public input is reconstructed from primary instances.
    let comm_E_secondary_instance = secondary::R1CSInstanceVar::from_allocated_input(
        comm_E_secondary_instance,
        &U.commitment_E,
        commitment_T,
    )?;
    let (r_0_secondary, g_out) = comm_E_secondary_instance.parse_secondary_io::<G1>()?;
    r_0_secondary.conditional_enforce_equal(r_0, should_enforce)?;

    let commitment_E = g_out;

    random_oracle.absorb(&comm_E_secondary_instance)?;
    random_oracle.absorb(&_commitment_T)?;
    random_oracle.absorb(&r_0_scalar)?;

    let (r_1, r_1_bits) = random_oracle
        .squeeze_nonnative_field_elements_with_sizes::<G1::BaseField>(&[
            SQUEEZE_ELEMENTS_BIT_SIZE,
        ])?;
    let r_1 = &r_1[0];
    let r_1_bits = &r_1_bits[0];

    let secondary::ProofVar {
        U: comm_W_secondary_instance,
        commitment_T: __commitment_T,
    } = &proof_secondary.1;

    // See the above comment for `comm_E_secondary_instance`.
    let comm_W_secondary_instance = secondary::R1CSInstanceVar::from_allocated_input(
        comm_W_secondary_instance,
        &U.commitment_W,
        &u.commitment_W,
    )?;
    let (r_0_secondary, g_out) = comm_W_secondary_instance.parse_secondary_io::<G1>()?;
    r_0_secondary.conditional_enforce_equal(r_0, should_enforce)?;

    let commitment_W = g_out;
    random_oracle.absorb(&comm_W_secondary_instance)?;
    random_oracle.absorb(&__commitment_T)?;
    random_oracle.absorb(&cast_field_element_unique::<G1::BaseField, G1::ScalarField>(r_1)?)?;

    let (r_2, r_2_bits) = random_oracle
        .squeeze_nonnative_field_elements_with_sizes::<G1::BaseField>(&[
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
        (
            (&comm_E_secondary_instance, None),
            _commitment_T,
            r_1,
            r_1_bits,
        ),
        (
            (&comm_W_secondary_instance, None),
            __commitment_T,
            r_2,
            r_2_bits,
        ),
    ])?;

    Ok((folded_U, U_secondary))
}

pub fn multifold_with_relaxed<G1, G2, C1, C2, RO>(
    config: &<RO::Var as CryptographicSpongeVar<G1::ScalarField, RO>>::Parameters,
    vk: &FpVar<G1::ScalarField>,
    U1: &primary::RelaxedR1CSInstanceVar<G1, C1>,
    U_secondary: &secondary::RelaxedR1CSInstanceVar<G2, C2>,
    U2: &primary::RelaxedR1CSInstanceVar<G1, C1>,
    U2_secondary: &secondary::RelaxedR1CSInstanceVar<G2, C2>,
    commitment_T: &NonNativeAffineVar<G1>,
    commitment_T_secondary: &ProjectiveVar<G2, FpVar<G2::BaseField>>,
    proof_secondary: (
        &[secondary::ProofVar<G2, C2>; 2], // commitment to E requires 2 proofs.
        &secondary::ProofVar<G2, C2>,
    ),
    should_enforce: &Boolean<G1::ScalarField>,
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
    C1: CommitmentScheme<Projective<G1>>,
    C2: CommitmentScheme<Projective<G2>>,
    G1::BaseField: PrimeField,
    G2::BaseField: PrimeField,
    RO: SpongeWithGadget<G1::ScalarField>,
{
    let cs = U1.cs();
    let mut random_oracle = RO::Var::new(cs.clone(), config);

    random_oracle.absorb(&vk)?;
    random_oracle.absorb(&U1)?;
    random_oracle.absorb(&U2)?;
    random_oracle.absorb(&U_secondary)?;
    random_oracle.absorb(&commitment_T)?;

    let (r_0, r_0_bits) = random_oracle
        .squeeze_nonnative_field_elements_with_sizes::<G1::BaseField>(&[
            SQUEEZE_ELEMENTS_BIT_SIZE,
        ])?;
    let r_0 = &r_0[0];
    let r_0_bits = &r_0_bits[0];
    let r_0_scalar = Boolean::le_bits_to_fp_var(r_0_bits)?;
    let r_0_scalar_square = r_0_scalar.square()?;

    let secondary::ProofVar {
        U: comm_E_secondary_instance_0,
        commitment_T: _commitment_T_0,
    } = &proof_secondary.0[0];
    // The rest of the secondary public input is reconstructed from primary instances.
    let comm_E_secondary_instance_0 = secondary::R1CSInstanceVar::from_allocated_input(
        comm_E_secondary_instance_0,
        &U1.commitment_E,
        commitment_T,
    )?;
    let (r_0_secondary, g_out) = comm_E_secondary_instance_0.parse_secondary_io::<G1>()?;
    r_0_secondary.conditional_enforce_equal(r_0, should_enforce)?;

    random_oracle.absorb(&comm_E_secondary_instance_0)?;
    random_oracle.absorb(&_commitment_T_0)?;
    random_oracle.absorb(&r_0_scalar)?;

    let (r_1, r_1_bits) = random_oracle
        .squeeze_nonnative_field_elements_with_sizes::<G1::BaseField>(&[
            SQUEEZE_ELEMENTS_BIT_SIZE,
        ])?;
    let r_1 = &r_1[0];
    let r_1_bits = &r_1_bits[0];

    let secondary::ProofVar {
        U: comm_E_secondary_instance_1,
        commitment_T: _commitment_T_1,
    } = &proof_secondary.0[1];
    let comm_E_secondary_instance_1 = secondary::R1CSInstanceVar::from_allocated_input(
        comm_E_secondary_instance_1,
        &g_out,
        &U2.commitment_E,
    )?;
    let (r_0_secondary, g_out) = comm_E_secondary_instance_1.parse_secondary_io::<G1>()?;
    // TODO: `r` shouldn't be contained in secondary vars, reconstruct it from ro output.
    for (r_square_bit, r_0_bit) in r_0_scalar_square
        .to_bits_le()?
        .iter()
        .zip(&r_0_secondary.to_bits_le()?)
    {
        r_square_bit.conditional_enforce_equal(r_0_bit, should_enforce)?;
    }

    let commitment_E = g_out;

    random_oracle.absorb(&comm_E_secondary_instance_1)?;
    random_oracle.absorb(&_commitment_T_1)?;
    random_oracle.absorb(&cast_field_element_unique::<G1::BaseField, G1::ScalarField>(r_1)?)?;

    let (r_2, r_2_bits) = random_oracle
        .squeeze_nonnative_field_elements_with_sizes::<G1::BaseField>(&[
            SQUEEZE_ELEMENTS_BIT_SIZE,
        ])?;
    let r_2 = &r_2[0];
    let r_2_bits = &r_2_bits[0];

    let secondary::ProofVar {
        U: comm_W_secondary_instance,
        commitment_T: __commitment_T,
    } = &proof_secondary.1;
    // See the above comment for `comm_E_secondary_instance`.
    let comm_W_secondary_instance = secondary::R1CSInstanceVar::from_allocated_input(
        comm_W_secondary_instance,
        &U1.commitment_W,
        &U2.commitment_W,
    )?;
    let (r_0_secondary, g_out) = comm_W_secondary_instance.parse_secondary_io::<G1>()?;
    r_0_secondary.conditional_enforce_equal(r_0, should_enforce)?;

    let commitment_W = g_out;

    random_oracle.absorb(&comm_W_secondary_instance)?;
    random_oracle.absorb(&__commitment_T)?;
    random_oracle.absorb(&cast_field_element_unique::<G1::BaseField, G1::ScalarField>(r_2)?)?;

    let (r_3, r_3_bits) = random_oracle
        .squeeze_nonnative_field_elements_with_sizes::<G1::BaseField>(&[
            SQUEEZE_ELEMENTS_BIT_SIZE,
        ])?;
    let r_3 = &r_3[0];
    let r_3_bits = &r_3_bits[0];

    let folded_U = primary::RelaxedR1CSInstanceVar::<G1, C1>::new(
        commitment_W,
        commitment_E,
        U1.X.iter()
            .zip(&U2.X)
            .map(|(x1, x2)| x1 + &r_0_scalar * x2)
            .collect(),
    );

    let U1_secondary = U_secondary.fold(&[
        (
            (&comm_E_secondary_instance_0, None),
            _commitment_T_0,
            r_1,
            &r_1_bits[..],
        ),
        (
            (&comm_E_secondary_instance_1, None),
            _commitment_T_1,
            r_2,
            r_2_bits,
        ),
        (
            (&comm_W_secondary_instance, None),
            __commitment_T,
            r_3,
            r_3_bits,
        ),
    ])?;

    random_oracle.absorb(&cast_field_element_unique::<G1::BaseField, G1::ScalarField>(r_3)?)?;
    random_oracle.absorb(&U1_secondary)?;
    random_oracle.absorb(&U2_secondary)?;
    random_oracle.absorb(&commitment_T_secondary)?;

    let (r, r_bits) =
        random_oracle.squeeze_nonnative_field_elements_with_sizes::<G1::BaseField>(&[
            SQUEEZE_ELEMENTS_BIT_SIZE,
        ])?;
    let r = &r[0];
    let r_bits = &r_bits[0];

    let U_secondary = U1_secondary.fold(&[(
        (&U2_secondary.into(), Some(&U2_secondary.commitment_E)),
        commitment_T_secondary,
        r,
        &r_bits[..],
    )])?;

    Ok((folded_U, U_secondary))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        folding::nova::cyclefold::{
            nimfs::{NIMFSProof, RelaxedR1CSInstance, RelaxedR1CSWitness},
            secondary as multifold_secondary,
        },
        pedersen::PedersenCommitment,
        poseidon_config,
        test_utils::setup_test_r1cs,
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
        C1: CommitmentScheme<Projective<G1>, SetupAux = ()>,
        C2: CommitmentScheme<Projective<G2>, SetupAux = ()>,
        G1::BaseField: PrimeField + Absorb,
        G2::BaseField: PrimeField + Absorb,
        C1::PP: Clone,
    {
        let config = poseidon_config();

        let vk = G1::ScalarField::ONE;

        let (shape, u, w, pp) = setup_test_r1cs::<G1, C1>(3, None, &());
        let shape_secondary = multifold_secondary::setup_shape::<G1, G2>()?;

        let pp_secondary = C2::setup(
            shape_secondary.num_vars + shape_secondary.num_constraints,
            &(),
        );

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

        let commitment_T_cs =
            NonNativeAffineVar::new_input(cs.clone(), || Ok(proof.commitment_T.into()))?;

        let comm_E_proof = &proof.commitment_E_proof;
        let comm_W_proof = &proof.commitment_W_proof;

        let vk_cs = FpVar::new_input(cs.clone(), || Ok(vk))?;
        let comm_E_proof =
            secondary::ProofVar::<G2, C2>::new_input(cs.clone(), || Ok(&comm_E_proof[0]))?;
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
            &Boolean::TRUE,
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
        let (_, u, w, _) = setup_test_r1cs::<G1, C1>(5, Some(&pp), &());

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

        let commitment_T_cs =
            NonNativeAffineVar::new_input(cs.clone(), || Ok(proof.commitment_T.into()))?;

        let comm_E_proof = &proof.commitment_E_proof;
        let comm_W_proof = &proof.commitment_W_proof;

        let vk_cs = FpVar::new_input(cs.clone(), || Ok(vk))?;
        let comm_E_proof =
            secondary::ProofVar::<G2, C2>::new_input(cs.clone(), || Ok(&comm_E_proof[0]))?;
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
            &Boolean::TRUE,
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

    #[test]
    fn verify_relaxed_in_circuit() {
        verify_relaxed_in_circuit_with_cycle::<
            ark_pallas::PallasConfig,
            ark_vesta::VestaConfig,
            PedersenCommitment<ark_pallas::Projective>,
            PedersenCommitment<ark_vesta::Projective>,
        >()
        .unwrap();
    }

    fn verify_relaxed_in_circuit_with_cycle<G1, G2, C1, C2>() -> Result<(), SynthesisError>
    where
        G1: SWCurveConfig<BaseField = G2::ScalarField, ScalarField = G2::BaseField>,
        G2: SWCurveConfig,
        C1: CommitmentScheme<Projective<G1>, SetupAux = ()>,
        C2: CommitmentScheme<Projective<G2>, SetupAux = ()>,
        G1::BaseField: PrimeField + Absorb,
        G2::BaseField: PrimeField + Absorb,
        C1::PP: Clone,
    {
        let config = poseidon_config();

        let vk = G1::ScalarField::ONE;

        let (shape, u, w, pp) = setup_test_r1cs::<G1, C1>(3, None, &());
        let shape_secondary = multifold_secondary::setup_shape::<G1, G2>()?;

        let pp_secondary = C2::setup(
            shape_secondary.num_vars + shape_secondary.num_constraints,
            &(),
        );

        let U = RelaxedR1CSInstance::<G1, C1>::new(&shape);
        let W = RelaxedR1CSWitness::<G1>::zero(&shape);

        let U_secondary = RelaxedR1CSInstance::<G2, C2>::new(&shape_secondary);
        let W_secondary = RelaxedR1CSWitness::<G2>::zero(&shape_secondary);
        let (_, (U2, W2), (U2_secondary, W2_secondary)) =
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

        let (_, u, w, _) = setup_test_r1cs::<G1, C1>(5, Some(&pp), &());
        let U1 = RelaxedR1CSInstance::from(&u);
        let W1 = RelaxedR1CSWitness::from_r1cs_witness(&shape, &w);

        let U1_secondary = RelaxedR1CSInstance::<G2, C2>::new(&shape_secondary);
        let W1_secondary = RelaxedR1CSWitness::<G2>::zero(&shape_secondary);

        let (proof, (U, W), (U_secondary, W_secondary)) =
            NIMFSProof::<_, _, _, _, PoseidonSponge<G1::ScalarField>>::prove_with_relaxed(
                &pp,
                &pp_secondary,
                &config,
                &vk,
                (&shape, &shape_secondary),
                (&U1, &W1),
                (&U1_secondary, &W1_secondary),
                (&U2, &W2),
                (&U2_secondary, &W2_secondary),
            )
            .unwrap();

        let cs = ConstraintSystem::<G1::ScalarField>::new_ref();

        let U1_cs = primary::RelaxedR1CSInstanceVar::<G1, C1>::new_input(cs.clone(), || Ok(&U1))?;
        let U1_secondary_cs =
            secondary::RelaxedR1CSInstanceVar::<G2, C2>::new_input(cs.clone(), || {
                Ok(&U1_secondary)
            })?;
        let U2_cs = primary::RelaxedR1CSInstanceVar::<G1, C1>::new_input(cs.clone(), || Ok(&U2))?;
        let U2_secondary_cs =
            secondary::RelaxedR1CSInstanceVar::<G2, C2>::new_input(cs.clone(), || {
                Ok(&U2_secondary)
            })?;
        let commitment_T_secondary_cs = <ProjectiveVar<G2, FpVar<G2::BaseField>> as AllocVar<
            Projective<G2>,
            G2::BaseField,
        >>::new_input(cs.clone(), || {
            Ok(proof.proof_secondary.commitment_T.into())
        })?;

        let commitment_T_cs =
            NonNativeAffineVar::new_input(cs.clone(), || Ok(proof.commitment_T.into()))?;

        let comm_E_proof = &proof.commitment_E_proof;
        let comm_W_proof = &proof.commitment_W_proof;

        let vk_cs = FpVar::new_input(cs.clone(), || Ok(vk))?;
        let comm_E_proof = [
            secondary::ProofVar::<G2, C2>::new_input(cs.clone(), || Ok(&comm_E_proof[0]))?,
            secondary::ProofVar::<G2, C2>::new_input(cs.clone(), || Ok(&comm_E_proof[1]))?,
        ];
        let comm_W_proof =
            secondary::ProofVar::<G2, C2>::new_input(cs.clone(), || Ok(comm_W_proof))?;
        let proof_cs = (&comm_E_proof, &comm_W_proof);

        let (_U_cs, _U_secondary_cs) =
            multifold_with_relaxed::<G1, G2, C1, C2, PoseidonSponge<G1::ScalarField>>(
                &config,
                &vk_cs,
                &U1_cs,
                &U1_secondary_cs,
                &U2_cs,
                &U2_secondary_cs,
                &commitment_T_cs,
                &commitment_T_secondary_cs,
                proof_cs,
                &Boolean::TRUE,
            )?;

        let _U = _U_cs.value()?;
        let _U_secondary = _U_secondary_cs.value()?;

        assert_eq!(_U, U);
        shape.is_relaxed_satisfied(&U, &W, &pp).unwrap();

        assert_eq!(_U_secondary, U_secondary);
        shape_secondary
            .is_relaxed_satisfied(&U_secondary, &W_secondary, &pp_secondary)
            .unwrap();

        assert!(cs.is_satisfied().unwrap());

        Ok(())
    }
}
