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
        cyclefold::{nova, secondary},
        nonnative::{cast_field_element_unique, short_weierstrass::NonNativeAffineVar},
    },
};

pub fn multifold<G1, G2, C1, C2, RO>(
    config: &<RO::Var as CryptographicSpongeVar<G1::ScalarField, RO>>::Parameters,
    vk: &FpVar<G1::ScalarField>,
    U: &primary::LCCSInstanceVar<G1, C1>,
    U_secondary: &secondary::RelaxedR1CSInstanceVar<G2, C2>,
    u: &primary::CCSInstanceVar<G1, C1>,
    commitment_T: &NonNativeAffineVar<G2>,
    commitment_W_proof: &secondary::ProofVar<G2, C2>,
    should_enforce: &Boolean<G1::ScalarField>,
) -> Result<
    (
        primary::LCCSInstanceFromR1CSVar<G1, C1>,
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

    random_oracle.absorb(&U_secondary)?;

    random_oracle.absorb(&vk)?;
    random_oracle.absorb(&U)?;
    random_oracle.absorb(&u)?;

    let (rho, rho_bits) = random_oracle
        .squeeze_nonnative_field_elements_with_sizes::<G1::BaseField>(&[
            SQUEEZE_ELEMENTS_BIT_SIZE,
        ])?;
    let rho = &rho[0];
    let rho_bits = &rho_bits[0];
    let rho_scalar = Boolean::le_bits_to_fp_var(rho_bits)?;

    // HyperNova Verification
    // assumes CCS constraints are of R1CS origin

    const NUM_MATRICES = 3;
    const NUM_MULTISETS = 2;

    let s: usize = ((shape.num_constraints - 1).checked_ilog2().unwrap_or(0) + 1) as usize;
    let cSs: vec![
        (FpVar::constant(G1::ScalarField::ONE), vec![0, 1]),
        (FpVar::constant(G1::ScalarField::ONE.neg()), vec![2]),
    ];

    let gamma: G::ScalarField =
        random_oracle.squeeze_field_elements_with_sizes(&[SQUEEZE_ELEMENTS_BIT_SIZE])[0];
    let gamma_var = FpVar::<G1::ScalarField>::new_variable(cs.clone(), || Ok(gamma))?;

    let beta = random_oracle.squeeze_field_elements_with_sizes(&[SQUEEZE_ELEMENTS_BIT_SIZE; s]);
    let beta_vars = beta
        .iter()
        .map(|b| FpVar::<G1::ScalarField>::new_variable(cs.clone(), || Ok(b))?)
        .collect();

    let claimed_sum = (1..=NUM_MATRICES)
        .map(|j| gamma_var.pow_le(Boolean::constant_vec_from_bytes(j.to_le_bytes())) * U.vs[j - 1])
        .sum();

    // verify sumcheck

    // compute e1 and e2

    let cl = (1..=NUM_MATRICES)
        .map(|j| gamma_var.pow_le(Boolean::constant_vec_from_bytes(j.to_le_bytes())) * e1 * sigmas[j - 1])
        .sum();

    let cr: G::ScalarField = (0..NUM_MULTISETS)
        .map(|i| {
            shape.cSs[i]
                .1
                .iter()
                .fold(shape.cSs[i].0, |acc, j| acc * thetas[*j])
        })
        .sum()
        * gamma_var.pow_le(Boolean::constant_vec_from_bytes((NUM_MATRICES + 1).to_le_bytes()))
        * e2;

    // abort if bad

    // End HyperNova Verification

    let secondary::ProofVar {
        U: comm_W_secondary_instance,
        commitment_T: commitment_T,
    } = &commitment_W_proof;

    // The rest of the secondary public input is reconstructed from primary instances.
    let comm_W_secondary_instance = secondary::R1CSInstanceVar::from_allocated_input(
        comm_W_secondary_instance,
        &U.commitment_W,
        commitment_T,
    )?;
    let (r_secondary, g_out) = comm_W_secondary_instance.parse_secondary_io::<G1>()?;
    r_secondary.conditional_enforce_equal(rho, should_enforce)?;

    let commitment_W = g_out;

    random_oracle.absorb(&comm_W_secondary_instance)?;
    random_oracle.absorb(&commitment_T)?;
    random_oracle.absorb(&rho_scalar)?;

    let (rho_p, rho_p_bits) = random_oracle
        .squeeze_nonnative_field_elements_with_sizes::<G1::BaseField>(&[
            SQUEEZE_ELEMENTS_BIT_SIZE,
        ])?;
    let rho_p = &rho_p[0];
    let rho_p_bits = &rho_p_bits[0];

    let folded_U = primary::LCCSInstanceFromR1CSVar::new(
        commitment_W,
        [U.X[0] + rho_scalar,
         U.X[1..].iter()
         .zip(&u.X[1..])
         .map(|(a, b)| a + &rho_scalar * b)
         .collect(),
        ].concat(),
        rs,
        sigmas.iter()
            .zip(&thetas)
            .map(|(a, b)| a + &rho_scalar * b)
            .collect(),
    );

    let U_secondary = U_secondary.fold(&[
        (&comm_W_secondary_instance, None),
        commitment_T,
        rho_p,
        rho_p_bits,
    ])?;

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
            ark_bn254::g1::Config,
            ark_grumpkin::GrumpkinConfig,
            Zeromorph<ark_bn254::Bn254>,
            PedersenCommitment<ark_grumpkin::Projective>,
        >()
        .unwrap();
    }

    fn verify_in_circuit_with_cycle<G1, G2, C1, C2>() -> Result<(), SynthesisError>
    where
        G1: SWCurveConfig<BaseField = G2::ScalarField, ScalarField = G2::BaseField>,
        G2: SWCurveConfig,
        C1: PolyCommitmentScheme<Projective<G1>>,
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
            b"test",
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
}
