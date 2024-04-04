#![deny(unsafe_code)]

use ark_crypto_primitives::sponge::constraints::{CryptographicSpongeVar, SpongeWithGadget};
use ark_ec::{
    short_weierstrass::{Projective, SWCurveConfig},
    AdditiveGroup,
};
use ark_ff::{Field, PrimeField};
use ark_r1cs_std::{
    alloc::AllocVar,
    boolean::Boolean,
    eq::EqGadget,
    fields::{fp::FpVar, FieldVar},
    groups::curves::short_weierstrass::ProjectiveVar,
    R1CSVar, ToBitsGadget,
};
use ark_relations::r1cs::SynthesisError;
use ark_spartan::polycommitments::PolyCommitmentScheme;
use std::ops::Neg;

pub(crate) mod primary;

use crate::{
    commitment::CommitmentScheme,
    folding::hypernova::{
        cyclefold::nimfs::SQUEEZE_ELEMENTS_BIT_SIZE,
        ml_sumcheck::protocol::verifier::SQUEEZE_NATIVE_ELEMENTS_NUM,
    },
    gadgets::{
        cyclefold::{nova, secondary},
        nonnative::{cast_field_element_unique, short_weierstrass::NonNativeAffineVar},
    },
};

pub fn multifold<G1, G2, C1, C2, RO>(
    config: &<RO::Var as CryptographicSpongeVar<G1::ScalarField, RO>>::Parameters,
    vk: &FpVar<G1::ScalarField>,
    U: &primary::LCCSInstanceFromR1CSVar<G1, C1>,
    U_secondary: &secondary::RelaxedR1CSInstanceVar<G2, C2>,
    u: &primary::CCSInstanceFromR1CSVar<G1, C1>,
    commitment_T: &NonNativeAffineVar<G2>,
    commitment_W_proof: &secondary::ProofVar<G2, C2>,
    hypernova_proof: &primary::ProofVar<G1, RO>,
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
    C1: PolyCommitmentScheme<Projective<G1>>,
    C2: CommitmentScheme<Projective<G2>>,
    G1::BaseField: PrimeField,
    G2::BaseField: PrimeField,
    RO: SpongeWithGadget<G1::ScalarField>,
{
    let cs = U.cs();
    let mut random_oracle = RO::Var::new(cs.clone(), config);

    random_oracle.absorb(&U_secondary)?;

    random_oracle.absorb(&vk)?;
    random_oracle.absorb(&U.var())?;
    random_oracle.absorb(&u)?;

    let (rho, rho_bits) = random_oracle
        .squeeze_nonnative_field_elements_with_sizes::<G1::BaseField>(&[
            SQUEEZE_ELEMENTS_BIT_SIZE,
        ])?;
    let rho = &rho[0];
    let rho_bits = &rho_bits[0];
    let rho_scalar = Boolean::le_bits_to_fp_var(rho_bits)?;

    // HyperNova Verification Circuit - implementation is specific to R1CS origin for constraints

    const NUM_MATRICES: usize = 3;
    const NUM_MULTISETS: usize = 2;

    // d + 1 in HyperNova/Cyclefold papers
    const MAX_DEGREE: usize = 3;

    let cSs: [(i32, Vec<usize>); 2] = [(1, vec![0, 1]), (-1, vec![2])];

    let s: usize = ((cs.num_constraints() - 1).checked_ilog2().unwrap_or(0) + 1) as usize;

    let gamma: FpVar<G1::ScalarField> = random_oracle.squeeze_field_elements(1)?[0].clone();
    let beta: Vec<FpVar<G1::ScalarField>> = random_oracle.squeeze_field_elements(s)?;

    let gamma_powers: Vec<FpVar<G1::ScalarField>> = (1..=NUM_MATRICES)
        .map(|j| gamma.pow_le(&Boolean::constant_vec_from_bytes(&j.to_le_bytes())))
        .collect::<Result<Vec<FpVar<G1::ScalarField>>, SynthesisError>>()?;

    let mut expected: FpVar<G1::ScalarField> = gamma_powers
        .iter()
        .zip(U.var().vs.iter())
        .fold(
            FpVar::<G1::ScalarField>::Constant(G1::ScalarField::ZERO),
            |acc, (a, b)| acc + (a * b),
        );

    // (i, \prod_{j != i} (i - j))
    let interpolation_constants = [
        (G1::ScalarField::from(0), G1::ScalarField::from(-6)), // (0 - 1)(0 - 2)(0 - 3) = -6
        (G1::ScalarField::from(1), G1::ScalarField::from(2)),  // (1 - 0)(1 - 2)(1 - 3) =  2
        (G1::ScalarField::from(2), G1::ScalarField::from(-2)), // (2 - 0)(2 - 1)(2 - 3) = -2
        (G1::ScalarField::from(3), G1::ScalarField::from(6)),  // (3 - 0)(3 - 1)(3 - 2) =  6
    ];

    random_oracle.absorb(&hypernova_proof.poly_info)?;

    let mut rs_p: Vec<FpVar<G1::ScalarField>> = vec![];
    for round in 0..s {
        random_oracle.absorb(&hypernova_proof.sumcheck_proof[round])?;
        let r = random_oracle.squeeze_field_elements(SQUEEZE_NATIVE_ELEMENTS_NUM)?[0].clone();
        random_oracle.absorb(&r)?;

        let evals = &hypernova_proof.sumcheck_proof[round];
        expected.conditional_enforce_equal(&(&evals[0] + &evals[1]), should_enforce)?;

        // lagrange interpolate and evaluate polynomial

        // \prod_{j} x - j
        let prod: FpVar<G1::ScalarField> = (0..(MAX_DEGREE + 1)).fold(
            FpVar::<G1::ScalarField>::Constant(G1::ScalarField::ONE),
            |acc, i| acc * (&r - interpolation_constants[i].0),
        );

        // p(x) = \sum_{i} (\prod_{j} x - j) * y[i] / (x - i) * (\prod_{j != i} (i - j))
        //      = \sum_{i} y[i] * (\prod_{j != i} x - j) / (\prod_{j != i} i - j)
        //      = \sum_{i} y[i] * (\prod_{j != i} (x - j) / (j - i))
        expected = (0..(MAX_DEGREE + 1))
            .map(|i| {
                let num = &prod * &evals[i];
                let denom =
                    (&r - interpolation_constants[i].0) * interpolation_constants[i].1;
                num.mul_by_inverse(&denom)
            })
            .collect::<Result<Vec<FpVar<G1::ScalarField>>, SynthesisError>>()?
            .iter()
            .sum();

        rs_p.push(r);
    }

    let e1 = (0..U.var().rs.len())
        .map(|i| {
            &U.var().rs[i] * &rs_p[i]
                + (FpVar::<G1::ScalarField>::Constant(G1::ScalarField::ONE) - &U.var().rs[i])
                    * (FpVar::<G1::ScalarField>::Constant(G1::ScalarField::ONE) - &rs_p[i])
        })
        .fold(
            FpVar::<G1::ScalarField>::Constant(G1::ScalarField::ONE),
            |acc, x| acc * x,
        );

    let e2 = (0..beta.len())
        .map(|i| {
            &beta[i] * &rs_p[i]
                + (FpVar::<G1::ScalarField>::Constant(G1::ScalarField::ONE) - &beta[i])
                    * (FpVar::<G1::ScalarField>::Constant(G1::ScalarField::ONE) - &rs_p[i])
        })
        .fold(
            FpVar::<G1::ScalarField>::Constant(G1::ScalarField::ONE),
            |acc, x| acc * x,
        );

    /*
    let cSs = vec![
        (
            FpVar::<G1::ScalarField>::Constant(G1::ScalarField::ONE),
            vec![0, 1],
        ),
        (
            FpVar::<G1::ScalarField>::Constant(G1::ScalarField::ONE.neg()),
            vec![2],
        ),
    ];
     */

    let cl = gamma_powers
        .iter()
        .zip(hypernova_proof.sigmas.iter())
        .fold(
            FpVar::<G1::ScalarField>::Constant(G1::ScalarField::ZERO),
            |acc, (a, b)| acc + (a * b),
        ) * e1;

    let cr = (0..NUM_MULTISETS)
        .map(|i| {
            cSs[i]
                .1
                .iter()
                .fold(FpVar::<G1::ScalarField>::Constant(G1::ScalarField::from(cSs[i].0)), |acc, j| acc * &hypernova_proof.thetas[*j])
        })
        .fold(
            FpVar::<G1::ScalarField>::Constant(G1::ScalarField::ZERO),
            |acc, x| acc + x,
        ) * gamma.pow_le(&Boolean::constant_vec_from_bytes(
            &(NUM_MATRICES + 1).to_le_bytes(),
        ))? * e2;

    expected.conditional_enforce_equal(&(cl + cr), should_enforce)?;

    // End HyperNova Verification Circuit

    let secondary::ProofVar {
        U: comm_W_secondary_instance,
        commitment_T: commitment_T,
    } = &commitment_W_proof;

    // The rest of the secondary public input is reconstructed from primary instances.
    let comm_W_secondary_instance = secondary::R1CSInstanceVar::from_allocated_input(
        comm_W_secondary_instance,
        &U.var().commitment_W,
        &u.var().commitment_W,
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
        U.var()
            .X
            .iter()
            .zip(u.var().X.iter()) // by assertion, u.X[0] = 1
            .map(|(a, b)| a + &rho_scalar * b)
            .collect(),
        rs_p,
        hypernova_proof
            .sigmas
            .iter()
            .zip(hypernova_proof.thetas.iter())
            .map(|(a, b)| a + &rho_scalar * b)
            .collect(),
    );

    let U_secondary = U_secondary.fold(&[(
        (&comm_W_secondary_instance, None),
        commitment_T,
        rho_p,
        rho_p_bits,
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
}
