#![allow(unused)]
#![deny(unsafe_code)]

use ark_crypto_primitives::sponge::constraints::{CryptographicSpongeVar, SpongeWithGadget};
use ark_ec::{
    short_weierstrass::{Projective, SWCurveConfig},
    AdditiveGroup,
};
use ark_ff::{Field, PrimeField};
use ark_r1cs_std::{
    boolean::Boolean,
    eq::EqGadget,
    fields::{fp::FpVar, FieldVar},
    R1CSVar,
};
use ark_relations::r1cs::SynthesisError;
use ark_spartan::polycommitments::PolyCommitmentScheme;

pub(crate) mod primary;

use crate::{
    commitment::CommitmentScheme,
    folding::hypernova::{
        cyclefold::{nimfs::SQUEEZE_ELEMENTS_BIT_SIZE, CCSShape},
        ml_sumcheck::protocol::verifier::SQUEEZE_NATIVE_ELEMENTS_NUM,
    },
    gadgets::{
        cyclefold::secondary,
        nonnative::{cast_field_element_unique, short_weierstrass::NonNativeAffineVar},
    },
};

pub fn multifold<G1, G2, C1, C2, RO>(
    config: &<RO::Var as CryptographicSpongeVar<G1::ScalarField, RO>>::Parameters,
    vk: &FpVar<G1::ScalarField>,
    shape: &CCSShape<G1>,
    U: &primary::LCCSInstanceFromR1CSVar<G1, C1>,
    U_secondary: &secondary::RelaxedR1CSInstanceVar<G2, C2>,
    u: &primary::CCSInstanceFromR1CSVar<G1, C1>,
    commitment_W_proof: &secondary::ProofVar<G2, C2>,
    hypernova_proof: &primary::ProofFromR1CSVar<G1, RO>,
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
    random_oracle.absorb(&u.var())?;

    let (rho, rho_bits) = random_oracle
        .squeeze_nonnative_field_elements_with_sizes::<G1::BaseField>(&[
            SQUEEZE_ELEMENTS_BIT_SIZE,
        ])?;
    let rho = &rho[0];
    let rho_bits = &rho_bits[0];
    let rho_scalar = Boolean::le_bits_to_fp_var(rho_bits)?;

    // HyperNova Verification Circuit - implementation is specific to R1CS origin for constraints

    debug_assert!(shape.num_matrices == 3);
    debug_assert!(shape.num_multisets == 2);
    debug_assert!(shape.max_cardinality == 2);

    let s: usize = ((shape.num_constraints - 1).checked_ilog2().unwrap_or(0) + 1) as usize;

    let gamma: FpVar<G1::ScalarField> = random_oracle.squeeze_field_elements(1)?[0].clone();
    let beta: Vec<FpVar<G1::ScalarField>> = random_oracle.squeeze_field_elements(s)?;

    let gamma_powers: Vec<FpVar<G1::ScalarField>> = (1..=shape.num_matrices)
        .map(|j| gamma.pow_le(&Boolean::constant_vec_from_bytes(&j.to_le_bytes())))
        .collect::<Result<Vec<FpVar<G1::ScalarField>>, SynthesisError>>()?;

    let mut expected: FpVar<G1::ScalarField> = gamma_powers.iter().zip(U.var().vs.iter()).fold(
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

    random_oracle.absorb(&hypernova_proof.var().poly_info.var())?;

    let mut rs_p: Vec<FpVar<G1::ScalarField>> = vec![];
    for round in 0..s {
        random_oracle.absorb(&hypernova_proof.var().sumcheck_proof[round])?;
        let r = random_oracle.squeeze_field_elements(SQUEEZE_NATIVE_ELEMENTS_NUM)?[0].clone();
        random_oracle.absorb(&r)?;

        let evals = &hypernova_proof.var().sumcheck_proof[round];
        expected.conditional_enforce_equal(&(&evals[0] + &evals[1]), should_enforce)?;

        // lagrange interpolate and evaluate polynomial

        // \prod_{j} x - j
        let prod: FpVar<G1::ScalarField> = (0..(shape.max_cardinality + 2)).fold(
            FpVar::<G1::ScalarField>::Constant(G1::ScalarField::ONE),
            |acc, i| acc * (&r - interpolation_constants[i].0),
        );

        // p(x) = \sum_{i} (\prod_{j} x - j) * y[i] / (x - i) * (\prod_{j != i} (i - j))
        //      = \sum_{i} y[i] * (\prod_{j != i} x - j) / (\prod_{j != i} i - j)
        //      = \sum_{i} y[i] * (\prod_{j != i} (x - j) / (j - i))
        expected = (0..(shape.max_cardinality + 2))
            .map(|i| {
                let num = &prod * &evals[i];
                let denom = (&r - interpolation_constants[i].0) * interpolation_constants[i].1;
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

    let cl = gamma_powers
        .iter()
        .zip(hypernova_proof.var().sigmas.iter())
        .fold(
            FpVar::<G1::ScalarField>::Constant(G1::ScalarField::ZERO),
            |acc, (a, b)| acc + (a * b),
        )
        * e1;

    let cr = (0..shape.num_multisets)
        .map(|i| {
            shape.cSs[i].1.iter().fold(
                FpVar::<G1::ScalarField>::Constant(shape.cSs[i].0),
                |acc, j| acc * &hypernova_proof.var().thetas[*j],
            )
        })
        .fold(
            FpVar::<G1::ScalarField>::Constant(G1::ScalarField::ZERO),
            |acc, x| acc + x,
        )
        * gamma.pow_le(&Boolean::constant_vec_from_bytes(
            &(shape.num_matrices + 1).to_le_bytes(),
        ))?
        * e2;

    expected.conditional_enforce_equal(&(cl + cr), should_enforce)?;

    // End HyperNova Verification Circuit

    let secondary::ProofVar {
        U: comm_W_secondary_instance,
        commitment_T,
    } = &commitment_W_proof;

    // The rest of the secondary public input is reconstructed from primary instances.
    let comm_W_secondary_instance = secondary::R1CSInstanceVar::from_allocated_input(
        comm_W_secondary_instance,
        &U.var().commitment_W,
        &u.var().commitment_W,
    )?;
    let (rho_secondary, g_out) = comm_W_secondary_instance.parse_secondary_io::<G1>()?;
    rho_secondary.conditional_enforce_equal(rho, should_enforce)?;

    let commitment_W = g_out;
    random_oracle.absorb(&comm_W_secondary_instance)?;
    random_oracle.absorb(&commitment_T)?;
    random_oracle.absorb(&cast_field_element_unique::<G1::BaseField, G1::ScalarField>(rho)?)?;

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
            .var()
            .sigmas
            .iter()
            .zip(hypernova_proof.var().thetas.iter())
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

    use crate::poseidon_config;
    use crate::{
        ccs::mle::vec_to_mle,
        folding::hypernova::cyclefold::{
            nimfs::{
                CCSInstance, CCSWitness, LCCSInstance, NIMFSProof, RelaxedR1CSInstance,
                RelaxedR1CSWitness,
            },
            secondary as multifold_secondary,
        },
        pedersen::PedersenCommitment,
        r1cs::tests::to_field_elements,
        test_utils::setup_test_ccs,
    };
    use ark_crypto_primitives::sponge::{poseidon::PoseidonSponge, Absorb};
    use ark_ec::short_weierstrass::{Projective, SWCurveConfig};
    use ark_ff::Field;
    use ark_r1cs_std::{fields::fp::FpVar, prelude::AllocVar, R1CSVar};
    use ark_relations::r1cs::ConstraintSystem;
    use ark_spartan::polycommitments::zeromorph::Zeromorph;
    use ark_std::{test_rng, UniformRand};

    use rayon::iter::{IntoParallelRefIterator, ParallelIterator};

    #[test]
    fn verify_in_circuit() {
        verify_in_circuit_with_cycle::<
            ark_bn254::g1::Config,
            ark_grumpkin::GrumpkinConfig,
            Zeromorph<ark_bn254::Bn254>,
            PedersenCommitment<ark_grumpkin::GrumpkinConfig>,
        >()
        .unwrap();
    }

    fn verify_in_circuit_with_cycle<G1, G2, C1, C2>() -> Result<(), SynthesisError>
    where
        G1: SWCurveConfig<BaseField = G2::ScalarField, ScalarField = G2::BaseField>,
        G2: SWCurveConfig,
        C1: PolyCommitmentScheme<Projective<G1>>,
        C2: CommitmentScheme<Projective<G2>, SetupAux = [u8]>,
        G1::BaseField: PrimeField + Absorb,
        G2::BaseField: PrimeField + Absorb,
    {
        let config = poseidon_config();

        let vk = G1::ScalarField::ONE;

        let mut rng = test_rng();
        let (shape, u, w, ck) = setup_test_ccs::<G1, C1>(3, None, Some(&mut rng));

        let shape_secondary = multifold_secondary::setup_shape::<G1, G2>()?;

        let pp_secondary = C2::setup(
            shape_secondary.num_vars + shape_secondary.num_constraints,
            &[],
        );

        let X = to_field_elements::<Projective<G1>>((vec![0; shape.num_io]).as_slice());
        let W = CCSWitness::zero(&shape);

        let commitment_W = W.commit::<C1>(&ck);

        let s = (shape.num_constraints - 1).checked_ilog2().unwrap_or(0) + 1;
        let rs: Vec<G1::ScalarField> = (0..s).map(|_| G1::ScalarField::rand(&mut rng)).collect();

        let z = [X.as_slice(), W.W.as_slice()].concat();
        let vs: Vec<G1::ScalarField> = ark_std::cfg_iter!(&shape.Ms)
            .map(|M| {
                vec_to_mle(M.multiply_vec(&z).as_slice()).evaluate::<Projective<G1>>(rs.as_slice())
            })
            .collect();

        let U =
            LCCSInstance::<G1, C1>::new(&shape, &commitment_W, &X, rs.as_slice(), vs.as_slice())
                .unwrap();

        let U_secondary = RelaxedR1CSInstance::<G2, C2>::new(&shape_secondary);
        let W_secondary = RelaxedR1CSWitness::<G2>::zero(&shape_secondary);

        let (proof, (folded_U, folded_W), (folded_U_secondary, folded_W_secondary)) =
            NIMFSProof::<_, _, _, _, PoseidonSponge<G1::ScalarField>>::prove(
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
        let U_cs = primary::LCCSInstanceFromR1CSVar::<G1, C1>::new_input(cs.clone(), || Ok(&U))?;
        let U_secondary_cs =
            secondary::RelaxedR1CSInstanceVar::<G2, C2>::new_input(cs.clone(), || {
                Ok(&U_secondary)
            })?;
        let u_cs = primary::CCSInstanceFromR1CSVar::<G1, C1>::new_input(cs.clone(), || Ok(&u))?;

        let hypernova_proof = &proof.hypernova_proof;
        let comm_W_proof = &proof.commitment_W_proof;

        let vk_cs = FpVar::new_input(cs.clone(), || Ok(vk))?;
        let hypernova_proof =
            primary::ProofFromR1CSVar::<G1, PoseidonSponge<G1::ScalarField>>::new_input(
                cs.clone(),
                || Ok(hypernova_proof),
            )?;
        let comm_W_proof =
            secondary::ProofVar::<G2, C2>::new_input(cs.clone(), || Ok(comm_W_proof))?;

        let (_U_cs, _U_secondary_cs) = multifold::<G1, G2, C1, C2, PoseidonSponge<G1::ScalarField>>(
            &config,
            &vk_cs,
            &shape,
            &U_cs,
            &U_secondary_cs,
            &u_cs,
            &comm_W_proof,
            &hypernova_proof,
            &Boolean::TRUE,
        )?;

        let _U = _U_cs.value()?;
        let _U_secondary = _U_secondary_cs.value()?;

        assert_eq!(_U, folded_U);
        shape.is_satisfied_linearized(&_U, &folded_W, &ck).unwrap();

        assert_eq!(_U_secondary, folded_U_secondary);
        shape_secondary
            .is_relaxed_satisfied(&_U_secondary, &folded_W_secondary, &pp_secondary)
            .unwrap();

        assert!(cs.is_satisfied().unwrap());

        // another round.
        let (_, u, w, _) = setup_test_ccs(5, Some(&ck), Some(&mut rng));

        let (proof, (folded_U_2, folded_W_2), (folded_U_secondary_2, folded_W_secondary_2)) =
            NIMFSProof::<_, _, _, _, PoseidonSponge<G1::ScalarField>>::prove(
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
            primary::LCCSInstanceFromR1CSVar::<G1, C1>::new_input(cs.clone(), || Ok(&folded_U))?;
        let U_secondary_cs =
            secondary::RelaxedR1CSInstanceVar::<G2, C2>::new_input(cs.clone(), || {
                Ok(&folded_U_secondary)
            })?;
        let u_cs = primary::CCSInstanceFromR1CSVar::<G1, C1>::new_input(cs.clone(), || Ok(&u))?;

        let hypernova_proof = &proof.hypernova_proof;
        let comm_W_proof = &proof.commitment_W_proof;

        let vk_cs = FpVar::new_input(cs.clone(), || Ok(vk))?;
        let hypernova_proof =
            primary::ProofFromR1CSVar::<G1, PoseidonSponge<G1::ScalarField>>::new_input(
                cs.clone(),
                || Ok(hypernova_proof),
            )?;
        let comm_W_proof =
            secondary::ProofVar::<G2, C2>::new_input(cs.clone(), || Ok(comm_W_proof))?;

        let (_U_cs, _U_secondary_cs) = multifold::<G1, G2, C1, C2, PoseidonSponge<G1::ScalarField>>(
            &config,
            &vk_cs,
            &shape,
            &U_cs,
            &U_secondary_cs,
            &u_cs,
            &comm_W_proof,
            &hypernova_proof,
            &Boolean::TRUE,
        )?;

        let _U = _U_cs.value()?;
        let _U_secondary = _U_secondary_cs.value()?;

        assert_eq!(_U, folded_U_2);
        shape
            .is_satisfied_linearized(&_U, &folded_W_2, &ck)
            .unwrap();

        assert_eq!(_U_secondary, folded_U_secondary_2);
        shape_secondary
            .is_relaxed_satisfied(&_U_secondary, &folded_W_secondary_2, &pp_secondary)
            .unwrap();

        assert!(cs.is_satisfied().unwrap());

        Ok(())
    }
}
