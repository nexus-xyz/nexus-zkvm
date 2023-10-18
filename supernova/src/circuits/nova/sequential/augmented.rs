use std::{borrow::Borrow, marker::PhantomData};

use ark_crypto_primitives::sponge::{
    constraints::{CryptographicSpongeVar, SpongeWithGadget},
    Absorb,
};
use ark_ec::short_weierstrass::{Projective, SWCurveConfig};
use ark_ff::{AdditiveGroup, Field, PrimeField};
use ark_r1cs_std::{
    alloc::{AllocVar, AllocationMode},
    boolean::Boolean,
    eq::EqGadget,
    fields::{fp::FpVar, FieldVar},
    R1CSVar,
};
use ark_relations::{
    lc,
    r1cs::{ConstraintSystemRef, Namespace, SynthesisError, Variable},
};
use ark_std::Zero;

use crate::{
    circuits::{NovaConstraintSynthesizer, StepCircuit},
    commitment::CommitmentScheme,
    gadgets::multifold::{multifold, primary, secondary, NonNativeAffineVar},
    multifold::{
        self,
        nimfs::{
            NIMFSProof, R1CSInstance, R1CSShape, R1CSWitness, RelaxedR1CSInstance,
            RelaxedR1CSWitness, SecondaryCircuit,
        },
    },
};

pub const SQUEEZE_NATIVE_ELEMENTS_NUM: usize = 1;

/// Leading `Variable::One` + 1 hash.
pub const AUGMENTED_CIRCUIT_NUM_IO: usize = 2;

pub enum NovaAugmentedCircuitInput<G1, G2, C1, C2, RO>
where
    G1: SWCurveConfig,
    G2: SWCurveConfig,
    C1: CommitmentScheme<Projective<G1>, Commitment = Projective<G1>>,
    C2: CommitmentScheme<Projective<G2>, Commitment = Projective<G2>>,
{
    Base {
        vk: G1::ScalarField,
        z_0: Vec<G1::ScalarField>,
    },
    NonBase(NovaAugmentedCircuitNonBaseInput<G1, G2, C1, C2, RO>),
}

pub struct NovaAugmentedCircuitNonBaseInput<G1, G2, C1, C2, RO>
where
    G1: SWCurveConfig,
    G2: SWCurveConfig,
    C1: CommitmentScheme<Projective<G1>, Commitment = Projective<G1>>,
    C2: CommitmentScheme<Projective<G2>, Commitment = Projective<G2>>,
{
    pub vk: G1::ScalarField,
    pub i: G1::ScalarField,
    pub z_0: Vec<G1::ScalarField>,
    pub z_i: Vec<G1::ScalarField>,
    pub U: RelaxedR1CSInstance<G1, C1>,
    pub U_secondary: RelaxedR1CSInstance<G2, C2>,
    pub u: R1CSInstance<G1, C1>,
    pub proof: NIMFSProof<G1, G2, C1, C2, RO>,
}

impl<G1, G2, C1, C2, RO> Clone for NovaAugmentedCircuitNonBaseInput<G1, G2, C1, C2, RO>
where
    G1: SWCurveConfig,
    G2: SWCurveConfig,
    C1: CommitmentScheme<Projective<G1>, Commitment = Projective<G1>>,
    C2: CommitmentScheme<Projective<G2>, Commitment = Projective<G2>>,
{
    fn clone(&self) -> Self {
        Self {
            vk: self.vk,
            i: self.i,
            z_0: self.z_0.clone(),
            z_i: self.z_i.clone(),
            U: self.U.clone(),
            U_secondary: self.U_secondary.clone(),
            u: self.u.clone(),
            proof: self.proof.clone(),
        }
    }
}

impl<G1, G2, C1, C2, RO> NovaAugmentedCircuitNonBaseInput<G1, G2, C1, C2, RO>
where
    G1: SWCurveConfig,
    G2: SWCurveConfig<BaseField = G1::ScalarField, ScalarField = G1::BaseField>,
    G1::BaseField: PrimeField + Absorb,
    G2::BaseField: PrimeField + Absorb,
    C1: CommitmentScheme<Projective<G1>, Commitment = Projective<G1>>,
    C2: CommitmentScheme<Projective<G2>, Commitment = Projective<G2>>,
    RO: SpongeWithGadget<G1::ScalarField>,
    RO::Var: CryptographicSpongeVar<G1::ScalarField, RO, Parameters = RO::Config>,
{
    fn new(
        ro_config: &<RO::Var as CryptographicSpongeVar<G1::ScalarField, RO>>::Parameters,
        vk: &G1::ScalarField,
        z_0: &[G1::ScalarField],
    ) -> Result<Self, SynthesisError> {
        let i = G1::ScalarField::ZERO;
        let z_i = vec![G1::ScalarField::ZERO; z_0.len()];

        let shape = R1CSShape::<G1>::new(0, 0, AUGMENTED_CIRCUIT_NUM_IO, &[], &[], &[]).unwrap();
        let shape_secondary = multifold::secondary::Circuit::<G1>::setup_shape::<G2>()?;

        let U = RelaxedR1CSInstance::<G1, C1>::new(&shape);
        let W = RelaxedR1CSWitness::<G1>::zero(&shape);

        let U_secondary = RelaxedR1CSInstance::<G2, C2>::new(&shape_secondary);
        let W_secondary = RelaxedR1CSWitness::<G2>::zero(&shape_secondary);

        let u = R1CSInstance::<G1, C1>::new(
            &shape,
            &Projective::zero(),
            &[G1::ScalarField::ONE; AUGMENTED_CIRCUIT_NUM_IO],
        )
        .unwrap();
        let w = R1CSWitness::<G1>::zero(&shape);
        let (proof, ..) =
            match NIMFSProof::<G1, G2, C1, C2, RO>::prove::<multifold::secondary::Circuit<G1>>(
                &C1::setup(0),
                &C2::setup(0),
                ro_config,
                vk,
                (&shape, &shape_secondary),
                (&U, &W),
                (&U_secondary, &W_secondary),
                (&u, &w),
            ) {
                Ok(proof) => proof,
                Err(multifold::Error::Synthesis(err)) => return Err(err),
                _ => unreachable!(),
            };

        Ok(Self {
            vk: *vk,
            i,
            z_0: z_0.to_owned(),
            z_i,
            U,
            U_secondary,
            u,
            proof,
        })
    }
}

pub struct NovaAugmentedCircuitInputVar<G1, G2, C1, C2, RO>
where
    G1: SWCurveConfig,
    G2: SWCurveConfig,
    G1::BaseField: PrimeField,
    G2::BaseField: PrimeField,
    C1: CommitmentScheme<Projective<G1>, Commitment = Projective<G1>>,
    C2: CommitmentScheme<Projective<G2>, Commitment = Projective<G2>>,
    RO: SpongeWithGadget<G1::ScalarField>,
{
    vk: FpVar<G1::ScalarField>,
    i: FpVar<G1::ScalarField>,
    z_0: Vec<FpVar<G1::ScalarField>>,
    z_i: Vec<FpVar<G1::ScalarField>>,
    U: primary::RelaxedR1CSInstanceVar<G1, C1>,
    U_secondary: secondary::RelaxedR1CSInstanceVar<G2, C2>,
    u: primary::R1CSInstanceVar<G1, C1>,

    // proof
    commitment_T: NonNativeAffineVar<G1>,
    proof_secondary: (secondary::ProofVar<G2, C2>, secondary::ProofVar<G2, C2>),

    _random_oracle: PhantomData<RO>,
}

impl<G1, G2, C1, C2, RO>
    AllocVar<NovaAugmentedCircuitNonBaseInput<G1, G2, C1, C2, RO>, G1::ScalarField>
    for NovaAugmentedCircuitInputVar<G1, G2, C1, C2, RO>
where
    G1: SWCurveConfig,
    G2: SWCurveConfig<BaseField = G1::ScalarField, ScalarField = G1::BaseField>,
    G1::BaseField: PrimeField,
    G2::BaseField: PrimeField,
    C1: CommitmentScheme<Projective<G1>, Commitment = Projective<G1>>,
    C2: CommitmentScheme<Projective<G2>, Commitment = Projective<G2>>,
    RO: SpongeWithGadget<G1::ScalarField>,
    RO::Var: CryptographicSpongeVar<G1::ScalarField, RO, Parameters = RO::Config>,
{
    fn new_variable<T: Borrow<NovaAugmentedCircuitNonBaseInput<G1, G2, C1, C2, RO>>>(
        cs: impl Into<Namespace<G1::ScalarField>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        let ns = cs.into();
        let cs = ns.cs();

        let input = f()?;
        let input = input.borrow();

        let vk = FpVar::new_variable(cs.clone(), || Ok(input.vk), mode)?;
        let i = FpVar::new_variable(cs.clone(), || Ok(input.i), mode)?;
        let z_0 = input
            .z_0
            .iter()
            .map(|z| FpVar::new_variable(cs.clone(), || Ok(z), mode))
            .collect::<Result<_, _>>()?;
        let z_i = input
            .z_i
            .iter()
            .map(|z| FpVar::new_variable(cs.clone(), || Ok(z), mode))
            .collect::<Result<_, _>>()?;
        let U = primary::RelaxedR1CSInstanceVar::new_variable(cs.clone(), || Ok(&input.U), mode)?;
        let U_secondary = secondary::RelaxedR1CSInstanceVar::new_variable(
            cs.clone(),
            || Ok(&input.U_secondary),
            mode,
        )?;
        let u = primary::R1CSInstanceVar::new_variable(cs.clone(), || Ok(&input.u), mode)?;

        let commitment_T =
            NonNativeAffineVar::new_variable(cs.clone(), || Ok(&input.proof.commitment_T), mode)?;

        // proof variables are cloned from the allocated input.
        let u_secondary = (
            secondary::ProofVar::from_allocated_input::<G1>(
                &U.commitment_E,
                &commitment_T,
                &input.proof.commitment_E_proof,
                mode,
            )?,
            secondary::ProofVar::from_allocated_input::<G1>(
                &U.commitment_W,
                &u.commitment_W,
                &input.proof.commitment_W_proof,
                mode,
            )?,
        );

        Ok(Self {
            vk,
            i,
            z_0,
            z_i,
            U,
            U_secondary,
            u,
            commitment_T,
            proof_secondary: u_secondary,
            _random_oracle: PhantomData,
        })
    }
}

pub struct NovaAugmentedCircuit<'a, G1, G2, C1, C2, RO, SC>
where
    G1: SWCurveConfig,
    G2: SWCurveConfig,
    C1: CommitmentScheme<Projective<G1>, Commitment = Projective<G1>>,
    C2: CommitmentScheme<Projective<G2>, Commitment = Projective<G2>>,
    RO: SpongeWithGadget<G1::ScalarField>,
    SC: StepCircuit<G1::ScalarField>,
{
    ro_config: &'a <RO::Var as CryptographicSpongeVar<G1::ScalarField, RO>>::Parameters,
    step_circuit: &'a SC,
    input: NovaAugmentedCircuitInput<G1, G2, C1, C2, RO>,
}

impl<'a, G1, G2, C1, C2, RO, SC> NovaAugmentedCircuit<'a, G1, G2, C1, C2, RO, SC>
where
    G1: SWCurveConfig,
    G2: SWCurveConfig,
    C1: CommitmentScheme<Projective<G1>, Commitment = Projective<G1>>,
    C2: CommitmentScheme<Projective<G2>, Commitment = Projective<G2>>,
    RO: SpongeWithGadget<G1::ScalarField>,
    SC: StepCircuit<G1::ScalarField>,
{
    pub fn new(
        ro_config: &'a <RO::Var as CryptographicSpongeVar<G1::ScalarField, RO>>::Parameters,
        step_circuit: &'a SC,
        input: NovaAugmentedCircuitInput<G1, G2, C1, C2, RO>,
    ) -> Self {
        Self {
            ro_config,
            step_circuit,
            input,
        }
    }
}

impl<G1, G2, C1, C2, RO, SC> NovaConstraintSynthesizer<G1::ScalarField>
    for NovaAugmentedCircuit<'_, G1, G2, C1, C2, RO, SC>
where
    G1: SWCurveConfig,
    G2: SWCurveConfig<BaseField = G1::ScalarField, ScalarField = G1::BaseField>,
    G1::BaseField: PrimeField + Absorb,
    G2::BaseField: PrimeField + Absorb,
    C1: CommitmentScheme<Projective<G1>, Commitment = Projective<G1>>,
    C2: CommitmentScheme<Projective<G2>, Commitment = Projective<G2>>,
    RO: SpongeWithGadget<G1::ScalarField>,
    RO::Var: CryptographicSpongeVar<G1::ScalarField, RO, Parameters = RO::Config>,
    SC: StepCircuit<G1::ScalarField>,
{
    fn generate_constraints(
        self,
        cs: ConstraintSystemRef<G1::ScalarField>,
    ) -> Result<Vec<FpVar<G1::ScalarField>>, SynthesisError> {
        let input =
            NovaAugmentedCircuitInputVar::<G1, G2, C1, C2, RO>::new_witness(cs.clone(), || {
                match &self.input {
                    NovaAugmentedCircuitInput::Base { z_0, vk } => {
                        NovaAugmentedCircuitNonBaseInput::new(self.ro_config, vk, z_0)
                    }
                    NovaAugmentedCircuitInput::NonBase(input) => {
                        assert!(!input.i.is_zero());
                        Ok(input.clone())
                    }
                }
            })?;

        let is_base_case = input.i.is_zero()?;
        let U_base = primary::RelaxedR1CSInstanceVar::<G1, C1>::new_constant(
            cs.clone(),
            RelaxedR1CSInstance {
                commitment_W: Projective::zero(),
                commitment_E: Projective::zero(),
                X: vec![G1::ScalarField::ZERO; AUGMENTED_CIRCUIT_NUM_IO],
            },
        )?;
        let U_secondary_base = secondary::RelaxedR1CSInstanceVar::<G2, C2>::new_constant(
            cs.clone(),
            RelaxedR1CSInstance {
                commitment_W: Projective::zero(),
                commitment_E: Projective::zero(),
                X: vec![G2::ScalarField::ZERO; multifold::secondary::Circuit::<G1>::NUM_IO],
            },
        )?;

        let mut random_oracle = RO::Var::new(cs.clone(), self.ro_config);
        random_oracle.absorb(&input.vk)?;
        random_oracle.absorb(&input.i)?;
        random_oracle.absorb(&input.z_0)?;
        random_oracle.absorb(&input.z_i)?;
        random_oracle.absorb(&input.U)?;
        random_oracle.absorb(&input.U_secondary)?;

        let hash = &random_oracle.squeeze_field_elements(SQUEEZE_NATIVE_ELEMENTS_NUM)?[0];
        let hash_matches = hash.is_eq(&input.u.X[1])?;

        is_base_case
            .or(&hash_matches)?
            .enforce_equal(&Boolean::TRUE)?;

        let (U, U_secondary) = multifold::<G1, G2, C1, C2, RO>(
            self.ro_config,
            &input.vk,
            &input.U,
            &input.U_secondary,
            &input.u,
            &input.commitment_T,
            (&input.proof_secondary.0, &input.proof_secondary.1),
        )?;

        let U = is_base_case.select(&U_base, &U)?;
        let U_secondary = is_base_case.select(&U_secondary_base, &U_secondary)?;
        let z: Vec<FpVar<G1::ScalarField>> = input
            .z_0
            .iter()
            .zip(&input.z_i)
            .map(|(z_0, z_i)| is_base_case.select(z_0, z_i))
            .collect::<Result<_, _>>()?;

        let z_next = <SC as StepCircuit<G1::ScalarField>>::generate_constraints(
            self.step_circuit,
            cs.clone(),
            &input.i,
            &z,
        )?;
        let i_next = &input.i + FpVar::one();

        let mut random_oracle = RO::Var::new(cs.clone(), self.ro_config);
        random_oracle.absorb(&input.vk)?;
        random_oracle.absorb(&i_next)?;
        random_oracle.absorb(&input.z_0)?;
        random_oracle.absorb(&z_next)?;
        random_oracle.absorb(&U)?;
        random_oracle.absorb(&U_secondary)?;

        let hash = &random_oracle.squeeze_field_elements(SQUEEZE_NATIVE_ELEMENTS_NUM)?[0];
        let FpVar::Var(allocated_hash) = hash else {
            unreachable!()
        };
        let hash_input = cs.new_input_variable(|| hash.value())?;

        cs.enforce_constraint(
            lc!() + hash_input,
            lc!() + Variable::One,
            lc!() + allocated_hash.variable,
        )?;

        Ok(z_next)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{pedersen::PedersenCommitment, poseidon_config};
    use ark_crypto_primitives::sponge::poseidon::PoseidonSponge;
    use ark_relations::r1cs::ConstraintSystem;

    struct TestCircuit;

    impl<F: PrimeField> StepCircuit<F> for TestCircuit {
        const ARITY: usize = 0;

        fn generate_constraints(
            &self,
            _: ConstraintSystemRef<F>,
            _: &FpVar<F>,
            z: &[FpVar<F>],
        ) -> Result<Vec<FpVar<F>>, SynthesisError> {
            Ok(z.to_owned())
        }
    }

    #[test]
    fn step_circuit_base_step() {
        step_circuit_base_step_with_cycle::<
            ark_pallas::PallasConfig,
            ark_vesta::VestaConfig,
            PedersenCommitment<ark_pallas::Projective>,
            PedersenCommitment<ark_vesta::Projective>,
        >()
        .unwrap()
    }

    fn step_circuit_base_step_with_cycle<G1, G2, C1, C2>() -> Result<(), SynthesisError>
    where
        G1: SWCurveConfig,
        G2: SWCurveConfig<BaseField = G1::ScalarField, ScalarField = G1::BaseField>,
        G1::BaseField: PrimeField + Absorb,
        G2::BaseField: PrimeField + Absorb,
        C1: CommitmentScheme<Projective<G1>, Commitment = Projective<G1>>,
        C2: CommitmentScheme<Projective<G2>, Commitment = Projective<G2>>,
        C1::PP: Clone,
    {
        let ro_config = poseidon_config();

        let input =
            NovaAugmentedCircuitInput::<G1, G2, C1, C2, PoseidonSponge<G1::ScalarField>>::Base {
                z_0: Vec::new(),
                vk: G1::ScalarField::ZERO,
            };

        let circuit = NovaAugmentedCircuit {
            ro_config: &ro_config,
            step_circuit: &TestCircuit,
            input,
        };
        let cs = ConstraintSystem::new_ref();

        circuit.generate_constraints(cs.clone())?;

        assert!(cs.is_satisfied()?);

        Ok(())
    }
}
