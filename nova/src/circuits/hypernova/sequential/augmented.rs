// !!! Please review the contents of `project_augmented_circuit_size` in
// !!!
// !!!    .../src/circuits/hypernova/sequential/util.rs
// !!!
// !!! before modifying this circuit.

use std::{borrow::Borrow, marker::PhantomData};

use ark_crypto_primitives::sponge::{
    constraints::{CryptographicSpongeVar, SpongeWithGadget},
    Absorb,
};
use ark_ec::short_weierstrass::{Projective, SWCurveConfig};
use ark_ff::{AdditiveGroup, Field, PrimeField};
use ark_r1cs_std::{
    alloc::{AllocVar, AllocationMode},
    eq::EqGadget,
    fields::{fp::FpVar, FieldVar},
    R1CSVar,
};
use ark_relations::{
    lc,
    r1cs::{ConstraintSystemRef, Namespace, SynthesisError, Variable},
};
use ark_std::Zero;
use ark_spartan::polycommitments::PolyCommitmentScheme;

use crate::{
    circuits::hypernova::{HyperNovaConstraintSynthesizer, StepCircuit},
    commitment::CommitmentScheme,
    folding::hypernova::cyclefold::{
        self,
        nimfs::{NIMFSProof, R1CSShape, RelaxedR1CSInstance,
                CCSShape, CCSInstance, CCSWitness, LCCSInstance},
        secondary::Circuit as SecondaryCircuit,
    },
    gadgets::cyclefold::{hypernova::{multifold, primary}, secondary},
    gadgets::nonnative::short_weierstrass::NonNativeAffineVar,
};

pub const SQUEEZE_NATIVE_ELEMENTS_NUM: usize = 1;

/// Leading `Variable::One` + 1 hash.
pub const AUGMENTED_CIRCUIT_NUM_IO: usize = 2;

pub enum HyperNovaAugmentedCircuitInput<G1, G2, C1, C2, RO>
where
    G1: SWCurveConfig,
    G2: SWCurveConfig,
    C1: PolyCommitmentScheme<Projective<G1>>,
    C2: CommitmentScheme<Projective<G2>>,
{
    Base {
        vk: G1::ScalarField,
        z_0: Vec<G1::ScalarField>,
    },
    NonBase(HyperNovaAugmentedCircuitNonBaseInput<G1, G2, C1, C2, RO>),
}

pub struct HyperNovaAugmentedCircuitNonBaseInput<G1, G2, C1, C2, RO>
where
    G1: SWCurveConfig,
    G2: SWCurveConfig,
    C1: PolyCommitmentScheme<Projective<G1>>,
    C2: CommitmentScheme<Projective<G2>>,
{
    pub vk: G1::ScalarField,
    pub i: G1::ScalarField,
    pub z_0: Vec<G1::ScalarField>,
    pub z_i: Vec<G1::ScalarField>,
    pub U: LCCSInstance<G1, C1>,
    pub U_secondary: RelaxedR1CSInstance<G2, C2>,
    pub u: CCSInstance<G1, C1>,
    pub proof: NIMFSProof<G1, G2, C1, C2, RO>,
}

impl<G1, G2, C1, C2, RO> Clone for HyperNovaAugmentedCircuitNonBaseInput<G1, G2, C1, C2, RO>
where
    G1: SWCurveConfig,
    G2: SWCurveConfig,
    C1: PolyCommitmentScheme<Projective<G1>>,
    C2: CommitmentScheme<Projective<G2>>,
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

pub struct HyperNovaAugmentedCircuitInputVar<G1, G2, C1, C2, RO>
where
    G1: SWCurveConfig,
    G2: SWCurveConfig,
    G1::BaseField: PrimeField,
    G2::BaseField: PrimeField,
    C1: PolyCommitmentScheme<Projective<G1>>,
    C2: CommitmentScheme<Projective<G2>>,
    RO: SpongeWithGadget<G1::ScalarField>,
{
    vk: FpVar<G1::ScalarField>,
    i: FpVar<G1::ScalarField>,
    z_0: Vec<FpVar<G1::ScalarField>>,
    z_i: Vec<FpVar<G1::ScalarField>>,
    U: primary::LCCSInstanceFromR1CSVar<G1, C1>,
    U_secondary: secondary::RelaxedR1CSInstanceVar<G2, C2>,
    u: primary::CCSInstanceFromR1CSVar<G1, C1>,
    commitment_W_proof: secondary::ProofVar<G2, C2>,
    hypernova_proof: primary::ProofFromR1CSVar<G1, RO>,
    _random_oracle: PhantomData<RO>,
}

impl<G1, G2, C1, C2, RO> AllocVar<HyperNovaAugmentedCircuitInput<G1, G2, C1, C2, RO>, G1::ScalarField>
    for HyperNovaAugmentedCircuitInputVar<G1, G2, C1, C2, RO>
where
    G1: SWCurveConfig,
    G2: SWCurveConfig<BaseField = G1::ScalarField, ScalarField = G1::BaseField>,
    G1::BaseField: PrimeField,
    G2::BaseField: PrimeField,
    C1: PolyCommitmentScheme<Projective<G1>>,
    C2: CommitmentScheme<Projective<G2>>,
    RO: SpongeWithGadget<G1::ScalarField>,
    RO::Var: CryptographicSpongeVar<G1::ScalarField, RO, Parameters = RO::Config>,
{
    fn new_variable<T: Borrow<HyperNovaAugmentedCircuitInput<G1, G2, C1, C2, RO>>>(
        cs: impl Into<Namespace<G1::ScalarField>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        let ns = cs.into();
        let cs = ns.cs();

        let input = f()?;
        let input = input.borrow();

        let input = match input {
            HyperNovaAugmentedCircuitInput::Base { vk, z_0 } => {
                let shape =
                    CCSShape::from(R1CSShape::<G1>::new(0, 0, AUGMENTED_CIRCUIT_NUM_IO, &[], &[], &[]).unwrap());
                let shape_secondary = cyclefold::secondary::setup_shape::<G1, G2>()?;

                let U = LCCSInstance::<G1, C1>::base(&shape);
                let U_secondary = RelaxedR1CSInstance::<G2, C2>::new(&shape_secondary);
                let u = CCSInstance::<G1, C1>::new(
                    &shape,
                    &vec![Projective::zero()].into(),
                    &[G1::ScalarField::ONE; AUGMENTED_CIRCUIT_NUM_IO],
                )
                .unwrap();
                HyperNovaAugmentedCircuitNonBaseInput {
                    vk: *vk,
                    i: G1::ScalarField::ZERO,
                    z_0: z_0.clone(),
                    z_i: z_0.clone(),
                    U,
                    U_secondary,
                    u,
                    proof: NIMFSProof::default(),
                }
            }
            HyperNovaAugmentedCircuitInput::NonBase(non_base) => non_base.clone(),
        };

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
        let U = primary::LCCSInstanceFromR1CSVar::new_variable(cs.clone(), || Ok(&input.U), mode)?;
        let U_secondary = secondary::RelaxedR1CSInstanceVar::new_variable(
            cs.clone(),
            || Ok(&input.U_secondary),
            mode,
        )?;
        let u = primary::CCSInstanceFromR1CSVar::new_variable(cs.clone(), || Ok(&input.u), mode)?;

        let hypernova_proof =
            primary::ProofFromR1CSVar::<G1, RO>::new_input(
                cs.clone(),
                || Ok(&input.proof.hypernova_proof),
            )?;
        let commitment_W_proof =
            secondary::ProofVar::<G2, C2>::new_input(cs.clone(), || Ok(&input.proof.commitment_W_proof))?;

        Ok(Self {
            vk,
            i,
            z_0,
            z_i,
            U,
            U_secondary,
            u,
            commitment_W_proof,
            hypernova_proof,
            _random_oracle: PhantomData,
        })
    }
}

pub struct HyperNovaAugmentedCircuit<'a, G1, G2, C1, C2, RO, SC>
where
    G1: SWCurveConfig,
    G2: SWCurveConfig,
    C1: PolyCommitmentScheme<Projective<G1>>,
    C2: CommitmentScheme<Projective<G2>>,
    RO: SpongeWithGadget<G1::ScalarField>,
    SC: StepCircuit<G1::ScalarField>,
{
    ro_config: &'a <RO::Var as CryptographicSpongeVar<G1::ScalarField, RO>>::Parameters,
    step_circuit: &'a SC,
    s: usize,
    input: HyperNovaAugmentedCircuitInput<G1, G2, C1, C2, RO>,
}

impl<'a, G1, G2, C1, C2, RO, SC> HyperNovaAugmentedCircuit<'a, G1, G2, C1, C2, RO, SC>
where
    G1: SWCurveConfig,
    G2: SWCurveConfig<BaseField = G1::ScalarField, ScalarField = G1::BaseField>,
    G1::BaseField: PrimeField + Absorb,
    G2::BaseField: PrimeField + Absorb,
    C1: PolyCommitmentScheme<Projective<G1>>,
    C2: CommitmentScheme<Projective<G2>>,
    RO: SpongeWithGadget<G1::ScalarField>,
    RO::Var: CryptographicSpongeVar<G1::ScalarField, RO, Parameters = RO::Config>,
    SC: StepCircuit<G1::ScalarField>,
{
    pub fn new(
        ro_config: &'a <RO::Var as CryptographicSpongeVar<G1::ScalarField, RO>>::Parameters,
        step_circuit: &'a SC,
        s: usize,
        input: HyperNovaAugmentedCircuitInput<G1, G2, C1, C2, RO>,
    ) -> Self {
        Self { ro_config, step_circuit, s, input }
    }

    fn generate_constraints_from_r1cs(
        self,
        cs: ConstraintSystemRef<G1::ScalarField>,
    ) -> Result<Vec<FpVar<G1::ScalarField>>, SynthesisError> {
        let input =
            HyperNovaAugmentedCircuitInputVar::<G1, G2, C1, C2, RO>::new_witness(cs.clone(), || {
                Ok(&self.input)
            })?;

        let is_base_case = input.i.is_zero()?;
        let should_enforce = is_base_case.not();

        const NUM_MATRICES: usize = 3;

        let U_base = primary::LCCSInstanceFromR1CSVar::<G1, C1>::new_constant(
            cs.clone(),
            LCCSInstance {
                commitment_W: vec![Projective::zero()].into(),
                X: vec![G1::ScalarField::ZERO; AUGMENTED_CIRCUIT_NUM_IO],
                rs: vec![G1::ScalarField::ZERO; self.s],
                vs: vec![G1::ScalarField::ZERO; NUM_MATRICES],
            },
        )?;
        let U_secondary_base = secondary::RelaxedR1CSInstanceVar::<G2, C2>::new_constant(
            cs.clone(),
            RelaxedR1CSInstance {
                commitment_W: Projective::zero().into(),
                commitment_E: Projective::zero().into(),
                X: vec![G2::ScalarField::ZERO; SecondaryCircuit::<G1>::NUM_IO],
            },
        )?;

        for (z_0, z_i) in input.z_0.iter().zip(&input.z_i) {
            z_0.conditional_enforce_equal(z_i, &is_base_case)?;
        }

        // NOTE: Review `project_augmented_circuit_size` for context.
        #[cfg(debug_assertions)]
        println!("re Augmented Circuit Constraint Projection: {} constraints before step circuit", cs.num_constraints());

        let z_next = <SC as StepCircuit<G1::ScalarField>>::generate_constraints(
            self.step_circuit,
            cs.clone(),
            &input.i,
            &input.z_i,
        )?;

        // NOTE: Review `project_augmented_circuit_size` for context.
        #[cfg(debug_assertions)]
        println!("re Augmented Circuit Constraint Projection: {} constraints after step circuit", cs.num_constraints());

        let mut random_oracle = RO::Var::new(cs.clone(), self.ro_config);
        random_oracle.absorb(&input.vk)?;
        random_oracle.absorb(&input.i)?;
        random_oracle.absorb(&input.z_0)?;
        random_oracle.absorb(&input.z_i)?;
        random_oracle.absorb(&input.U.var())?;
        random_oracle.absorb(&input.U_secondary)?;

        let hash = &random_oracle.squeeze_field_elements(SQUEEZE_NATIVE_ELEMENTS_NUM)?[0];
        hash.conditional_enforce_equal(&input.u.var().X[1], &should_enforce)?;

        let (U, U_secondary) = multifold::<G1, G2, C1, C2, RO>(
            self.ro_config,
            &input.vk,
            self.s,
            &input.U,
            &input.U_secondary,
            &input.u,
            &input.commitment_W_proof,
            &input.hypernova_proof,
            &should_enforce,
        )?;

        let U = is_base_case.select(U_base.var(), U.var())?; // returns an LCCSInstanceVar, not an LCCSInstanceFromR1CSVar

        let U_secondary = is_base_case.select(&U_secondary_base, &U_secondary)?;
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

impl<G1, G2, C1, C2, RO, SC> HyperNovaConstraintSynthesizer<G1::ScalarField>
    for HyperNovaAugmentedCircuit<'_, G1, G2, C1, C2, RO, SC>
where
    G1: SWCurveConfig,
    G2: SWCurveConfig<BaseField = G1::ScalarField, ScalarField = G1::BaseField>,
    G1::BaseField: PrimeField + Absorb,
    G2::BaseField: PrimeField + Absorb,
    C1: PolyCommitmentScheme<Projective<G1>>,
    C2: CommitmentScheme<Projective<G2>>,
    RO: SpongeWithGadget<G1::ScalarField>,
    RO::Var: CryptographicSpongeVar<G1::ScalarField, RO, Parameters = RO::Config>,
    SC: StepCircuit<G1::ScalarField>,
{
    fn generate_constraints(
        self,
        cs: ConstraintSystemRef<G1::ScalarField>,
    ) -> Result<Vec<FpVar<G1::ScalarField>>, SynthesisError> {
        self.generate_constraints_from_r1cs(cs)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{pedersen::PedersenCommitment, poseidon_config};
    use ark_ec::short_weierstrass::{Projective, SWCurveConfig};
    use ark_crypto_primitives::sponge::poseidon::PoseidonSponge;
    use ark_relations::r1cs::ConstraintSystem;
    use ark_spartan::polycommitments::zeromorph::Zeromorph;

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
            ark_bn254::g1::Config,
            ark_grumpkin::GrumpkinConfig,
            Zeromorph<ark_bn254::Bn254>,
            PedersenCommitment<ark_grumpkin::Projective>,
        >()
        .unwrap()
    }

    fn step_circuit_base_step_with_cycle<G1, G2, C1, C2>() -> Result<(), SynthesisError>
    where
        G1: SWCurveConfig,
        G2: SWCurveConfig<BaseField = G1::ScalarField, ScalarField = G1::BaseField>,
        G1::BaseField: PrimeField + Absorb,
        G2::BaseField: PrimeField + Absorb,
        C1: PolyCommitmentScheme<Projective<G1>>,
        C2: CommitmentScheme<Projective<G2>>,
        C1::PolyCommitmentKey: Clone,
    {
        let ro_config = poseidon_config();

        let input =
            HyperNovaAugmentedCircuitInput::<G1, G2, C1, C2, PoseidonSponge<G1::ScalarField>>::Base {
                z_0: Vec::new(),
                vk: G1::ScalarField::ZERO,
            };

        //let s = project_augmented_circuit_size(&TestCircuit);
        let s: usize = 0;

        let circuit = HyperNovaAugmentedCircuit {
            ro_config: &ro_config,
            step_circuit: &TestCircuit,
            s,
            input,
        };
        let cs = ConstraintSystem::new_ref();

        circuit.generate_constraints_from_r1cs(cs.clone())?;

        assert!(cs.is_satisfied()?);

        Ok(())
    }
}
