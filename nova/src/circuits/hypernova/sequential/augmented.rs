// !!! Please review the contents of `project_augmented_circuit_size` in
// !!!
// !!!    .../src/circuits/hypernova/mod.rs
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
    r1cs::{ConstraintSystem, ConstraintSystemRef, Namespace, SynthesisError, Variable},
};
use ark_spartan::polycommitments::PolyCommitmentScheme;
use ark_std::Zero;

use crate::{
    circuits::hypernova::{HyperNovaConstraintSynthesizer, StepCircuit},
    commitment::CommitmentScheme,
    folding::hypernova::cyclefold::{
        self,
        nimfs::{
            CCSInstance, CCSShape, HNProof, LCCSInstance, NIMFSProof, R1CSShape,
            RelaxedR1CSInstance,
        },
        secondary::Circuit as SecondaryCircuit,
    },
    folding::hypernova::ml_sumcheck::{protocol::prover::ProverMsg, PolynomialInfo},
    gadgets::cyclefold::{
        hypernova::{multifold, primary},
        secondary,
    },
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
        U: LCCSInstance<G1, C1>,
        proof: NIMFSProof<G1, G2, C1, C2, RO>,
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

    // proof
    commitment_W_proof: secondary::ProofVar<G2, C2>,
    hypernova_proof: primary::ProofFromR1CSVar<G1, RO>,

    _random_oracle: PhantomData<RO>,
}

impl<G1, G2, C1, C2, RO>
    AllocVar<HyperNovaAugmentedCircuitInput<G1, G2, C1, C2, RO>, G1::ScalarField>
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
            HyperNovaAugmentedCircuitInput::Base { vk, z_0, U, proof } => {
                let shape = CCSShape::from(
                    R1CSShape::<G1>::new(0, 0, AUGMENTED_CIRCUIT_NUM_IO, &[], &[], &[]).unwrap(),
                );
                let shape_secondary = cyclefold::secondary::setup_shape::<G1, G2>()?;

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
                    U: U.clone(),
                    U_secondary,
                    u,
                    proof: proof.clone(),
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

        let hypernova_proof = primary::ProofFromR1CSVar::<G1, RO>::new_variable(
            cs.clone(),
            || Ok(&input.proof.hypernova_proof),
            mode,
        )?;
        let commitment_W_proof = secondary::ProofVar::<G2, C2>::new_variable(
            cs.clone(),
            || Ok(&input.proof.commitment_W_proof),
            mode,
        )?;

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
    sumcheck_rounds: usize,
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
        sumcheck_rounds: usize,
        input: HyperNovaAugmentedCircuitInput<G1, G2, C1, C2, RO>,
    ) -> Self {
        Self {
            ro_config,
            step_circuit,
            sumcheck_rounds,
            input,
        }
    }

    pub fn project_augmented_circuit_size_from_r1cs(
        step_circuit: &'a SC,
    ) -> Result<(usize, usize), SynthesisError> {
        // In order to regenerate these parameters, enable the (ignored) test `calculate_circuit_constants`

        const BASE_CONSTRAINTS: u32 = 82023; // number of constraints in augmented circuit, not including step circuit or sumcheck
        const PER_SC_INPUT_CONSTRAINTS: u32 = 487; // number of additional constraints per step circuit input
        const SUMCHECK_ROUND_CONSTRAINTS: u32 = 1238; // number of additional constraints per sumcheck round

        let z_0 = vec![G1::ScalarField::ZERO; SC::ARITY];

        let cs = ConstraintSystem::new_ref();

        // step circuit size does not depend on number of sumcheck rounds, so we can just use 0 here
        let (U, proof) = HyperNovaAugmentedCircuit::<G1, G2, C1, C2, RO, SC>::base(0);

        let input = HyperNovaAugmentedCircuitInput::<G1, G2, C1, C2, RO>::Base {
            vk: G1::ScalarField::ZERO,
            z_0: z_0.clone(),
            U,
            proof,
        };

        let input = HyperNovaAugmentedCircuitInputVar::<G1, G2, C1, C2, RO>::new_witness(
            cs.clone(),
            || Ok(&input),
        )?;

        let _ = <SC as StepCircuit<G1::ScalarField>>::generate_constraints(
            step_circuit,
            cs.clone(),
            &input.i,
            &input.z_i,
        )?;

        let step_circuit_constraints = cs.num_constraints() as u32;

        let mut constraints = BASE_CONSTRAINTS
            + step_circuit_constraints
            + (SC::ARITY as u32 * PER_SC_INPUT_CONSTRAINTS);

        let mut low = 0;
        let mut high = (constraints - 1).checked_ilog2().unwrap_or(0) + 1;

        let mut eq = false;
        while !eq {
            constraints += (high - low) * SUMCHECK_ROUND_CONSTRAINTS;
            low = high;
            high = (constraints - 1).checked_ilog2().unwrap_or(0) + 1;

            eq = low == high;
        }

        Ok((high as usize, constraints as usize))
    }

    pub fn base_from_r1cs(
        sumcheck_rounds: usize,
    ) -> (LCCSInstance<G1, C1>, NIMFSProof<G1, G2, C1, C2, RO>) {
        const NUM_MATRICES: usize = 3;
        const MAX_CARDINALITY: usize = 2;

        (
            LCCSInstance {
                commitment_W: C1::Commitment::default(),
                X: vec![G1::ScalarField::ZERO; AUGMENTED_CIRCUIT_NUM_IO],
                rs: vec![G1::ScalarField::ZERO; sumcheck_rounds],
                vs: vec![G1::ScalarField::ZERO; NUM_MATRICES],
            },
            NIMFSProof {
                commitment_W_proof: cyclefold::secondary::Proof::<G2, C2>::default(),
                hypernova_proof: HNProof {
                    sumcheck_proof: vec![
                        ProverMsg {
                            evaluations: vec![<G1::ScalarField>::ZERO; MAX_CARDINALITY + 2]
                        };
                        sumcheck_rounds
                    ],
                    poly_info: PolynomialInfo::default(),
                    sigmas: vec![G1::ScalarField::ZERO; NUM_MATRICES],
                    thetas: vec![G1::ScalarField::ZERO; NUM_MATRICES],
                    _random_oracle: PhantomData,
                },
                _poly_commitment: PhantomData,
            },
        )
    }

    fn generate_constraints_from_r1cs(
        self,
        cs: ConstraintSystemRef<G1::ScalarField>,
    ) -> Result<Vec<FpVar<G1::ScalarField>>, SynthesisError> {
        let input = HyperNovaAugmentedCircuitInputVar::<G1, G2, C1, C2, RO>::new_witness(
            cs.clone(),
            || Ok(&self.input),
        )?;

        let is_base_case = input.i.is_zero()?;
        let should_enforce = is_base_case.not();

        const NUM_MATRICES: usize = 3;

        let U_base = primary::LCCSInstanceFromR1CSVar::<G1, C1>::new_constant(
            cs.clone(),
            LCCSInstance {
                commitment_W: vec![Projective::zero()].into(),
                X: vec![G1::ScalarField::ZERO; AUGMENTED_CIRCUIT_NUM_IO],
                rs: vec![G1::ScalarField::ZERO; self.sumcheck_rounds],
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
        let z_next = <SC as StepCircuit<G1::ScalarField>>::generate_constraints(
            self.step_circuit,
            cs.clone(),
            &input.i,
            &input.z_i,
        )?;

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
            self.sumcheck_rounds,
            &input.U,
            &input.U_secondary,
            &input.u,
            &input.commitment_W_proof,
            &input.hypernova_proof,
            &should_enforce,
        )?;

        let U = is_base_case.select(U_base.var(), U.var())?;
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

impl<G1, G2, C1, C2, RO, SC> HyperNovaConstraintSynthesizer<G1, G2, C1, C2, RO, SC>
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
    fn base(sumcheck_rounds: usize) -> (LCCSInstance<G1, C1>, NIMFSProof<G1, G2, C1, C2, RO>) {
        HyperNovaAugmentedCircuit::<'_, G1, G2, C1, C2, RO, SC>::base_from_r1cs(sumcheck_rounds)
    }

    fn project_augmented_circuit_size(
        step_circuit: &'_ SC,
    ) -> Result<(usize, usize), SynthesisError> {
        HyperNovaAugmentedCircuit::<'_, G1, G2, C1, C2, RO, SC>::project_augmented_circuit_size_from_r1cs(step_circuit)
    }

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
    use ark_crypto_primitives::sponge::poseidon::PoseidonSponge;
    use ark_ec::short_weierstrass::{Projective, SWCurveConfig};
    use ark_relations::r1cs::ConstraintSystem;
    use ark_spartan::polycommitments::zeromorph::Zeromorph;

    struct TestCircuit;
    struct TestCircuitAlt;

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

    impl<F: PrimeField> StepCircuit<F> for TestCircuitAlt {
        const ARITY: usize = 1;

        fn generate_constraints(
            &self,
            _: ConstraintSystemRef<F>,
            _: &FpVar<F>,
            z: &[FpVar<F>],
        ) -> Result<Vec<FpVar<F>>, SynthesisError> {
            Ok(z.to_owned())
        }
    }

    type SC = TestCircuit;
    type SCAlt = TestCircuitAlt;

    #[ignore]
    #[test]
    fn calculate_circuit_constants() {
        calculate_circuit_constants_with_cycle::<
            ark_bn254::g1::Config,
            ark_grumpkin::GrumpkinConfig,
            Zeromorph<ark_bn254::Bn254>,
            PedersenCommitment<ark_grumpkin::Projective>,
        >()
        .unwrap()
    }

    fn calculate_circuit_constants_with_cycle<G1, G2, C1, C2>() -> Result<(), SynthesisError>
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

        let z_0 = vec![G1::ScalarField::ZERO; <TestCircuit as StepCircuit<G1::ScalarField>>::ARITY];
        let z_0_alt =
            vec![G1::ScalarField::ZERO; <TestCircuitAlt as StepCircuit<G1::ScalarField>>::ARITY];

        // Constraint Generation #1: The Step Circuit

        let cs = ConstraintSystem::new_ref();

        let (U, proof) =
            HyperNovaAugmentedCircuit::<G1, G2, C1, C2, PoseidonSponge<G1::ScalarField>, SC>::base(
                1,
            );

        let input = HyperNovaAugmentedCircuitInput::<
            G1,
            G2,
            C1,
            C2,
            PoseidonSponge<G1::ScalarField>,
        >::Base {
            vk: G1::ScalarField::ZERO,
            z_0: z_0.clone(),
            U,
            proof,
        };

        let input = HyperNovaAugmentedCircuitInputVar::<
            G1,
            G2,
            C1,
            C2,
            PoseidonSponge<G1::ScalarField>,
        >::new_witness(cs.clone(), || Ok(&input))?;

        let _ = SC::generate_constraints(&TestCircuit, cs.clone(), &input.i, &input.z_i)?;

        let step_circuit_constraints = cs.num_constraints();

        // Constraint Generation #2: The Augmented Circuit with one sumcheck round and no step circuit inputs

        let cs = ConstraintSystem::new_ref();

        let (U, proof) =
            HyperNovaAugmentedCircuit::<G1, G2, C1, C2, PoseidonSponge<G1::ScalarField>, SC>::base(
                1,
            );

        let input = HyperNovaAugmentedCircuitInput::<
            G1,
            G2,
            C1,
            C2,
            PoseidonSponge<G1::ScalarField>,
        >::Base {
            vk: G1::ScalarField::ZERO,
            z_0: z_0.clone(),
            U,
            proof,
        };

        let circuit = HyperNovaAugmentedCircuit::new(&ro_config, &TestCircuit, 1, input);
        let _ = HyperNovaConstraintSynthesizer::generate_constraints(circuit, cs.clone())?;

        cs.finalize();

        let base_circuit_constraints = cs.num_constraints() - step_circuit_constraints;

        // Constraint Generation #3: The Augmented Circuit with one sumcheck round and one step circuit input

        let cs = ConstraintSystem::new_ref();

        let (U, proof) = HyperNovaAugmentedCircuit::<
            G1,
            G2,
            C1,
            C2,
            PoseidonSponge<G1::ScalarField>,
            SCAlt,
        >::base(1);

        let input = HyperNovaAugmentedCircuitInput::<
            G1,
            G2,
            C1,
            C2,
            PoseidonSponge<G1::ScalarField>,
        >::Base {
            vk: G1::ScalarField::ZERO,
            z_0: z_0_alt.clone(),
            U,
            proof,
        };

        let circuit = HyperNovaAugmentedCircuit::new(&ro_config, &TestCircuitAlt, 1, input);
        let _ = HyperNovaConstraintSynthesizer::generate_constraints(circuit, cs.clone())?;

        cs.finalize();

        let per_sc_input_constraints =
            (cs.num_constraints() - step_circuit_constraints) - base_circuit_constraints;

        // Constraint Generation #4: The Augmented Circuit with two sumcheck rounds and no step circuit inputs

        let cs = ConstraintSystem::new_ref();

        let (U, proof) =
            HyperNovaAugmentedCircuit::<G1, G2, C1, C2, PoseidonSponge<G1::ScalarField>, SC>::base(
                2,
            );

        let input = HyperNovaAugmentedCircuitInput::<
            G1,
            G2,
            C1,
            C2,
            PoseidonSponge<G1::ScalarField>,
        >::Base {
            vk: G1::ScalarField::ZERO,
            z_0: z_0.clone(),
            U,
            proof,
        };

        let circuit = HyperNovaAugmentedCircuit::new(&ro_config, &TestCircuit, 2, input);
        let _ = HyperNovaConstraintSynthesizer::generate_constraints(circuit, cs.clone())?;

        cs.finalize();

        let sumcheck_round_constraints =
            (cs.num_constraints() - step_circuit_constraints) - base_circuit_constraints;

        let o = format!(
            r#"Size Parameters for Augmented Circuit:
                    -- Base Constraints (no sumcheck, no step circuit):  {}
                    -- Per Step Circuit Input Constraints:               {}
                    -- Constrains per Sumcheck Round:                    {}"#,
            base_circuit_constraints, per_sc_input_constraints, sumcheck_round_constraints
        );

        println!("{}", o);

        Ok(())
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

        let sumcheck_rounds = HyperNovaAugmentedCircuit::<
            G1,
            G2,
            C1,
            C2,
            PoseidonSponge<G1::ScalarField>,
            SC,
        >::project_augmented_circuit_size(&TestCircuit)
        .unwrap()
        .0;

        let (U, proof) =
            HyperNovaAugmentedCircuit::<G1, G2, C1, C2, PoseidonSponge<G1::ScalarField>, SC>::base(
                sumcheck_rounds,
            );

        let input = HyperNovaAugmentedCircuitInput::<
            G1,
            G2,
            C1,
            C2,
            PoseidonSponge<G1::ScalarField>,
        >::Base {
            z_0: Vec::new(),
            vk: G1::ScalarField::ZERO,
            U,
            proof,
        };

        let circuit = HyperNovaAugmentedCircuit {
            ro_config: &ro_config,
            step_circuit: &TestCircuit,
            sumcheck_rounds,
            input,
        };
        let cs = ConstraintSystem::new_ref();

        circuit.generate_constraints_from_r1cs(cs.clone())?;

        assert!(cs.is_satisfied()?);

        Ok(())
    }
}
