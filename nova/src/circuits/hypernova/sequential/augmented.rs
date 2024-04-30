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
    safe_log,
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

        let commitment_W_proof = secondary::ProofVar::<G2, C2>::new_variable(
            cs.clone(),
            || Ok(&input.proof.commitment_W_proof),
            mode,
        )?;
        let hypernova_proof = primary::ProofFromR1CSVar::<G1, RO>::new_variable(
            cs.clone(),
            || Ok(&input.proof.hypernova_proof),
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

    pub fn project_augmented_circuit_size_upper_bound_from_r1cs(
        base_constraints: u32,
        max_constraints_per_step_circuit_input: u32,
        max_constraints_per_sumcheck_round: u32,
        step_circuit: &'a SC,
    ) -> Result<(usize, usize), SynthesisError> {
        let cs = ConstraintSystem::new_ref();

        let z_0 = vec![G1::ScalarField::ZERO; SC::ARITY];

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

        let mut max_constraints = base_constraints
            + step_circuit_constraints
            + (SC::ARITY as u32).saturating_sub(1) * max_constraints_per_step_circuit_input;

        let mut low = 0;
        let mut high = safe_log!(max_constraints);

        let mut eq = false;
        while !eq {
            max_constraints += (high - low) * max_constraints_per_sumcheck_round;
            low = high;
            high = safe_log!(max_constraints);

            eq = low == high;
        }

        Ok((high as usize, max_constraints as usize))
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
    pub fn project_augmented_circuit_size_upper_bound_bn254(
        step_circuit: &'a SC,
    ) -> Result<(usize, usize), SynthesisError> {
        // in order to regenerate these parameters, enable the (ignored) test `calculate_circuit_constants_bn254`
        const BASE_CONSTRAINTS: u32 = 82852;
        const MAX_CONSTRAINTS_PER_STEP_CIRCUIT_INPUT: u32 = 487;
        const MAX_CONSTRAINTS_PER_SUMCHECK_ROUND: u32 = 1481;

        HyperNovaAugmentedCircuit::<'_, G1, G2, C1, C2, RO, SC>::project_augmented_circuit_size_upper_bound_from_r1cs(
            BASE_CONSTRAINTS,
            MAX_CONSTRAINTS_PER_STEP_CIRCUIT_INPUT,
            MAX_CONSTRAINTS_PER_SUMCHECK_ROUND,
            step_circuit,
        )
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

    fn project_augmented_circuit_size_upper_bound(
        step_circuit: &'_ SC,
    ) -> Result<(usize, usize), SynthesisError> {
        // todo: make more robust
        assert_eq!(std::any::type_name::<G1>(), "ark_bn254::curves::g1::Config");
        assert_eq!(std::any::type_name::<G2>(), "ark_grumpkin::curves::GrumpkinConfig");

        HyperNovaAugmentedCircuit::<'_, G1, G2, C1, C2, RO, SC>::project_augmented_circuit_size_upper_bound_bn254(step_circuit)
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
    use crate::{pedersen::PedersenCommitment, poseidon_config, zeromorph::Zeromorph};
    use ark_crypto_primitives::sponge::poseidon::PoseidonSponge;
    use ark_ec::short_weierstrass::{Projective, SWCurveConfig};
    use ark_relations::r1cs::ConstraintSystem;

    struct TestCircuit1;
    struct TestCircuit2;

    // these circuits produce the largest
    //
    //   -- constraints per step circuit input
    //   -- constraints per sumcheck round
    //
    // step sizes observed in testing

    impl<F: PrimeField> StepCircuit<F> for TestCircuit1 {
        const ARITY: usize = 1;

        fn generate_constraints(
            &self,
            _: ConstraintSystemRef<F>,
            _: &FpVar<F>,
            z: &[FpVar<F>],
        ) -> Result<Vec<FpVar<F>>, SynthesisError> {
            let mut zp = z.to_owned();

            let x = &zp[0];

            let x_square = x.square()?;
            let x_cube = x_square * x;

            zp[0] = x + x_cube + &FpVar::Constant(5u64.into());

            Ok(zp)
        }
    }

    impl<F: PrimeField> StepCircuit<F> for TestCircuit2 {
        const ARITY: usize = 2;

        fn generate_constraints(
            &self,
            _: ConstraintSystemRef<F>,
            _: &FpVar<F>,
            z: &[FpVar<F>],
        ) -> Result<Vec<FpVar<F>>, SynthesisError> {
            let mut zp = z.to_owned();

            let x = &zp[0];

            let x_square = x.square()?;
            let x_cube = x_square * x;

            zp[0] = x + x_cube + &FpVar::Constant(5u64.into());

            Ok(zp)
        }
    }

    type SC1 = TestCircuit1;
    type SC2 = TestCircuit2;

    #[ignore]
    #[test]
    fn calculate_circuit_constants_bn254() {
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

        let z_0_1 =
            vec![G1::ScalarField::ZERO; <TestCircuit1 as StepCircuit<G1::ScalarField>>::ARITY];
        let z_0_2 =
            vec![G1::ScalarField::ZERO; <TestCircuit2 as StepCircuit<G1::ScalarField>>::ARITY];

        // Constraint Generation #1: The Step Circuit

        let cs = ConstraintSystem::new_ref();

        let (U, proof) = HyperNovaAugmentedCircuit::<
            G1,
            G2,
            C1,
            C2,
            PoseidonSponge<G1::ScalarField>,
            SC1,
        >::base(0);

        let input = HyperNovaAugmentedCircuitInput::<
            G1,
            G2,
            C1,
            C2,
            PoseidonSponge<G1::ScalarField>,
        >::Base {
            vk: G1::ScalarField::ZERO,
            z_0: z_0_1.clone(),
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

        let _ = SC1::generate_constraints(&TestCircuit1, cs.clone(), &input.i, &input.z_i)?;

        cs.finalize();
        let step_circuit_constraints = cs.num_constraints();

        // Constraint Generation #2: The Augmented Circuit with no sumcheck rounds and one step circuit input

        let cs = ConstraintSystem::new_ref();

        let (U, proof) = HyperNovaAugmentedCircuit::<
            G1,
            G2,
            C1,
            C2,
            PoseidonSponge<G1::ScalarField>,
            SC1,
        >::base(0);

        let input = HyperNovaAugmentedCircuitInput::<
            G1,
            G2,
            C1,
            C2,
            PoseidonSponge<G1::ScalarField>,
        >::Base {
            vk: G1::ScalarField::ZERO,
            z_0: z_0_1.clone(),
            U,
            proof,
        };

        let circuit = HyperNovaAugmentedCircuit::new(&ro_config, &TestCircuit1, 0, input);
        let _ = HyperNovaConstraintSynthesizer::generate_constraints(circuit, cs.clone())?;

        cs.finalize();

        let base_circuit_constraints = cs.num_constraints() - step_circuit_constraints;

        // Constraint Generation #3: The Augmented Circuit with no sumcheck rounds and two step circuit inputs

        let cs = ConstraintSystem::new_ref();

        let (U, proof) = HyperNovaAugmentedCircuit::<
            G1,
            G2,
            C1,
            C2,
            PoseidonSponge<G1::ScalarField>,
            SC2,
        >::base(0);

        let input = HyperNovaAugmentedCircuitInput::<
            G1,
            G2,
            C1,
            C2,
            PoseidonSponge<G1::ScalarField>,
        >::Base {
            vk: G1::ScalarField::ZERO,
            z_0: z_0_2.clone(),
            U,
            proof,
        };

        let circuit = HyperNovaAugmentedCircuit::new(&ro_config, &TestCircuit2, 0, input);
        let _ = HyperNovaConstraintSynthesizer::generate_constraints(circuit, cs.clone())?;

        cs.finalize();

        let sc_input_constraints =
            (cs.num_constraints() - step_circuit_constraints) - base_circuit_constraints;

        // Constraint Generation #4: The Augmented Circuit with one sumcheck round and one step circuit input

        let cs = ConstraintSystem::new_ref();

        let (U, proof) = HyperNovaAugmentedCircuit::<
            G1,
            G2,
            C1,
            C2,
            PoseidonSponge<G1::ScalarField>,
            SC1,
        >::base(1);

        let input = HyperNovaAugmentedCircuitInput::<
            G1,
            G2,
            C1,
            C2,
            PoseidonSponge<G1::ScalarField>,
        >::Base {
            vk: G1::ScalarField::ZERO,
            z_0: z_0_1.clone(),
            U,
            proof,
        };

        let circuit = HyperNovaAugmentedCircuit::new(&ro_config, &TestCircuit1, 1, input);
        let _ = HyperNovaConstraintSynthesizer::generate_constraints(circuit, cs.clone())?;

        cs.finalize();

        let sumcheck_round_constraints =
            (cs.num_constraints() - step_circuit_constraints) - base_circuit_constraints;

        let o = format!(
            r#"Size Parameters for Augmented Circuit:
                    -- Base Constraints (no sumcheck, no step circuit):  {}
                    -- (Max) Constraints per Step Circuit Input:         {}
                    -- (Max) Constraints per Sumcheck Round:             {}"#,
            base_circuit_constraints, sc_input_constraints, sumcheck_round_constraints
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
            SC1,
        >::project_augmented_circuit_size_upper_bound(&TestCircuit1)
        .unwrap()
        .0;

        let (U, proof) = HyperNovaAugmentedCircuit::<
            G1,
            G2,
            C1,
            C2,
            PoseidonSponge<G1::ScalarField>,
            SC1,
        >::base(sumcheck_rounds);

        let input = HyperNovaAugmentedCircuitInput::<
            G1,
            G2,
            C1,
            C2,
            PoseidonSponge<G1::ScalarField>,
        >::Base {
            z_0: vec![G1::ScalarField::ZERO],
            vk: G1::ScalarField::ZERO,
            U,
            proof,
        };

        let circuit = HyperNovaAugmentedCircuit {
            ro_config: &ro_config,
            step_circuit: &TestCircuit1,
            sumcheck_rounds,
            input,
        };
        let cs = ConstraintSystem::new_ref();

        circuit.generate_constraints(cs.clone())?;

        assert!(cs.is_satisfied()?);

        Ok(())
    }
}
