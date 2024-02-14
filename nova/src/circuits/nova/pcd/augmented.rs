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
    groups::curves::short_weierstrass::ProjectiveVar,
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
    folding::nova::cyclefold::{
        self,
        nimfs::{NIMFSProof, R1CSInstance, R1CSShape, RelaxedR1CSInstance},
        secondary::Circuit as SecondaryCircuit,
    },
    gadgets::cyclefold::{
        multifold, multifold_with_relaxed, primary, secondary, NonNativeAffineVar,
    },
};

pub const SQUEEZE_NATIVE_ELEMENTS_NUM: usize = 1;

/// Leading `Variable::One` + 1 hash.
pub const AUGMENTED_CIRCUIT_NUM_IO: usize = 2;

pub enum NovaAugmentedCircuitInput<G1, G2, C1, C2, RO>
where
    G1: SWCurveConfig,
    G2: SWCurveConfig,
    C1: CommitmentScheme<Projective<G1>>,
    C2: CommitmentScheme<Projective<G2>>,
{
    Base {
        vk: G1::ScalarField,
        i: G1::ScalarField,
        z_i: Vec<G1::ScalarField>,
    },
    NonBase(NovaAugmentedCircuitNonBaseInput<G1, G2, C1, C2, RO>),
}

pub struct NovaAugmentedCircuitNonBaseInput<G1, G2, C1, C2, RO>
where
    G1: SWCurveConfig,
    G2: SWCurveConfig,
    C1: CommitmentScheme<Projective<G1>>,
    C2: CommitmentScheme<Projective<G2>>,
{
    pub vk: G1::ScalarField,

    pub i: G1::ScalarField,
    pub j: G1::ScalarField,
    pub k: G1::ScalarField,

    pub z_i: Vec<G1::ScalarField>,
    pub z_j: Vec<G1::ScalarField>,
    pub z_k: Vec<G1::ScalarField>,

    pub nodes: [PCDNodeInput<G1, G2, C1, C2, RO>; 2],
    pub proof: NIMFSProof<G1, G2, C1, C2, RO>,
}

impl<G1, G2, C1, C2, RO> Clone for NovaAugmentedCircuitNonBaseInput<G1, G2, C1, C2, RO>
where
    G1: SWCurveConfig,
    G2: SWCurveConfig,
    C1: CommitmentScheme<Projective<G1>>,
    C2: CommitmentScheme<Projective<G2>>,
{
    fn clone(&self) -> Self {
        Self {
            vk: self.vk,
            i: self.i,
            j: self.j,
            k: self.k,
            z_i: self.z_i.clone(),
            z_j: self.z_j.clone(),
            z_k: self.z_k.clone(),
            nodes: self.nodes.clone(),
            proof: self.proof.clone(),
        }
    }
}

pub struct PCDNodeInput<G1, G2, C1, C2, RO>
where
    G1: SWCurveConfig,
    G2: SWCurveConfig,
    C1: CommitmentScheme<Projective<G1>>,
    C2: CommitmentScheme<Projective<G2>>,
{
    pub U: RelaxedR1CSInstance<G1, C1>,
    pub U_secondary: RelaxedR1CSInstance<G2, C2>,
    pub u: R1CSInstance<G1, C1>,

    pub proof: NIMFSProof<G1, G2, C1, C2, RO>,
}

impl<G1, G2, C1, C2, RO> Clone for PCDNodeInput<G1, G2, C1, C2, RO>
where
    G1: SWCurveConfig,
    G2: SWCurveConfig,
    C1: CommitmentScheme<Projective<G1>>,
    C2: CommitmentScheme<Projective<G2>>,
{
    fn clone(&self) -> Self {
        Self {
            U: self.U.clone(),
            U_secondary: self.U_secondary.clone(),
            u: self.u.clone(),
            proof: self.proof.clone(),
        }
    }
}

#[must_use]
struct AllocatedPCDNodeInput<G1, G2, C1, C2, RO>
where
    G1: SWCurveConfig,
    G2: SWCurveConfig,
    G1::BaseField: PrimeField,
    G2::BaseField: PrimeField,
    C1: CommitmentScheme<Projective<G1>>,
    C2: CommitmentScheme<Projective<G2>>,
{
    U: primary::RelaxedR1CSInstanceVar<G1, C1>,
    U_secondary: secondary::RelaxedR1CSInstanceVar<G2, C2>,
    u: primary::R1CSInstanceVar<G1, C1>,

    // proof
    commitment_T: NonNativeAffineVar<G1>,
    proof_secondary: (secondary::ProofVar<G2, C2>, secondary::ProofVar<G2, C2>),

    _random_oracle: PhantomData<RO>,
}

impl<G1, G2, C1, C2, RO> AllocatedPCDNodeInput<G1, G2, C1, C2, RO>
where
    G1: SWCurveConfig,
    G2: SWCurveConfig<BaseField = G1::ScalarField, ScalarField = G1::BaseField>,
    G1::BaseField: PrimeField,
    G2::BaseField: PrimeField,
    C1: CommitmentScheme<Projective<G1>>,
    C2: CommitmentScheme<Projective<G2>>,
    RO: SpongeWithGadget<G1::ScalarField>,
    RO::Var: CryptographicSpongeVar<G1::ScalarField, RO, Parameters = RO::Config>,
{
    fn hash(
        &self,
        ro_config: &RO::Config,
        vk: &FpVar<G1::ScalarField>,
        (i, j): (&FpVar<G1::ScalarField>, &FpVar<G1::ScalarField>),
        (z_i, z_j): (&[FpVar<G1::ScalarField>], &[FpVar<G1::ScalarField>]),
    ) -> Result<FpVar<G1::ScalarField>, SynthesisError> {
        let cs = self.U.cs();
        let mut random_oracle = RO::Var::new(cs, ro_config);

        random_oracle.absorb(vk)?;
        random_oracle.absorb(i)?;
        random_oracle.absorb(j)?;
        random_oracle.absorb(&z_i)?;
        random_oracle.absorb(&z_j)?;
        random_oracle.absorb(&self.U)?;
        random_oracle.absorb(&self.U_secondary)?;

        let hash = random_oracle.squeeze_field_elements(SQUEEZE_NATIVE_ELEMENTS_NUM)?[0].clone();
        Ok(hash)
    }
}

#[must_use]
struct NovaAugmentedCircuitInputVar<G1, G2, C1, C2, RO>
where
    G1: SWCurveConfig,
    G2: SWCurveConfig,
    G1::BaseField: PrimeField,
    G2::BaseField: PrimeField,
    C1: CommitmentScheme<Projective<G1>>,
    C2: CommitmentScheme<Projective<G2>>,
    RO: SpongeWithGadget<G1::ScalarField>,
{
    vk: FpVar<G1::ScalarField>,

    i: FpVar<G1::ScalarField>,
    j: FpVar<G1::ScalarField>,
    k: FpVar<G1::ScalarField>,

    z_i: Vec<FpVar<G1::ScalarField>>,
    z_j: Vec<FpVar<G1::ScalarField>>,
    z_k: Vec<FpVar<G1::ScalarField>>,

    nodes: [AllocatedPCDNodeInput<G1, G2, C1, C2, RO>; 2],
    // proof
    commitment_T: NonNativeAffineVar<G1>,
    commitment_T_secondary: ProjectiveVar<G2, FpVar<G2::BaseField>>,
    proof_secondary: (
        [secondary::ProofVar<G2, C2>; 2],
        secondary::ProofVar<G2, C2>,
    ),
}

impl<G1, G2, C1, C2, RO> AllocVar<PCDNodeInput<G1, G2, C1, C2, RO>, G1::ScalarField>
    for AllocatedPCDNodeInput<G1, G2, C1, C2, RO>
where
    G1: SWCurveConfig,
    G2: SWCurveConfig<BaseField = G1::ScalarField, ScalarField = G1::BaseField>,
    G1::BaseField: PrimeField,
    G2::BaseField: PrimeField,
    C1: CommitmentScheme<Projective<G1>>,
    C2: CommitmentScheme<Projective<G2>>,
    RO: SpongeWithGadget<G1::ScalarField>,
    RO::Var: CryptographicSpongeVar<G1::ScalarField, RO, Parameters = RO::Config>,
{
    fn new_variable<T: Borrow<PCDNodeInput<G1, G2, C1, C2, RO>>>(
        cs: impl Into<Namespace<G1::ScalarField>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        let ns = cs.into();
        let cs = ns.cs();

        let input = f()?;
        let input = input.borrow();

        let U = primary::RelaxedR1CSInstanceVar::new_variable(cs.clone(), || Ok(&input.U), mode)?;
        let U_secondary = secondary::RelaxedR1CSInstanceVar::new_variable(
            cs.clone(),
            || Ok(&input.U_secondary),
            mode,
        )?;
        let u = primary::R1CSInstanceVar::new_variable(cs.clone(), || Ok(&input.u), mode)?;

        let commitment_T_point = input.proof.commitment_T.into();
        let commitment_T =
            NonNativeAffineVar::new_variable(cs.clone(), || Ok(&commitment_T_point), mode)?;

        let u_secondary = (
            secondary::ProofVar::new_variable(
                cs.clone(),
                || Ok(&input.proof.commitment_E_proof[0]),
                mode,
            )?,
            secondary::ProofVar::new_variable(
                cs.clone(),
                || Ok(&input.proof.commitment_W_proof),
                mode,
            )?,
        );

        Ok(Self {
            U,
            U_secondary,
            u,
            commitment_T,
            proof_secondary: u_secondary,
            _random_oracle: PhantomData,
        })
    }
}

impl<G1, G2, C1, C2, RO> AllocVar<NovaAugmentedCircuitInput<G1, G2, C1, C2, RO>, G1::ScalarField>
    for NovaAugmentedCircuitInputVar<G1, G2, C1, C2, RO>
where
    G1: SWCurveConfig,
    G2: SWCurveConfig<BaseField = G1::ScalarField, ScalarField = G1::BaseField>,
    G1::BaseField: PrimeField,
    G2::BaseField: PrimeField,
    C1: CommitmentScheme<Projective<G1>>,
    C2: CommitmentScheme<Projective<G2>>,
    RO: SpongeWithGadget<G1::ScalarField>,
    RO::Var: CryptographicSpongeVar<G1::ScalarField, RO, Parameters = RO::Config>,
{
    fn new_variable<T: Borrow<NovaAugmentedCircuitInput<G1, G2, C1, C2, RO>>>(
        cs: impl Into<Namespace<G1::ScalarField>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        let ns = cs.into();
        let cs = ns.cs();

        let input = f()?;
        let input = input.borrow();

        let input = match input {
            NovaAugmentedCircuitInput::Base { vk, i, z_i } => {
                let shape =
                    R1CSShape::<G1>::new(0, 0, AUGMENTED_CIRCUIT_NUM_IO, &[], &[], &[]).unwrap();
                let shape_secondary = cyclefold::secondary::setup_shape::<G1, G2>()?;

                let U = RelaxedR1CSInstance::<G1, C1>::new(&shape);
                let U_secondary = RelaxedR1CSInstance::<G2, C2>::new(&shape_secondary);
                let u = R1CSInstance::<G1, C1>::new(
                    &shape,
                    &(Projective::zero().into()),
                    &[G1::ScalarField::ONE; AUGMENTED_CIRCUIT_NUM_IO],
                )
                .unwrap();

                let node = PCDNodeInput {
                    U,
                    U_secondary,
                    u,
                    proof: NIMFSProof::default(),
                };
                NovaAugmentedCircuitNonBaseInput {
                    vk: *vk,
                    nodes: [node.clone(), node],
                    proof: NIMFSProof::default(),
                    i: *i,
                    j: *i,
                    k: *i + G1::ScalarField::ONE,
                    z_i: z_i.clone(),
                    z_j: z_i.clone(),
                    z_k: z_i.clone(),
                }
            }
            NovaAugmentedCircuitInput::NonBase(non_base) => non_base.clone(),
        };

        let vk = FpVar::new_variable(cs.clone(), || Ok(&input.vk), mode)?;

        let i = FpVar::new_variable(cs.clone(), || Ok(input.i), mode)?;
        let j = FpVar::new_variable(cs.clone(), || Ok(input.j), mode)?;
        let k = FpVar::new_variable(cs.clone(), || Ok(input.k), mode)?;

        let z_i = input
            .z_i
            .iter()
            .map(|z| FpVar::new_variable(cs.clone(), || Ok(z), mode))
            .collect::<Result<_, _>>()?;
        let z_j = input
            .z_j
            .iter()
            .map(|z| FpVar::new_variable(cs.clone(), || Ok(z), mode))
            .collect::<Result<_, _>>()?;
        let z_k = input
            .z_k
            .iter()
            .map(|z| FpVar::new_variable(cs.clone(), || Ok(z), mode))
            .collect::<Result<_, _>>()?;

        let node_l = AllocatedPCDNodeInput::new_variable(cs.clone(), || Ok(&input.nodes[0]), mode)?;
        let node_r = AllocatedPCDNodeInput::new_variable(cs.clone(), || Ok(&input.nodes[1]), mode)?;

        let commitment_T_point = input.proof.commitment_T.into();
        let commitment_T =
            NonNativeAffineVar::new_variable(cs.clone(), || Ok(&commitment_T_point), mode)?;
        let commitment_T_secondary = <ProjectiveVar<G2, FpVar<G2::BaseField>> as AllocVar<
            Projective<G2>,
            G2::BaseField,
        >>::new_variable(
            cs.clone(),
            || Ok(input.proof.proof_secondary.commitment_T.into()),
            mode,
        )?;
        let u_secondary = (
            [
                secondary::ProofVar::new_variable(
                    cs.clone(),
                    || Ok(&input.proof.commitment_E_proof[0]),
                    mode,
                )?,
                secondary::ProofVar::new_variable(
                    cs.clone(),
                    || Ok(&input.proof.commitment_E_proof[1]),
                    mode,
                )?,
            ],
            secondary::ProofVar::new_variable(
                cs.clone(),
                || Ok(&input.proof.commitment_W_proof),
                mode,
            )?,
        );

        Ok(Self {
            vk,
            i,
            j,
            k,
            z_i,
            z_j,
            z_k,
            nodes: [node_l, node_r],
            commitment_T,
            commitment_T_secondary,
            proof_secondary: u_secondary,
        })
    }
}

pub struct NovaAugmentedCircuit<'a, G1, G2, C1, C2, RO, SC>
where
    G1: SWCurveConfig,
    G2: SWCurveConfig,
    C1: CommitmentScheme<Projective<G1>>,
    C2: CommitmentScheme<Projective<G2>>,
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
    C1: CommitmentScheme<Projective<G1>>,
    C2: CommitmentScheme<Projective<G2>>,
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
    C1: CommitmentScheme<Projective<G1>>,
    C2: CommitmentScheme<Projective<G2>>,
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
                Ok(&self.input)
            })?;

        let vk = &input.vk;
        let (i, j, k) = (&input.i, &input.j, &input.k);
        let (z_i, z_j, z_k) = (&input.z_i, &input.z_j, &input.z_k);
        let left = &input.nodes[0];
        let right = &input.nodes[1];

        let is_base_case = i.is_eq(j)?;
        let should_enforce = is_base_case.not();

        let U_base = primary::RelaxedR1CSInstanceVar::<G1, C1>::new_constant(
            cs.clone(),
            RelaxedR1CSInstance {
                commitment_W: Projective::zero().into(),
                commitment_E: Projective::zero().into(),
                X: vec![G1::ScalarField::ZERO; AUGMENTED_CIRCUIT_NUM_IO],
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

        // constrain output
        for (z_i, z_j) in z_i.iter().zip(z_j) {
            z_i.conditional_enforce_equal(z_j, &is_base_case)?;
        }
        let mut z_next = <SC as StepCircuit<G1::ScalarField>>::generate_constraints(
            self.step_circuit,
            cs.clone(),
            j,
            z_j,
        )?;

        let j_next = j + FpVar::one();
        k.conditional_enforce_equal(&j_next, &is_base_case)?;

        // check hashes
        let hash_l = left.hash(self.ro_config, vk, (i, j), (z_i, z_j))?;
        let hash_r = right.hash(self.ro_config, vk, (&j_next, k), (&z_next, z_k))?;

        hash_l.conditional_enforce_equal(&left.u.X[1], &should_enforce)?;
        hash_r.conditional_enforce_equal(&right.u.X[1], &should_enforce)?;

        let (U_l, U_l_secondary) = multifold::<G1, G2, C1, C2, RO>(
            self.ro_config,
            vk,
            &left.U,
            &left.U_secondary,
            &left.u,
            &left.commitment_T,
            (&left.proof_secondary.0, &left.proof_secondary.1),
            &should_enforce,
        )?;
        let (U_r, U_r_secondary) = multifold::<G1, G2, C1, C2, RO>(
            self.ro_config,
            vk,
            &right.U,
            &right.U_secondary,
            &right.u,
            &right.commitment_T,
            (&right.proof_secondary.0, &right.proof_secondary.1),
            &should_enforce,
        )?;

        let (U, U_secondary) = multifold_with_relaxed::<G1, G2, C1, C2, RO>(
            self.ro_config,
            vk,
            &U_l,
            &U_l_secondary,
            &U_r,
            &U_r_secondary,
            &input.commitment_T,
            &input.commitment_T_secondary,
            (&input.proof_secondary.0, &input.proof_secondary.1),
            &should_enforce,
        )?;
        let U = is_base_case.select(&U_base, &U)?;
        let U_secondary = is_base_case.select(&U_secondary_base, &U_secondary)?;
        // absorb z_next into ro in the base case and z_k otherwise.
        for (z_next, z) in z_next.iter_mut().zip(z_k) {
            *z_next = is_base_case.select(z_next, z)?;
        }

        let mut random_oracle = RO::Var::new(cs.clone(), self.ro_config);
        random_oracle.absorb(&input.vk)?;
        random_oracle.absorb(i)?;
        random_oracle.absorb(k)?;
        random_oracle.absorb(&z_i)?;
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
        const ARITY: usize = 1;

        fn generate_constraints(
            &self,
            _: ConstraintSystemRef<F>,
            _: &FpVar<F>,
            z: &[FpVar<F>],
        ) -> Result<Vec<FpVar<F>>, SynthesisError> {
            let mut z = z.to_owned();
            z[0] += FpVar::one();
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
        C1: CommitmentScheme<Projective<G1>>,
        C2: CommitmentScheme<Projective<G2>>,
        C1::PP: Clone,
    {
        let ro_config = poseidon_config();

        let z_i = vec![G1::ScalarField::ONE];

        let input =
            NovaAugmentedCircuitInput::<G1, G2, C1, C2, PoseidonSponge<G1::ScalarField>>::Base {
                i: G1::ScalarField::ZERO,
                z_i,
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
