use std::{borrow::Borrow, marker::PhantomData};

use ark_crypto_primitives::sponge::{
    constraints::{CryptographicSpongeVar, SpongeWithGadget},
    Absorb,
};
use ark_ec::short_weierstrass::{Projective, SWCurveConfig};
use ark_ff::{AdditiveGroup, BigInteger, Field, PrimeField};
use ark_r1cs_std::{
    alloc::{AllocVar, AllocationMode},
    boolean::Boolean,
    eq::EqGadget,
    fields::{fp::FpVar, FieldVar},
    select::CondSelectGadget,
    R1CSVar,
};
use ark_relations::{
    lc,
    r1cs::{ConstraintSystemRef, LinearCombination, Namespace, SynthesisError, Variable},
};
use ark_std::Zero;

use crate::{
    circuits::supernova::{NonUniformCircuit, SuperNovaConstraintSynthesizer},
    commitment::CommitmentScheme,
    folding::nova::cyclefold::{
        nimfs::{NIMFSProof, R1CSInstance, RelaxedR1CSInstance},
        secondary::Circuit as SecondaryCircuit,
    },
    gadgets::cyclefold::{nova::{multifold, primary}, secondary},
    gadgets::nonnative::short_weierstrass::NonNativeAffineVar,
};

pub const SQUEEZE_NATIVE_ELEMENTS_NUM: usize = 1;

/// Leading `Variable::One` + 1 hash.
pub const AUGMENTED_CIRCUIT_NUM_IO: usize = 2;

/// Converts prime field element into u64.
///
/// Panics if it doesn't fit into 8 bytes.
pub(super) fn field_to_u64<F: PrimeField>(f: F) -> u64 {
    let bytes = f.into_bigint().to_bytes_le();

    let (bytes, rem) = bytes.split_at((u64::BITS / 8) as usize);
    let u = u64::from_le_bytes(bytes.try_into().unwrap());

    if rem.iter().any(|&byte| byte != 0) {
        panic!("field element is greater than u64::MAX: {f:?}");
    }

    u
}

pub enum SuperNovaAugmentedCircuitInput<G1, G2, C1, C2, RO>
where
    G1: SWCurveConfig,
    G2: SWCurveConfig,
    C1: CommitmentScheme<Projective<G1>>,
    C2: CommitmentScheme<Projective<G2>>,
{
    Base {
        vk: G1::ScalarField,
        z_0: Vec<G1::ScalarField>,
        num_augmented_circuits: usize,
    },
    NonBase(SuperNovaAugmentedCircuitNonBaseInput<G1, G2, C1, C2, RO>),
}

pub struct SuperNovaAugmentedCircuitNonBaseInput<G1, G2, C1, C2, RO>
where
    G1: SWCurveConfig,
    G2: SWCurveConfig,
    C1: CommitmentScheme<Projective<G1>>,
    C2: CommitmentScheme<Projective<G2>>,
{
    pub vk: G1::ScalarField,
    pub i: G1::ScalarField,
    pub pc: G1::ScalarField,
    pub z_0: Vec<G1::ScalarField>,
    pub z_i: Vec<G1::ScalarField>,
    pub U: Vec<Option<RelaxedR1CSInstance<G1, C1>>>,
    pub U_secondary: Vec<Option<RelaxedR1CSInstance<G2, C2>>>,
    pub u: R1CSInstance<G1, C1>,
    pub proof: NIMFSProof<G1, G2, C1, C2, RO>,
}

impl<G1, G2, C1, C2, RO> Clone for SuperNovaAugmentedCircuitNonBaseInput<G1, G2, C1, C2, RO>
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
            pc: self.pc,
            z_0: self.z_0.clone(),
            z_i: self.z_i.clone(),
            U: self.U.clone(),
            U_secondary: self.U_secondary.clone(),
            u: self.u.clone(),
            proof: self.proof.clone(),
        }
    }
}

struct SuperNovaAugmentedCircuitInputVar<G1, G2, C1, C2, RO>
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
    pc: FpVar<G1::ScalarField>,
    z_0: Vec<FpVar<G1::ScalarField>>,
    z_i: Vec<FpVar<G1::ScalarField>>,
    U: Vec<primary::RelaxedR1CSInstanceVar<G1, C1>>,
    U_secondary: Vec<secondary::RelaxedR1CSInstanceVar<G2, C2>>,
    u: primary::R1CSInstanceVar<G1, C1>,

    // proof
    commitment_T: NonNativeAffineVar<G1>,
    proof_secondary: (secondary::ProofVar<G2, C2>, secondary::ProofVar<G2, C2>),

    _random_oracle: PhantomData<RO>,
}

impl<G1, G2, C1, C2, RO>
    AllocVar<SuperNovaAugmentedCircuitInput<G1, G2, C1, C2, RO>, G1::ScalarField>
    for SuperNovaAugmentedCircuitInputVar<G1, G2, C1, C2, RO>
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
    fn new_variable<T: Borrow<SuperNovaAugmentedCircuitInput<G1, G2, C1, C2, RO>>>(
        cs: impl Into<Namespace<G1::ScalarField>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        let ns = cs.into();
        let cs = ns.cs();

        let input = f()?;
        let input = input.borrow();

        let input = match input {
            SuperNovaAugmentedCircuitInput::Base { vk, z_0, num_augmented_circuits } => {
                let U = vec![None; *num_augmented_circuits];
                let U_secondary = vec![None; *num_augmented_circuits];
                let u = R1CSInstance::<G1, C1> {
                    commitment_W: C1::Commitment::default(),
                    X: vec![G1::ScalarField::ONE; AUGMENTED_CIRCUIT_NUM_IO],
                };
                SuperNovaAugmentedCircuitNonBaseInput {
                    vk: *vk,
                    i: G1::ScalarField::ZERO,
                    pc: G1::ScalarField::ZERO,
                    z_0: z_0.clone(),
                    z_i: z_0.clone(),
                    U,
                    U_secondary,
                    u,
                    proof: NIMFSProof::default(),
                }
            }
            SuperNovaAugmentedCircuitInput::NonBase(non_base) => non_base.clone(),
        };

        let vk = FpVar::new_variable(cs.clone(), || Ok(input.vk), mode)?;
        let i = FpVar::new_variable(cs.clone(), || Ok(input.i), mode)?;
        let pc = FpVar::new_variable(cs.clone(), || Ok(input.pc), mode)?;
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

        let U = input
            .U
            .iter()
            .map(|U| {
                let U = U.clone().unwrap_or_else(|| RelaxedR1CSInstance {
                    commitment_W: C1::Commitment::default(),
                    commitment_E: C1::Commitment::default(),
                    X: vec![G1::ScalarField::ZERO; AUGMENTED_CIRCUIT_NUM_IO],
                });
                primary::RelaxedR1CSInstanceVar::new_variable(cs.clone(), || Ok(U), mode)
            })
            .collect::<Result<_, _>>()?;
        let U_secondary = input
            .U_secondary
            .iter()
            .map(|U_secondary| {
                let U_secondary = U_secondary.clone().unwrap_or_else(|| RelaxedR1CSInstance {
                    commitment_W: C2::Commitment::default(),
                    commitment_E: C2::Commitment::default(),
                    X: vec![G2::ScalarField::ZERO; SecondaryCircuit::<G1>::NUM_IO],
                });
                secondary::RelaxedR1CSInstanceVar::new_variable(
                    cs.clone(),
                    || Ok(U_secondary),
                    mode,
                )
            })
            .collect::<Result<_, _>>()?;
        let u = primary::R1CSInstanceVar::new_variable(cs.clone(), || Ok(&input.u), mode)?;

        let commitment_T = NonNativeAffineVar::new_variable(
            cs.clone(),
            || Ok(input.proof.commitment_T.into()),
            mode,
        )?;

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
            vk,
            i,
            pc,
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

pub struct SuperNovaAugmentedCircuit<'a, G1, G2, C1, C2, RO, SC>
where
    G1: SWCurveConfig,
    G2: SWCurveConfig,
    C1: CommitmentScheme<Projective<G1>>,
    C2: CommitmentScheme<Projective<G2>>,
    RO: SpongeWithGadget<G1::ScalarField>,
    SC: NonUniformCircuit<G1::ScalarField>,
{
    ro_config: &'a <RO::Var as CryptographicSpongeVar<G1::ScalarField, RO>>::Parameters,
    step_circuit: &'a SC,
    input: SuperNovaAugmentedCircuitInput<G1, G2, C1, C2, RO>,
    /// Hint value for the program counter -- computed value is not available during setup.
    pc_hint: Option<u64>,
}

impl<'a, G1, G2, C1, C2, RO, SC> SuperNovaAugmentedCircuit<'a, G1, G2, C1, C2, RO, SC>
where
    G1: SWCurveConfig,
    G2: SWCurveConfig,
    C1: CommitmentScheme<Projective<G1>>,
    C2: CommitmentScheme<Projective<G2>>,
    RO: SpongeWithGadget<G1::ScalarField>,
    SC: NonUniformCircuit<G1::ScalarField>,
{
    pub fn new(
        ro_config: &'a <RO::Var as CryptographicSpongeVar<G1::ScalarField, RO>>::Parameters,
        step_circuit: &'a SC,
        input: SuperNovaAugmentedCircuitInput<G1, G2, C1, C2, RO>,
        pc_hint: Option<u64>,
    ) -> Self {
        Self { ro_config, step_circuit, input, pc_hint }
    }
}

struct SelectorBits<F: PrimeField> {
    bits: Vec<Boolean<F>>,
}

impl<F: PrimeField> SelectorBits<F> {
    fn new(
        cs: ConstraintSystemRef<F>,
        pc: &FpVar<F>,
        max_value: u64,
    ) -> Result<Self, SynthesisError> {
        // from Lurk's implementation of SuperNova
        //
        // https://github.com/lurk-lab/arecibo/blob/02d9fe50d64ca6b67b35014fa2a91f9231c84fde/src/supernova/utils.rs#L60

        let bits: Vec<Boolean<F>> = (0..max_value)
            .map(|i| Boolean::new_witness(cs.clone(), || pc.value().map(|pc| pc == i.into())))
            .collect::<Result<_, _>>()?;

        let selected_sum = bits
            .iter()
            .fold(LinearCombination::zero(), |lc, bit| lc + bit.lc());
        cs.enforce_constraint(selected_sum, lc!() + Variable::One, lc!() + Variable::One)?;

        let mut selected_value = FpVar::<F>::zero();
        // can be optimized to avoid creating new lc on each iteration
        for (i, bit) in bits.iter().enumerate() {
            selected_value += FpVar::from(bit.clone()) * FpVar::constant((i as u64).into());
        }
        selected_value.enforce_equal(pc)?;

        Ok(Self { bits })
    }

    fn select<T: CondSelectGadget<F>>(&self, vals: &[T]) -> Result<T, SynthesisError> {
        let bits = &self.bits;
        assert_eq!(vals.len(), bits.len());

        // skipping first bit is correct since all bits are constrained.
        let mut val = vals.first().cloned().expect("must be non-empty");
        for (v, bit) in vals.iter().zip(bits).skip(1) {
            val = bit.select(v, &val)?;
        }
        Ok(val)
    }

    fn insert<T: CondSelectGadget<F>>(
        &self,
        vals: &[T],
        ival: &T,
    ) -> Result<Vec<T>, SynthesisError> {
        let bits = &self.bits;
        assert_eq!(vals.len(), bits.len());

        vals.iter()
            .zip(bits)
            .map(|(val, bit)| bit.select(ival, val))
            .collect::<Result<_, _>>()
    }
}

impl<G1, G2, C1, C2, RO, SC> SuperNovaConstraintSynthesizer<G1::ScalarField>
    for SuperNovaAugmentedCircuit<'_, G1, G2, C1, C2, RO, SC>
where
    G1: SWCurveConfig,
    G2: SWCurveConfig<BaseField = G1::ScalarField, ScalarField = G1::BaseField>,
    G1::BaseField: PrimeField + Absorb,
    G2::BaseField: PrimeField + Absorb,
    C1: CommitmentScheme<Projective<G1>>,
    C2: CommitmentScheme<Projective<G2>>,
    RO: SpongeWithGadget<G1::ScalarField>,
    RO::Var: CryptographicSpongeVar<G1::ScalarField, RO, Parameters = RO::Config>,
    SC: NonUniformCircuit<G1::ScalarField>,
{
    fn generate_constraints(
        self,
        cs: ConstraintSystemRef<G1::ScalarField>,
    ) -> Result<(FpVar<G1::ScalarField>, Vec<FpVar<G1::ScalarField>>), SynthesisError> {
        assert!(self.pc_hint.is_none() ^ cs.is_in_setup_mode());

        let input = SuperNovaAugmentedCircuitInputVar::<G1, G2, C1, C2, RO>::new_witness(
            cs.clone(),
            || Ok(&self.input),
        )?;
        let num_augmented_circuits = input.U.len();
        assert_eq!(input.U_secondary.len(), num_augmented_circuits);

        let is_base_case = input.i.is_zero()?;
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

        for (z_0, z_i) in input.z_0.iter().zip(&input.z_i) {
            z_0.conditional_enforce_equal(z_i, &is_base_case)?;
        }

        let pc_next = <SC as NonUniformCircuit<G1::ScalarField>>::compute_selector(
            self.step_circuit,
            cs.clone(),
            &input.i,
            &input.z_i,
        )?;
        let pc_value = self.pc_hint.unwrap_or_else(|| {
            let pc_next = pc_next.value().expect("hint must be provided for cs setup");
            let pc_value = field_to_u64(pc_next);
            if pc_value >= SC::NUM_CIRCUITS as u64 {
                panic!(
                    "next pc is out of bounds: {} >= {}",
                    pc_value,
                    SC::NUM_CIRCUITS
                );
            }
            pc_value
        });
        let z_next = <SC as NonUniformCircuit<G1::ScalarField>>::generate_constraints(
            self.step_circuit,
            cs.clone(),
            pc_value,
            &input.i,
            &input.z_i,
        )?;

        let mut random_oracle = RO::Var::new(cs.clone(), self.ro_config);
        random_oracle.absorb(&input.vk)?;
        random_oracle.absorb(&input.i)?;
        random_oracle.absorb(&input.pc)?;
        random_oracle.absorb(&input.z_0)?;
        random_oracle.absorb(&input.z_i)?;
        random_oracle.absorb(&input.U)?;
        random_oracle.absorb(&input.U_secondary)?;

        let hash = &random_oracle.squeeze_field_elements(SQUEEZE_NATIVE_ELEMENTS_NUM)?[0];
        hash.conditional_enforce_equal(&input.u.X[1], &should_enforce)?;

        let selector_bits = SelectorBits::<G1::ScalarField>::new(
            cs.clone(),
            &input.pc,
            num_augmented_circuits as u64,
        )?;
        let U = selector_bits.select(&input.U)?;
        let U_secondary = selector_bits.select(&input.U_secondary)?;

        let (U, U_secondary) = multifold::<G1, G2, C1, C2, RO>(
            self.ro_config,
            &input.vk,
            &U,
            &U_secondary,
            &input.u,
            &input.commitment_T,
            (&input.proof_secondary.0, &input.proof_secondary.1),
            &should_enforce,
        )?;

        let mut U_next = selector_bits.insert(&input.U, &U)?;
        let mut U_secondary_next = selector_bits.insert(&input.U_secondary, &U_secondary)?;

        for U in &mut U_next {
            *U = is_base_case.select(&U_base, U)?;
        }
        for U_secondary in &mut U_secondary_next {
            *U_secondary = is_base_case.select(&U_secondary_base, U_secondary)?;
        }

        let i_next = &input.i + FpVar::one();

        let mut random_oracle = RO::Var::new(cs.clone(), self.ro_config);
        random_oracle.absorb(&input.vk)?;
        random_oracle.absorb(&i_next)?;
        random_oracle.absorb(&pc_next)?;
        random_oracle.absorb(&input.z_0)?;
        random_oracle.absorb(&z_next)?;
        random_oracle.absorb(&U_next)?;
        random_oracle.absorb(&U_secondary_next)?;

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

        Ok((pc_next, z_next))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{pedersen::PedersenCommitment, poseidon_config};
    use ark_crypto_primitives::sponge::poseidon::PoseidonSponge;
    use ark_relations::r1cs::ConstraintSystem;

    struct TestCircuit;

    impl<F: PrimeField> NonUniformCircuit<F> for TestCircuit {
        const ARITY: usize = 0;

        const NUM_CIRCUITS: usize = 1;

        fn compute_selector(
            &self,
            _: ConstraintSystemRef<F>,
            _: &FpVar<F>,
            _: &[FpVar<F>],
        ) -> Result<FpVar<F>, SynthesisError> {
            Ok(FpVar::zero())
        }

        fn generate_constraints(
            &self,
            _: ConstraintSystemRef<F>,
            _: u64,
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
        C1: CommitmentScheme<Projective<G1>>,
        C2: CommitmentScheme<Projective<G2>>,
        C1::PP: Clone,
    {
        let ro_config = poseidon_config();

        let input = SuperNovaAugmentedCircuitInput::<
            G1,
            G2,
            C1,
            C2,
            PoseidonSponge<G1::ScalarField>,
        >::Base {
            z_0: Vec::new(),
            vk: G1::ScalarField::ZERO,
            num_augmented_circuits:
                <TestCircuit as NonUniformCircuit<G1::ScalarField>>::NUM_CIRCUITS,
        };

        let circuit = SuperNovaAugmentedCircuit {
            ro_config: &ro_config,
            step_circuit: &TestCircuit,
            input,
            pc_hint: None,
        };
        let cs = ConstraintSystem::new_ref();

        let _ = circuit.generate_constraints(cs.clone())?;

        assert!(cs.is_satisfied()?);

        Ok(())
    }
}
