//! SuperNova implementation with CycleFold.
//!
//! Unlike [`IVCProof`](super::nova::sequential::IVCProof) allows the step circuit to have different
//! structure based on the computed program counter.

use std::marker::PhantomData;

use ark_crypto_primitives::sponge::{
    constraints::{CryptographicSpongeVar, SpongeWithGadget},
    Absorb, CryptographicSponge,
};
use ark_ec::short_weierstrass::{Projective, SWCurveConfig};
use ark_ff::{AdditiveGroup, PrimeField};
use ark_r1cs_std::{fields::fp::FpVar, R1CSVar};
use ark_relations::r1cs::{ConstraintSystem, ConstraintSystemRef, SynthesisError, SynthesisMode};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};

use crate::{
    absorb::CryptographicSpongeExt,
    commitment::CommitmentScheme,
    folding::nova::cyclefold::{
        self,
        nimfs::{
            NIMFSProof, R1CSInstance, R1CSShape, R1CSWitness, RelaxedR1CSInstance,
            RelaxedR1CSWitness,
        },
    },
};
use augmented::{
    SuperNovaAugmentedCircuit, SuperNovaAugmentedCircuitInput,
    SuperNovaAugmentedCircuitNonBaseInput,
};

pub mod public_params;
pub use crate::folding::nova::cyclefold::Error;

mod augmented;

trait SuperNovaConstraintSynthesizer<F: PrimeField> {
    fn generate_constraints(
        self,
        cs: ConstraintSystemRef<F>,
    ) -> Result<(FpVar<F>, Vec<FpVar<F>>), SynthesisError>;
}

pub trait NonUniformCircuit<F: PrimeField>: Send + Sync {
    /// Number of input variables, corresponds to `z.len()`.
    const ARITY: usize;

    /// Number of computable functions {F_0, ... , F_{l - 1}}.
    const NUM_CIRCUITS: usize;

    /// Generate constraints of computing selector function (phi).
    ///
    /// Return the next value of the program counter pc_{i + 1}.
    fn compute_selector(
        &self,
        cs: ConstraintSystemRef<F>,
        i: &FpVar<F>,
        z: &[FpVar<F>],
    ) -> Result<FpVar<F>, SynthesisError>;

    /// Generate constraints of computing `F_{pc}`.
    ///
    /// `generate_constraints()` takes `pc` argument to be used for switching between `F_i`.
    ///
    /// Return output `z_{i + 1}`.
    fn generate_constraints(
        &self,
        cs: ConstraintSystemRef<F>,
        pc: u64,
        i: &FpVar<F>,
        z: &[FpVar<F>],
    ) -> Result<Vec<FpVar<F>>, SynthesisError>;
}

const LOG_TARGET: &str = "nexus-nova::supernova";

#[doc(hidden)]
pub struct SetupParams<T>(PhantomData<T>);

impl<G1, G2, C1, C2, RO, SC> public_params::SetupParams<G1, G2, C1, C2, RO, SC>
    for SetupParams<(G1, G2, C1, C2, RO, SC)>
where
    G1: SWCurveConfig,
    G2: SWCurveConfig<BaseField = G1::ScalarField, ScalarField = G1::BaseField>,
    G1::BaseField: PrimeField + Absorb,
    G2::BaseField: PrimeField + Absorb,
    C1: CommitmentScheme<Projective<G1>>,
    C2: CommitmentScheme<Projective<G2>>,
    RO: SpongeWithGadget<G1::ScalarField> + Send + Sync,
    RO::Var: CryptographicSpongeVar<G1::ScalarField, RO, Parameters = RO::Config>,
    RO::Config: CanonicalSerialize + CanonicalDeserialize + Sync,
    SC: NonUniformCircuit<G1::ScalarField>,
{
    fn setup(
        ro_config: <RO as CryptographicSponge>::Config,
        step_circuit: &SC,
        aux1: &C1::SetupAux,
        aux2: &C2::SetupAux,
    ) -> Result<public_params::PublicParams<G1, G2, C1, C2, RO, SC, Self>, cyclefold::Error> {
        let _span = tracing::debug_span!(target: LOG_TARGET, "setup").entered();

        let mut shapes = Vec::new();
        let mut comm_key_len = 0;
        for pc in 0..SC::NUM_CIRCUITS {
            let z_0 = vec![G1::ScalarField::ZERO; SC::ARITY];

            let cs = ConstraintSystem::new_ref();
            cs.set_mode(SynthesisMode::Setup);

            let input = SuperNovaAugmentedCircuitInput::<G1, G2, C1, C2, RO>::Base {
                vk: G1::ScalarField::ZERO,
                z_0,
                num_augmented_circuits: SC::NUM_CIRCUITS,
            };
            let circuit =
                SuperNovaAugmentedCircuit::new(&ro_config, step_circuit, input, Some(pc as u64));
            let _ = SuperNovaConstraintSynthesizer::generate_constraints(circuit, cs.clone())?;

            cs.finalize();

            let shape = R1CSShape::from(cs);
            comm_key_len = comm_key_len.max(shape.num_vars.max(shape.num_constraints));

            shapes.push(shape);
        }

        let shape_secondary = cyclefold::secondary::setup_shape::<G1, G2>()?;

        let pp = C1::setup(comm_key_len, aux1);
        let pp_secondary = C2::setup(
            shape_secondary
                .num_vars
                .max(shape_secondary.num_constraints),
            aux2,
        );

        let mut params = public_params::PublicParams {
            ro_config,
            shapes,
            shape_secondary,
            pp,
            pp_secondary,
            digest: G1::ScalarField::ZERO,

            _step_circuit: PhantomData,
            _setup_params: PhantomData,
        };
        let digest = params.hash();
        params.digest = digest;

        tracing::debug!(
            target: LOG_TARGET,
            "public params setup done; augmented circuits({}): {}, ..., secondary circuit: {}",
            params.shapes.len(),
            params.shapes[0],
            params.shape_secondary,
        );
        Ok(params)
    }
}

pub type PublicParams<G1, G2, C1, C2, RO, SC> =
    public_params::PublicParams<G1, G2, C1, C2, RO, SC, SetupParams<(G1, G2, C1, C2, RO, SC)>>;

/// Non-uniform incrementally verifiable computation proof.
#[derive(CanonicalDeserialize, CanonicalSerialize)]
pub struct NIVCProof<G1, G2, C1, C2, RO, SC>
where
    G1: SWCurveConfig,
    G2: SWCurveConfig,
    C1: CommitmentScheme<Projective<G1>>,
    C2: CommitmentScheme<Projective<G2>>,
    RO: CryptographicSponge + Send + Sync,
    RO::Config: CanonicalSerialize + CanonicalDeserialize + Sync,
    SC: NonUniformCircuit<G1::ScalarField>,
{
    z_0: Vec<G1::ScalarField>,

    non_base: Option<NIVCProofNonBase<G1, G2, C1, C2>>,

    _random_oracle: PhantomData<RO>,
    _step_circuit: PhantomData<SC>,
}

impl<G1, G2, C1, C2, RO, SC> Clone for NIVCProof<G1, G2, C1, C2, RO, SC>
where
    G1: SWCurveConfig,
    G2: SWCurveConfig,
    C1: CommitmentScheme<Projective<G1>>,
    C2: CommitmentScheme<Projective<G2>>,
    RO: CryptographicSponge + Send + Sync,
    RO::Config: CanonicalSerialize + CanonicalDeserialize + Sync,
    SC: NonUniformCircuit<G1::ScalarField>,
{
    fn clone(&self) -> Self {
        Self {
            z_0: self.z_0.clone(),
            non_base: self.non_base.clone(),
            _random_oracle: PhantomData,
            _step_circuit: PhantomData,
        }
    }
}

#[derive(CanonicalDeserialize, CanonicalSerialize)]
struct NIVCProofNonBase<G1, G2, C1, C2>
where
    G1: SWCurveConfig,
    G2: SWCurveConfig,
    C1: CommitmentScheme<Projective<G1>>,
    C2: CommitmentScheme<Projective<G2>>,
{
    U: Vec<Option<RelaxedR1CSInstance<G1, C1>>>,
    W: Vec<Option<RelaxedR1CSWitness<G1>>>,
    U_secondary: Vec<Option<RelaxedR1CSInstance<G2, C2>>>,
    W_secondary: Vec<Option<RelaxedR1CSWitness<G2>>>,

    u: R1CSInstance<G1, C1>,
    w: R1CSWitness<G1>,
    i: u64,
    pc: u64,
    z_i: Vec<G1::ScalarField>,
}

impl<G1, G2, C1, C2> Clone for NIVCProofNonBase<G1, G2, C1, C2>
where
    G1: SWCurveConfig,
    G2: SWCurveConfig,
    C1: CommitmentScheme<Projective<G1>>,
    C2: CommitmentScheme<Projective<G2>>,
{
    fn clone(&self) -> Self {
        Self {
            U: self.U.clone(),
            W: self.W.clone(),
            U_secondary: self.U_secondary.clone(),
            W_secondary: self.W_secondary.clone(),
            u: self.u.clone(),
            w: self.w.clone(),
            i: self.i,
            pc: self.pc,
            z_i: self.z_i.clone(),
        }
    }
}

impl<G1, G2, C1, C2, RO, SC> NIVCProof<G1, G2, C1, C2, RO, SC>
where
    G1: SWCurveConfig,
    G2: SWCurveConfig<BaseField = G1::ScalarField, ScalarField = G1::BaseField>,
    G1::BaseField: PrimeField + Absorb,
    G2::BaseField: PrimeField + Absorb,
    C1: CommitmentScheme<Projective<G1>>,
    C2: CommitmentScheme<Projective<G2>>,
    RO: SpongeWithGadget<G1::ScalarField> + Send + Sync,
    RO::Var: CryptographicSpongeVar<G1::ScalarField, RO, Parameters = RO::Config>,
    RO::Config: CanonicalSerialize + CanonicalDeserialize + Sync,
    SC: NonUniformCircuit<G1::ScalarField>,
{
    pub fn new(z_0: &[G1::ScalarField]) -> Self {
        Self {
            z_0: z_0.to_owned(),
            non_base: None,
            _random_oracle: PhantomData,
            _step_circuit: PhantomData,
        }
    }

    pub fn z_i(&self) -> &[G1::ScalarField] {
        self.non_base
            .as_ref()
            .map(|r| &r.z_i[..])
            .unwrap_or(&self.z_0)
    }

    pub fn step_num(&self) -> u64 {
        self.non_base
            .as_ref()
            .map(|non_base| non_base.i)
            .unwrap_or(0)
    }

    pub fn prove_step(
        self,
        params: &PublicParams<G1, G2, C1, C2, RO, SC>,
        step_circuit: &SC,
    ) -> Result<Self, cyclefold::Error> {
        let _span = tracing::debug_span!(
            target: LOG_TARGET,
            "prove_step",
            step_num = %self.step_num(),
        )
        .entered();
        let NIVCProof { z_0, non_base, .. } = self;

        let (i_next, input, U, W, U_secondary, W_secondary) = if let Some(non_base) = non_base {
            let NIVCProofNonBase {
                mut U,
                mut W,
                mut U_secondary,
                mut W_secondary,
                u,
                w,
                i,
                pc,
                z_i,
            } = non_base;

            // instance `u` proofs execution of `F[pc]` and should be folded into `U[pc]`.
            let idx = pc as usize;
            let U_i = U[idx]
                .get_or_insert_with(|| RelaxedR1CSInstance::<G1, C1>::new(&params.shapes[idx]));
            let W_i = W[idx].get_or_insert_with(|| RelaxedR1CSWitness::zero(&params.shapes[idx]));

            let U_secondary_i = U_secondary[idx]
                .get_or_insert_with(|| RelaxedR1CSInstance::<G2, C2>::new(&params.shape_secondary));
            let W_secondary_i = W_secondary[idx]
                .get_or_insert_with(|| RelaxedR1CSWitness::zero(&params.shape_secondary));

            let proof = NIMFSProof::<G1, G2, C1, C2, RO>::prove(
                &params.pp,
                &params.pp_secondary,
                &params.ro_config,
                &params.digest,
                (&params.shapes[idx], &params.shape_secondary),
                (U_i, W_i),
                (U_secondary_i, W_secondary_i),
                (&u, &w),
            )?;

            let input =
                SuperNovaAugmentedCircuitInput::NonBase(SuperNovaAugmentedCircuitNonBaseInput {
                    vk: params.digest,
                    i: G1::ScalarField::from(i),
                    pc: G1::ScalarField::from(pc),
                    z_0: z_0.clone(),
                    z_i,
                    U: U.clone(),
                    U_secondary: U_secondary.clone(),
                    u,
                    proof: proof.0,
                });

            let (U_p, W_p) = proof.1;
            let (U_secondary_p, W_secondary_p) = proof.2;

            U[idx].replace(U_p);
            W[idx].replace(W_p);

            U_secondary[idx].replace(U_secondary_p);
            W_secondary[idx].replace(W_secondary_p);

            let i_next = i.saturating_add(1);

            (i_next, input, U, W, U_secondary, W_secondary)
        } else {
            let num_augmented_circuits = SC::NUM_CIRCUITS;

            let U = vec![None; num_augmented_circuits];
            let U_secondary = vec![None; num_augmented_circuits];

            let W = vec![None; num_augmented_circuits];
            let W_secondary = vec![None; num_augmented_circuits];

            let input = SuperNovaAugmentedCircuitInput::<G1, G2, C1, C2, RO>::Base {
                vk: params.digest,
                z_0: z_0.clone(),
                num_augmented_circuits,
            };
            let i_next = 1;

            (i_next, input, U, W, U_secondary, W_secondary)
        };

        let cs = ConstraintSystem::new_ref();
        cs.set_mode(SynthesisMode::Prove { construct_matrices: false });

        let circuit = SuperNovaAugmentedCircuit::new(&params.ro_config, step_circuit, input, None);

        let (pc_next, z_i) = tracing::debug_span!(target: LOG_TARGET, "satisfying_assignment")
            .in_scope(|| {
                SuperNovaConstraintSynthesizer::generate_constraints(circuit, cs.clone())
            })?;

        let cs_borrow = cs.borrow().unwrap();
        let witness = cs_borrow.witness_assignment.clone();
        let pub_io = cs_borrow.instance_assignment.clone();

        let w = R1CSWitness::<G1> { W: witness };

        let commitment_W = w.commit::<C1>(&params.pp);
        let u = R1CSInstance::<G1, C1> { commitment_W, X: pub_io };

        let z_i = z_i.iter().map(R1CSVar::value).collect::<Result<_, _>>()?;
        let pc_next = {
            let pc = augmented::field_to_u64(pc_next.value()?);
            if pc >= SC::NUM_CIRCUITS as u64 {
                panic!("next pc is out of bounds: {} >= {}", pc, SC::NUM_CIRCUITS);
            }
            pc
        };

        Ok(Self {
            z_0,

            non_base: Some(NIVCProofNonBase {
                U,
                W,
                U_secondary,
                W_secondary,
                u,
                w,
                i: i_next,
                pc: pc_next,
                z_i,
            }),
            _random_oracle: PhantomData,
            _step_circuit: PhantomData,
        })
    }

    pub fn verify(
        &self,
        params: &PublicParams<G1, G2, C1, C2, RO, SC>,
        num_steps: usize,
    ) -> Result<(), cyclefold::Error> {
        let _span = tracing::debug_span!(target: LOG_TARGET, "verify", %num_steps).entered();

        const NOT_SATISFIED_ERROR: cyclefold::Error =
            cyclefold::Error::R1CS(crate::r1cs::Error::NotSatisfied);

        let Some(non_base) = &self.non_base else {
            return Err(NOT_SATISFIED_ERROR);
        };

        let NIVCProofNonBase {
            U,
            W,
            U_secondary,
            W_secondary,
            u,
            w,
            i,
            pc,
            z_i,
        } = non_base;

        assert_eq!(U.len(), SC::NUM_CIRCUITS);
        assert_eq!(W.len(), SC::NUM_CIRCUITS);
        assert_eq!(U_secondary.len(), SC::NUM_CIRCUITS);
        assert_eq!(W_secondary.len(), SC::NUM_CIRCUITS);

        let num_steps = num_steps as u64;
        if num_steps != *i {
            return Err(NOT_SATISFIED_ERROR);
        }

        let mut random_oracle = RO::new(&params.ro_config);

        random_oracle.absorb(&params.digest);
        random_oracle.absorb(&G1::ScalarField::from(*i));
        random_oracle.absorb(&G1::ScalarField::from(*pc));
        random_oracle.absorb(&self.z_0);
        random_oracle.absorb(&z_i);
        for (i, U) in U.iter().enumerate() {
            let U = U
                .clone()
                .unwrap_or_else(|| RelaxedR1CSInstance::<G1, C1>::new(&params.shapes[i]));
            random_oracle.absorb(&U);
        }
        for U_secondary in U_secondary.iter() {
            let U_secondary = U_secondary
                .clone()
                .unwrap_or_else(|| RelaxedR1CSInstance::<G2, C2>::new(&params.shape_secondary));
            random_oracle.absorb_non_native(&U_secondary);
        }

        let hash: &G1::ScalarField =
            &random_oracle.squeeze_field_elements(augmented::SQUEEZE_NATIVE_ELEMENTS_NUM)[0];

        if hash != &u.X[1] {
            return Err(NOT_SATISFIED_ERROR);
        }

        for (i, (U, W)) in U
            .iter()
            .zip(W)
            .filter_map(|(u, w)| u.as_ref().zip(w.as_ref()))
            .enumerate()
        {
            params.shapes[i].is_relaxed_satisfied(U, W, &params.pp)?;
        }
        for (U_secondary, W_secondary) in U_secondary
            .iter()
            .zip(W_secondary)
            .filter_map(|(u, w)| u.as_ref().zip(w.as_ref()))
        {
            params.shape_secondary.is_relaxed_satisfied(
                U_secondary,
                W_secondary,
                &params.pp_secondary,
            )?;
        }

        params.shapes[*pc as usize].is_satisfied(u, w, &params.pp)?;

        Ok(())
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::{pedersen::PedersenCommitment, poseidon_config, LOG_TARGET as NOVA_TARGET};

    use ark_crypto_primitives::sponge::poseidon::PoseidonSponge;
    use ark_ff::Field;
    use ark_r1cs_std::fields::{fp::FpVar, FieldVar};
    use ark_relations::r1cs::{ConstraintSystemRef, SynthesisError};

    use tracing_subscriber::{
        filter, fmt::format::FmtSpan, layer::SubscriberExt, util::SubscriberInitExt,
    };

    #[derive(Debug, Default)]
    pub struct TestCircuit<F: Field>(PhantomData<F>);

    impl<F: PrimeField> NonUniformCircuit<F> for TestCircuit<F> {
        const ARITY: usize = 2;

        const NUM_CIRCUITS: usize = 2;

        fn compute_selector(
            &self,
            _: ConstraintSystemRef<F>,
            _: &FpVar<F>,
            z: &[FpVar<F>],
        ) -> Result<FpVar<F>, SynthesisError> {
            // store selector in the first input var.
            Ok(z[0].clone())
        }

        fn generate_constraints(
            &self,
            _: ConstraintSystemRef<F>,
            pc: u64,
            _: &FpVar<F>,
            z: &[FpVar<F>],
        ) -> Result<Vec<FpVar<F>>, SynthesisError> {
            // alternate between + 2 and * 2
            assert_eq!(z.len(), 2);

            let x = &z[1];

            let y = match pc {
                0 => x + FpVar::constant(2u64.into()),
                1 => x.double()?,
                _ => unreachable!(),
            };

            // update z[0]
            let pc = &z[0];
            let pc_is_zero = pc.is_zero()?;
            let pc_next = pc_is_zero.select(&FpVar::one(), &FpVar::zero())?;

            Ok(vec![pc_next, y])
        }
    }

    #[test]
    fn nivc_base_step() {
        nivc_base_step_with_cycle::<
            ark_pallas::PallasConfig,
            ark_vesta::VestaConfig,
            PedersenCommitment<ark_pallas::Projective>,
            PedersenCommitment<ark_vesta::Projective>,
        >()
        .unwrap()
    }

    fn nivc_base_step_with_cycle<G1, G2, C1, C2>() -> Result<(), cyclefold::Error>
    where
        G1: SWCurveConfig,
        G2: SWCurveConfig<BaseField = G1::ScalarField, ScalarField = G1::BaseField>,
        G1::BaseField: PrimeField + Absorb,
        G2::BaseField: PrimeField + Absorb,
        C1: CommitmentScheme<Projective<G1>, SetupAux = ()>,
        C2: CommitmentScheme<Projective<G2>, SetupAux = ()>,
    {
        let ro_config = poseidon_config();

        let circuit = TestCircuit::<G1::ScalarField>(PhantomData);
        let z_0 = vec![G1::ScalarField::ZERO, G1::ScalarField::ZERO];
        let num_steps = 1;

        let params = PublicParams::<
            G1,
            G2,
            C1,
            C2,
            PoseidonSponge<G1::ScalarField>,
            TestCircuit<G1::ScalarField>,
        >::setup(ro_config, &circuit, &(), &())?;

        let mut recursive_snark = NIVCProof::new(&z_0);
        recursive_snark = recursive_snark.prove_step(&params, &circuit)?;
        recursive_snark.verify(&params, num_steps).unwrap();

        assert_eq!(&recursive_snark.z_i()[1], &G1::ScalarField::from(2));

        Ok(())
    }

    #[test]
    fn nivc_multiple_steps() {
        nivc_multiple_steps_with_cycle::<
            ark_pallas::PallasConfig,
            ark_vesta::VestaConfig,
            PedersenCommitment<ark_pallas::Projective>,
            PedersenCommitment<ark_vesta::Projective>,
        >()
        .unwrap()
    }

    fn nivc_multiple_steps_with_cycle<G1, G2, C1, C2>() -> Result<(), cyclefold::Error>
    where
        G1: SWCurveConfig,
        G2: SWCurveConfig<BaseField = G1::ScalarField, ScalarField = G1::BaseField>,
        G1::BaseField: PrimeField + Absorb,
        G2::BaseField: PrimeField + Absorb,
        C1: CommitmentScheme<Projective<G1>, SetupAux = ()>,
        C2: CommitmentScheme<Projective<G2>, SetupAux = ()>,
    {
        let filter = filter::Targets::new().with_target(NOVA_TARGET, tracing::Level::DEBUG);
        let _guard = tracing_subscriber::registry()
            .with(
                tracing_subscriber::fmt::layer().with_span_events(FmtSpan::ENTER | FmtSpan::CLOSE),
            )
            .with(filter)
            .set_default();

        let ro_config = poseidon_config();

        let circuit = TestCircuit::<G1::ScalarField>(PhantomData);
        let z_0 = vec![G1::ScalarField::ZERO, G1::ScalarField::from(2u64)];
        let num_steps = 5;

        let params = PublicParams::<
            G1,
            G2,
            C1,
            C2,
            PoseidonSponge<G1::ScalarField>,
            TestCircuit<G1::ScalarField>,
        >::setup(ro_config, &circuit, &(), &())?;

        let mut recursive_snark = NIVCProof::new(&z_0);

        for _ in 0..num_steps {
            recursive_snark = NIVCProof::prove_step(recursive_snark, &params, &circuit)?;
        }
        recursive_snark.verify(&params, num_steps).unwrap();

        assert_eq!(&recursive_snark.z_i()[1], &G1::ScalarField::from(22));
        Ok(())
    }
}
