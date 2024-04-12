use std::marker::PhantomData;

use ark_crypto_primitives::sponge::{
    constraints::{CryptographicSpongeVar, SpongeWithGadget},
    Absorb, CryptographicSponge,
};
use ark_ec::short_weierstrass::{Projective, SWCurveConfig};
use ark_ff::{AdditiveGroup, PrimeField};
use ark_r1cs_std::R1CSVar;
use ark_relations::r1cs::{ConstraintSystem, SynthesisMode};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_spartan::polycommitments::{PolyCommitmentScheme, PCSKeys};

use crate::{
    absorb::CryptographicSpongeExt,
    commitment::CommitmentScheme,
    folding::hypernova::cyclefold::{
        self,
        nimfs::{
            NIMFSProof, R1CSShape, RelaxedR1CSInstance, RelaxedR1CSWitness,
            CCSShape, CCSInstance, CCSWitness, LCCSInstance,
        },
    },
};

use super::{public_params, HyperNovaConstraintSynthesizer, StepCircuit};

mod augmented;
use augmented::{
    HyperNovaAugmentedCircuit, HyperNovaAugmentedCircuitInput, HyperNovaAugmentedCircuitNonBaseInput,
};

const LOG_TARGET: &str = "nexus-hypernova::sequential";

#[doc(hidden)]
pub struct SetupParams<T>(PhantomData<T>);

impl<G1, G2, C1, C2, RO, SC> public_params::SetupParams<G1, G2, C1, C2, RO, SC>
    for SetupParams<(G1, G2, C1, C2, RO, SC)>
where
    G1: SWCurveConfig,
    G2: SWCurveConfig<BaseField = G1::ScalarField, ScalarField = G1::BaseField>,
    G1::BaseField: PrimeField + Absorb,
    G2::BaseField: PrimeField + Absorb,
    C1: PolyCommitmentScheme<Projective<G1>>,
    C2: CommitmentScheme<Projective<G2>>,
    RO: SpongeWithGadget<G1::ScalarField> + Send + Sync,
    RO::Var: CryptographicSpongeVar<G1::ScalarField, RO, Parameters = RO::Config>,
    RO::Config: CanonicalSerialize + CanonicalDeserialize + Sync,
    SC: StepCircuit<G1::ScalarField>,
{
    fn setup(
        ro_config: <RO as CryptographicSponge>::Config,
        step_circuit: &SC,
        srs: &C1::SRS,
        aux: &C2::SetupAux,
    ) -> Result<public_params::PublicParams<G1, G2, C1, C2, RO, SC, Self>, cyclefold::Error> {
        let _span = tracing::debug_span!(target: LOG_TARGET, "setup").entered();

        // NOTE: Review `project_augmented_circuit_size` for context.
        #[cfg(debug_assertions)]
        {
            for i in 0..=1 {
                let z_0 = vec![G1::ScalarField::ZERO; SC::ARITY];

                let input = HyperNovaAugmentedCircuitInput::<G1, G2, C1, C2, RO>::Base {
                    vk: G1::ScalarField::ZERO,
                    z_0,
                };

                let cs = ConstraintSystem::new_ref();
                cs.set_mode(SynthesisMode::Setup);

                println!("re Augmented Circuit Constraint Projection: Begin test for {} sumcheck rounds...", i);
                let circuit = HyperNovaAugmentedCircuit::new(&ro_config, step_circuit, i, input);
                let _ = HyperNovaConstraintSynthesizer::generate_constraints(circuit, cs.clone())?;

                cs.finalize();
                println!("re Augmented Circuit Constraint Projection: {} constraints total\n", cs.num_constraints());
            }
        }

        //let s: usize = project_augmented_circuit_size(&step_circuit);
        let s: usize = 0;

        let z_0 = vec![G1::ScalarField::ZERO; SC::ARITY];

        let input = HyperNovaAugmentedCircuitInput::<G1, G2, C1, C2, RO>::Base {
            vk: G1::ScalarField::ZERO,
            z_0,
        };

        let cs = ConstraintSystem::new_ref();
        cs.set_mode(SynthesisMode::Setup);

        let circuit = HyperNovaAugmentedCircuit::new(&ro_config, step_circuit, s, input);
        let _ = HyperNovaConstraintSynthesizer::generate_constraints(circuit, cs.clone())?;

        cs.finalize();

        let shape = CCSShape::from(R1CSShape::from(cs));
        let shape_secondary = cyclefold::secondary::setup_shape::<G1, G2>()?;

        // NOTE: Review `project_augmented_circuit_size` for context.
        //debug_assert!(shape.num_constraints == project_augmented_circuit_size(&step_circuit));

        // NOTE: We could try to use the EvalVerifierKey here, which should then make the
        //       public params smaller. However, that would make the interfaces uglier as
        //       well as potentially introduce concerns as we'd absorb it rather than the
        //       full key used for committing. So, for now we will just use the full key.
        let PCSKeys { ck, .. } = C1::trim(srs, shape.num_vars.max(shape.num_constraints));
        let pp_secondary = C2::setup(
            shape_secondary
                .num_vars
                .max(shape_secondary.num_constraints),
            b"nova_seq_secondary_curve",
            aux2,
        );

        let mut params = public_params::PublicParams {
            ro_config,
            shape,
            shape_secondary,
            ck,
            pp_secondary,
            digest: G1::ScalarField::ZERO,

            _step_circuit: PhantomData,
            _setup_params: PhantomData,
        };
        let digest = params.hash();
        params.digest = digest;

        tracing::debug!(
            target: LOG_TARGET,
            "public params setup done; augmented circuit: {}, secondary circuit: {}",
            params.shape,
            params.shape_secondary,
        );
        Ok(params)
    }
}

pub type PublicParams<G1, G2, C1, C2, RO, SC> =
    public_params::PublicParams<G1, G2, C1, C2, RO, SC, SetupParams<(G1, G2, C1, C2, RO, SC)>>;

#[derive(CanonicalDeserialize, CanonicalSerialize)]
pub struct IVCProof<G1, G2, C1, C2, RO, SC>
where
    G1: SWCurveConfig,
    G2: SWCurveConfig,
    C1: PolyCommitmentScheme<Projective<G1>>,
    C2: CommitmentScheme<Projective<G2>>,
    RO: CryptographicSponge + Send + Sync,
    RO::Config: CanonicalSerialize + CanonicalDeserialize + Sync,
    SC: StepCircuit<G1::ScalarField>,
{
    z_0: Vec<G1::ScalarField>,

    non_base: Option<IVCProofNonBase<G1, G2, C1, C2>>,

    _random_oracle: PhantomData<RO>,
    _step_circuit: PhantomData<SC>,
}

impl<G1, G2, C1, C2, RO, SC> Clone for IVCProof<G1, G2, C1, C2, RO, SC>
where
    G1: SWCurveConfig,
    G2: SWCurveConfig,
    C1: PolyCommitmentScheme<Projective<G1>>,
    C2: CommitmentScheme<Projective<G2>>,
    RO: CryptographicSponge + Send + Sync,
    RO::Config: CanonicalSerialize + CanonicalDeserialize + Sync,
    SC: StepCircuit<G1::ScalarField>,
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
struct IVCProofNonBase<G1, G2, C1, C2>
where
    G1: SWCurveConfig,
    G2: SWCurveConfig,
    C1: PolyCommitmentScheme<Projective<G1>>,
    C2: CommitmentScheme<Projective<G2>>,
{
    U: LCCSInstance<G1, C1>,
    W: CCSWitness<G1>,
    U_secondary: RelaxedR1CSInstance<G2, C2>,
    W_secondary: RelaxedR1CSWitness<G2>,

    u: CCSInstance<G1, C1>,
    w: CCSWitness<G1>,
    i: u64,
    z_i: Vec<G1::ScalarField>,
}

impl<G1, G2, C1, C2> Clone for IVCProofNonBase<G1, G2, C1, C2>
where
    G1: SWCurveConfig,
    G2: SWCurveConfig,
    C1: PolyCommitmentScheme<Projective<G1>>,
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
            z_i: self.z_i.clone(),
        }
    }
}

impl<G1, G2, C1, C2, RO, SC> IVCProof<G1, G2, C1, C2, RO, SC>
where
    G1: SWCurveConfig,
    G2: SWCurveConfig<BaseField = G1::ScalarField, ScalarField = G1::BaseField>,
    G1::BaseField: PrimeField + Absorb,
    G2::BaseField: PrimeField + Absorb,
    C1: PolyCommitmentScheme<Projective<G1>>,
    C2: CommitmentScheme<Projective<G2>>,
    RO: SpongeWithGadget<G1::ScalarField> + Send + Sync,
    RO::Var: CryptographicSpongeVar<G1::ScalarField, RO, Parameters = RO::Config>,
    RO::Config: CanonicalSerialize + CanonicalDeserialize + Sync,
    SC: StepCircuit<G1::ScalarField>,
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
        let IVCProof { z_0, non_base, .. } = self;

        let (i_next, input, U, W, U_secondary, W_secondary) = if let Some(non_base) = non_base {
            let IVCProofNonBase {
                U,
                W,
                U_secondary,
                W_secondary,
                u,
                w,
                i,
                z_i,
            } = non_base;

            let proof = NIMFSProof::<G1, G2, C1, C2, RO>::prove(
                &params.pp_secondary,
                &params.ro_config,
                &params.digest,
                (&params.shape, &params.shape_secondary),
                (&U, &W),
                (&U_secondary, &W_secondary),
                (&u, &w),
            )?;

            let input = HyperNovaAugmentedCircuitInput::NonBase(HyperNovaAugmentedCircuitNonBaseInput {
                vk: params.digest,
                i: G1::ScalarField::from(i),
                z_0: z_0.clone(),
                z_i,
                U: U.clone(),
                U_secondary: U_secondary.clone(),
                u,
                proof: proof.0,
            });

            let (U, W) = proof.1;
            let (U_secondary, W_secondary) = proof.2;
            let i_next = i.saturating_add(1);

            (i_next, input, U, W, U_secondary, W_secondary)
        } else {
            let U = LCCSInstance::<G1, C1>::base(&params.shape);
            let W = CCSWitness::zero(&params.shape);

            let U_secondary = RelaxedR1CSInstance::<G2, C2>::new(&params.shape_secondary);
            let W_secondary = RelaxedR1CSWitness::zero(&params.shape_secondary);

            let input = HyperNovaAugmentedCircuitInput::<G1, G2, C1, C2, RO>::Base {
                vk: params.digest,
                z_0: z_0.clone(),
            };
            let i_next = 1;

            (i_next, input, U, W, U_secondary, W_secondary)
        };

        let cs = ConstraintSystem::new_ref();
        cs.set_mode(SynthesisMode::Prove { construct_matrices: false });

        let s: usize = ((params.shape.num_constraints - 1).checked_ilog2().unwrap_or(0) + 1) as usize;

        let circuit = HyperNovaAugmentedCircuit::new(&params.ro_config, step_circuit, s, input);

        let z_i = tracing::debug_span!(target: LOG_TARGET, "satisfying_assignment")
            .in_scope(|| HyperNovaConstraintSynthesizer::generate_constraints(circuit, cs.clone()))?;

        let cs_borrow = cs.borrow().unwrap();
        let witness = cs_borrow.witness_assignment.clone();
        let pub_io = cs_borrow.instance_assignment.clone();

        let w = CCSWitness::<G1> { W: witness };

        let commitment_W = w.commit::<C1>(&params.ck);
        let u = CCSInstance::<G1, C1> { commitment_W, X: pub_io };

        let z_i = z_i.iter().map(R1CSVar::value).collect::<Result<_, _>>()?;

        Ok(Self {
            z_0,

            non_base: Some(IVCProofNonBase {
                U,
                W,
                U_secondary,
                W_secondary,
                u,
                w,
                i: i_next,
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
            cyclefold::Error::Ccs(crate::ccs::Error::NotSatisfied);

        let Some(non_base) = &self.non_base else {
            return Err(NOT_SATISFIED_ERROR);
        };

        let IVCProofNonBase {
            U,
            W,
            U_secondary,
            W_secondary,
            u,
            w,
            i,
            z_i,
        } = non_base;

        let num_steps = num_steps as u64;
        if num_steps != *i {
            return Err(NOT_SATISFIED_ERROR);
        }

        let mut random_oracle = RO::new(&params.ro_config);

        random_oracle.absorb(&params.digest);
        random_oracle.absorb(&G1::ScalarField::from(*i));
        random_oracle.absorb(&self.z_0);
        random_oracle.absorb(&z_i);
        random_oracle.absorb(U);
        random_oracle.absorb_non_native(U_secondary);

        let hash: &G1::ScalarField =
            &random_oracle.squeeze_field_elements(augmented::SQUEEZE_NATIVE_ELEMENTS_NUM)[0];

        if hash != &u.X[1] {
            return Err(NOT_SATISFIED_ERROR);
        }

        params.shape.is_satisfied_linearized(U, W, &params.ck)?;
        params.shape_secondary.is_relaxed_satisfied(
            U_secondary,
            W_secondary,
            &params.pp_secondary,
        )?;
        params.shape.is_satisfied(u, w, &params.ck)?;

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
    use ark_spartan::polycommitments::zeromorph::Zeromorph;

    use tracing_subscriber::{
        filter, fmt::format::FmtSpan, layer::SubscriberExt, util::SubscriberInitExt,
    };

    #[derive(Debug, Default)]
    pub struct CubicCircuit<F: Field>(PhantomData<F>);

    impl<F: PrimeField> StepCircuit<F> for CubicCircuit<F> {
        const ARITY: usize = 1;

        fn generate_constraints(
            &self,
            _: ConstraintSystemRef<F>,
            _: &FpVar<F>,
            z: &[FpVar<F>],
        ) -> Result<Vec<FpVar<F>>, SynthesisError> {
            assert_eq!(z.len(), 1);

            let x = &z[0];

            let x_square = x.square()?;
            let x_cube = x_square * x;

            let y: FpVar<F> = x + x_cube + &FpVar::Constant(5u64.into());

            Ok(vec![y])
        }
    }

    #[test]
    fn ivc_base_step() {
        ivc_base_step_with_cycle::<
            ark_bn254::g1::Config,
            ark_grumpkin::GrumpkinConfig,
            Zeromorph<ark_bn254::Bn254>,
            PedersenCommitment<ark_grumpkin::Projective>,
        >()
        .unwrap()
    }

    fn ivc_base_step_with_cycle<G1, G2, C1, C2>() -> Result<(), cyclefold::Error>
    where
        G1: SWCurveConfig,
        G2: SWCurveConfig<BaseField = G1::ScalarField, ScalarField = G1::BaseField>,
        G1::BaseField: PrimeField + Absorb,
        G2::BaseField: PrimeField + Absorb,
        C1: PolyCommitmentScheme<Projective<G1>, SRS = ()>,
        C2: CommitmentScheme<Projective<G2>, SetupAux = ()>,
    {
        let ro_config = poseidon_config();

        let circuit = CubicCircuit::<G1::ScalarField>(PhantomData);
        let z_0 = vec![G1::ScalarField::ONE];
        let num_steps = 1;

        let params = PublicParams::<
            G1,
            G2,
            C1,
            C2,
            PoseidonSponge<G1::ScalarField>,
            CubicCircuit<G1::ScalarField>,
        >::setup(
            ro_config,
            &circuit,
            &(),
            &(),
        )?;

        let mut recursive_snark = IVCProof::new(&z_0);
        recursive_snark = recursive_snark.prove_step(&params, &circuit)?;
        recursive_snark.verify(&params, num_steps).unwrap();

        assert_eq!(&recursive_snark.z_i()[0], &G1::ScalarField::from(7));

        Ok(())
    }

    #[test]
    fn ivc_multiple_steps() {
        ivc_multiple_steps_with_cycle::<
            ark_bn254::g1::Config,
            ark_grumpkin::GrumpkinConfig,
            Zeromorph<ark_bn254::Bn254>,
            PedersenCommitment<ark_grumpkin::Projective>,
         >()
         .unwrap()
    }

    fn ivc_multiple_steps_with_cycle<G1, G2, C1, C2>() -> Result<(), cyclefold::Error>
    where
        G1: SWCurveConfig,
        G2: SWCurveConfig<BaseField = G1::ScalarField, ScalarField = G1::BaseField>,
        G1::BaseField: PrimeField + Absorb,
        G2::BaseField: PrimeField + Absorb,
        C1: PolyCommitmentScheme<Projective<G1>, SRS = ()>,
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

        let circuit = CubicCircuit::<G1::ScalarField>(PhantomData);
        let z_0 = vec![G1::ScalarField::ONE];
        let num_steps = 3;

        let params = PublicParams::<
            G1,
            G2,
            C1,
            C2,
            PoseidonSponge<G1::ScalarField>,
            CubicCircuit<G1::ScalarField>,
        >::setup(ro_config,
                 &circuit,
                 &(),
                 &(),
        )?;

        let mut recursive_snark = IVCProof::new(&z_0);

        for _ in 0..num_steps {
            recursive_snark = IVCProof::prove_step(recursive_snark, &params, &circuit)?;
        }
        recursive_snark.verify(&params, num_steps).unwrap();

        assert_eq!(&recursive_snark.z_i()[0], &G1::ScalarField::from(44739235));
        Ok(())
    }
}
