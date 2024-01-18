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
use ark_std::fmt::Debug;

use super::{public_params, NovaConstraintSynthesizer, StepCircuit};
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

mod augmented;

#[cfg(feature = "spartan")]
pub mod compression;

use augmented::{
    NovaAugmentedCircuit, NovaAugmentedCircuitInput, NovaAugmentedCircuitNonBaseInput, PCDNodeInput,
};

const LOG_TARGET: &str = "supernova::pcd";

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
    C1::Commitment: Into<Projective<G1>> + From<Projective<G1>> + Eq + Debug,
    C2: CommitmentScheme<Projective<G2>, Commitment = Projective<G2>>,
    RO: SpongeWithGadget<G1::ScalarField> + Send + Sync,
    RO::Var: CryptographicSpongeVar<G1::ScalarField, RO, Parameters = RO::Config>,
    RO::Config: CanonicalSerialize + CanonicalDeserialize + Sync,
    SC: StepCircuit<G1::ScalarField>,
{
    fn setup(
        ro_config: <RO as CryptographicSponge>::Config,
        step_circuit: &SC,
        aux1: &C1::SetupAux,
        aux2: &C2::SetupAux,
    ) -> Result<public_params::PublicParams<G1, G2, C1, C2, RO, SC, Self>, cyclefold::Error> {
        let _span = tracing::debug_span!(target: LOG_TARGET, "setup").entered();

        let i = G1::ScalarField::ZERO;
        let z_i = vec![G1::ScalarField::ZERO; SC::ARITY];

        let cs = ConstraintSystem::new_ref();
        cs.set_mode(SynthesisMode::Setup);

        let input = NovaAugmentedCircuitInput::<G1, G2, C1, C2, RO>::Base {
            i,
            z_i,
            vk: G1::ScalarField::ZERO,
        };
        let circuit = NovaAugmentedCircuit::new(&ro_config, step_circuit, input);
        let _ = NovaConstraintSynthesizer::generate_constraints(circuit, cs.clone())?;

        cs.finalize();

        let shape = R1CSShape::from(cs);
        let shape_secondary = cyclefold::secondary::setup_shape::<G1, G2>()?;

        let pp = C1::setup(shape.num_vars.max(shape.num_constraints), aux1);
        let pp_secondary = C2::setup(
            shape_secondary
                .num_vars
                .max(shape_secondary.num_constraints),
            aux2,
        );

        let mut params = public_params::PublicParams {
            ro_config,
            shape,
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
            "public params setup done; augmented circuit: {}, secondary circuit: {}",
            params.shape,
            params.shape_secondary,
        );
        Ok(params)
    }
}

pub type PublicParams<G1, G2, C1, C2, RO, SC> =
    public_params::PublicParams<G1, G2, C1, C2, RO, SC, SetupParams<(G1, G2, C1, C2, RO, SC)>>;

/// Proof-carrying data tree node.
#[derive(CanonicalSerialize, CanonicalDeserialize)]
pub struct PCDNode<G1, G2, C1, C2, RO, SC>
where
    G1: SWCurveConfig,
    G2: SWCurveConfig,
    C1: CommitmentScheme<Projective<G1>>,
    C2: CommitmentScheme<Projective<G2>>,
    RO: SpongeWithGadget<G1::ScalarField> + Send + Sync,
    RO::Config: CanonicalSerialize + CanonicalDeserialize,
    SC: StepCircuit<G1::ScalarField>,
{
    pub i: u64,
    pub j: u64,

    pub z_i: Vec<G1::ScalarField>,
    pub z_j: Vec<G1::ScalarField>,

    pub U: RelaxedR1CSInstance<G1, C1>,
    pub W: RelaxedR1CSWitness<G1>,
    pub U_secondary: RelaxedR1CSInstance<G2, C2>,
    pub W_secondary: RelaxedR1CSWitness<G2>,

    pub u: R1CSInstance<G1, C1>,
    pub w: R1CSWitness<G1>,

    _random_oracle: PhantomData<RO>,
    _step_circuit: PhantomData<SC>,
}

impl<G1, G2, C1, C2, RO, SC> PCDNode<G1, G2, C1, C2, RO, SC>
where
    G1: SWCurveConfig,
    G2: SWCurveConfig<BaseField = G1::ScalarField, ScalarField = G1::BaseField>,
    G1::BaseField: PrimeField + Absorb,
    G2::BaseField: PrimeField + Absorb,
    C1: CommitmentScheme<Projective<G1>>,
    C1::Commitment: Into<Projective<G1>> + From<Projective<G1>> + Debug + Eq,
    C2: CommitmentScheme<Projective<G2>, Commitment = Projective<G2>>,
    RO: SpongeWithGadget<G1::ScalarField> + Send + Sync,
    RO::Var: CryptographicSpongeVar<G1::ScalarField, RO, Parameters = RO::Config>,
    RO::Config: CanonicalSerialize + CanonicalDeserialize + Sync,
    SC: StepCircuit<G1::ScalarField>,
{
    pub fn min_step(&self) -> u64 {
        self.i
    }

    pub fn max_step(&self) -> u64 {
        self.j
    }

    pub fn prove_step(
        params: &PublicParams<G1, G2, C1, C2, RO, SC>,
        step_circuit: &SC,
        i: usize,
        z_i: &[G1::ScalarField],
    ) -> Result<Self, cyclefold::Error> {
        Self::prove_step_with_commit_fn(params, step_circuit, i, z_i, |pp, w| w.commit::<C1>(pp))
    }

    /// Proves step of step circuit execution and calls `commit_fn(pp, w)` to
    /// compute commitment to the witness of the augmented circuit.
    pub fn prove_step_with_commit_fn(
        params: &PublicParams<G1, G2, C1, C2, RO, SC>,
        step_circuit: &SC,
        i: usize,
        z_i: &[G1::ScalarField],
        mut commit_fn: impl FnMut(&C1::PP, &R1CSWitness<G1>) -> C1::Commitment,
    ) -> Result<Self, cyclefold::Error> {
        let _span = tracing::debug_span!(
            target: LOG_TARGET,
            "prove_step",
            ?i,
            j = i + 1,
        )
        .entered();

        let i = i as u64;
        let U = RelaxedR1CSInstance::<G1, C1>::new(&params.shape);
        let W = RelaxedR1CSWitness::zero(&params.shape);

        let U_secondary = RelaxedR1CSInstance::<G2, C2>::new(&params.shape_secondary);
        let W_secondary = RelaxedR1CSWitness::zero(&params.shape_secondary);

        let input = NovaAugmentedCircuitInput::<G1, G2, C1, C2, RO>::Base {
            i: G1::ScalarField::from(i),
            z_i: z_i.to_owned(),
            vk: params.digest,
        };

        let cs = ConstraintSystem::new_ref();
        cs.set_mode(SynthesisMode::Prove {
            construct_matrices: false,
        });

        let circuit = NovaAugmentedCircuit::new(&params.ro_config, step_circuit, input);
        let z_next = tracing::debug_span!(target: LOG_TARGET, "satisfying_assignment")
            .in_scope(|| NovaConstraintSynthesizer::generate_constraints(circuit, cs.clone()))?;

        let cs_borrow = cs.borrow().unwrap();
        let witness = cs_borrow.witness_assignment.clone();
        let pub_io = cs_borrow.instance_assignment.clone();

        let w = R1CSWitness::<G1> { W: witness };

        let commitment_W = commit_fn(&params.pp, &w);
        let u = R1CSInstance::<G1, C1> {
            commitment_W,
            X: pub_io,
        };
        let z_j = z_next
            .iter()
            .map(R1CSVar::value)
            .collect::<Result<_, _>>()?;

        Ok(Self {
            i,
            j: i + 1,
            z_i: z_i.to_owned(),
            z_j,
            U,
            W,
            U_secondary,
            W_secondary,
            u,
            w,
            _random_oracle: PhantomData,
            _step_circuit: PhantomData,
        })
    }

    pub fn prove_from(
        params: &PublicParams<G1, G2, C1, C2, RO, SC>,
        step_circuit: &SC,
        left_node: &Self,
        right_node: &Self,
    ) -> Result<Self, cyclefold::Error> {
        Self::prove_from_with_commit_fn(params, step_circuit, left_node, right_node, |pp, w| {
            w.commit::<C1>(pp)
        })
    }

    pub fn prove_from_with_commit_fn(
        params: &PublicParams<G1, G2, C1, C2, RO, SC>,
        step_circuit: &SC,
        left_node: &Self,
        right_node: &Self,
        mut commit_fn: impl FnMut(&C1::PP, &R1CSWitness<G1>) -> C1::Commitment,
    ) -> Result<Self, cyclefold::Error> {
        let _span = tracing::debug_span!(
            target: LOG_TARGET,
            "prove_from",
            i = left_node.i,
            j = right_node.j,
        )
        .entered();

        // proof left node
        let (proof_left, (U_l, W_l), (U_l_secondary, W_l_secondary)) = NIMFSProof::prove(
            &params.pp,
            &params.pp_secondary,
            &params.ro_config,
            &params.digest,
            (&params.shape, &params.shape_secondary),
            (&left_node.U, &left_node.W),
            (&left_node.U_secondary, &left_node.W_secondary),
            (&left_node.u, &left_node.w),
        )?;
        // proof right node
        let (proof_right, (U_r, W_r), (U_r_secondary, W_r_secondary)) = NIMFSProof::prove(
            &params.pp,
            &params.pp_secondary,
            &params.ro_config,
            &params.digest,
            (&params.shape, &params.shape_secondary),
            (&right_node.U, &right_node.W),
            (&right_node.U_secondary, &right_node.W_secondary),
            (&right_node.u, &right_node.w),
        )?;

        // proof resulting node
        let (proof, (U, W), (U_secondary, W_secondary)) = NIMFSProof::prove_with_relaxed(
            &params.pp,
            &params.pp_secondary,
            &params.ro_config,
            &params.digest,
            (&params.shape, &params.shape_secondary),
            (&U_l, &W_l),
            (&U_l_secondary, &W_l_secondary),
            (&U_r, &W_r),
            (&U_r_secondary, &W_r_secondary),
        )?;

        let (i, j, k) = (left_node.i, left_node.j, right_node.j);
        let (z_i, z_j, z_k) = (&left_node.z_i, &left_node.z_j, &right_node.z_j);
        let left_node = PCDNodeInput::<G1, G2, C1, C2, RO> {
            U: left_node.U.clone(),
            U_secondary: left_node.U_secondary.clone(),
            u: left_node.u.clone(),
            proof: proof_left,
        };
        let right_node = PCDNodeInput::<G1, G2, C1, C2, RO> {
            U: right_node.U.clone(),
            U_secondary: right_node.U_secondary.clone(),
            u: right_node.u.clone(),
            proof: proof_right,
        };

        let input = NovaAugmentedCircuitNonBaseInput::<G1, G2, C1, C2, RO> {
            i: i.into(),
            j: j.into(),
            k: k.into(),
            z_i: z_i.to_owned(),
            z_j: z_j.to_owned(),
            z_k: z_k.to_owned(),

            vk: params.digest,
            nodes: [left_node, right_node],
            proof,
        };

        let cs = ConstraintSystem::new_ref();
        cs.set_mode(SynthesisMode::Prove {
            construct_matrices: false,
        });

        let circuit = NovaAugmentedCircuit::new(
            &params.ro_config,
            step_circuit,
            NovaAugmentedCircuitInput::NonBase(input),
        );
        let _ = tracing::debug_span!(target: LOG_TARGET, "satisfying_assignment")
            .in_scope(|| NovaConstraintSynthesizer::generate_constraints(circuit, cs.clone()))?;

        let cs_borrow = cs.borrow().unwrap();
        let witness = cs_borrow.witness_assignment.clone();
        let pub_io = cs_borrow.instance_assignment.clone();

        let w = R1CSWitness::<G1> { W: witness };

        let commitment_W = commit_fn(&params.pp, &w);
        let u = R1CSInstance::<G1, C1> {
            commitment_W,
            X: pub_io,
        };

        Ok(Self {
            i,
            j: k,
            z_i: z_i.to_owned(),
            z_j: z_k.to_owned(),
            U,
            W,
            U_secondary,
            W_secondary,
            u,
            w,
            _random_oracle: PhantomData,
            _step_circuit: PhantomData,
        })
    }

    pub fn verify(
        &self,
        params: &PublicParams<G1, G2, C1, C2, RO, SC>,
    ) -> Result<(), cyclefold::Error> {
        let _span = tracing::debug_span!(
            target: LOG_TARGET,
            "verify",
            i = self.i,
            j = self.j,
        )
        .entered();

        const NOT_SATISFIED_ERROR: cyclefold::Error =
            cyclefold::Error::R1CS(crate::r1cs::Error::NotSatisfied);
        let PCDNode {
            i,
            j,
            z_i,
            z_j,
            U,
            W,
            U_secondary,
            W_secondary,
            u,
            w,
            ..
        } = self;

        let mut random_oracle = RO::new(&params.ro_config);
        random_oracle.absorb(&params.digest);
        random_oracle.absorb(&G1::ScalarField::from(*i));
        random_oracle.absorb(&G1::ScalarField::from(*j));
        random_oracle.absorb(z_i);
        random_oracle.absorb(z_j);
        random_oracle.absorb(&U);
        random_oracle.absorb_non_native(&U_secondary);

        let hash: &G1::ScalarField =
            &random_oracle.squeeze_field_elements(augmented::SQUEEZE_NATIVE_ELEMENTS_NUM)[0];
        if hash != &u.X[1] {
            return Err(NOT_SATISFIED_ERROR);
        }

        params.shape.is_relaxed_satisfied(U, W, &params.pp)?;
        params.shape_secondary.is_relaxed_satisfied(
            U_secondary,
            W_secondary,
            &params.pp_secondary,
        )?;
        params.shape.is_satisfied(u, w, &params.pp)?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        circuits::nova::sequential::tests::CubicCircuit, pedersen::PedersenCommitment,
        poseidon_config, LOG_TARGET as SUPERNOVA_TARGET,
    };

    use ark_crypto_primitives::sponge::poseidon::PoseidonSponge;
    use ark_ff::Field;

    use tracing_subscriber::{
        filter, fmt::format::FmtSpan, layer::SubscriberExt, util::SubscriberInitExt,
    };

    #[test]
    fn ivc_base_step() {
        ivc_base_step_with_cycle::<
            ark_pallas::PallasConfig,
            ark_vesta::VestaConfig,
            PedersenCommitment<ark_pallas::Projective>,
            PedersenCommitment<ark_vesta::Projective>,
        >()
        .unwrap()
    }

    fn ivc_base_step_with_cycle<G1, G2, C1, C2>() -> Result<(), cyclefold::Error>
    where
        G1: SWCurveConfig,
        G2: SWCurveConfig<BaseField = G1::ScalarField, ScalarField = G1::BaseField>,
        G1::BaseField: PrimeField + Absorb,
        G2::BaseField: PrimeField + Absorb,
        C1: CommitmentScheme<Projective<G1>, Commitment = Projective<G1>, SetupAux = ()>,
        C2: CommitmentScheme<Projective<G2>, Commitment = Projective<G2>, SetupAux = ()>,
    {
        let ro_config = poseidon_config();

        let circuit = CubicCircuit::<G1::ScalarField>::default();
        let z_0 = vec![G1::ScalarField::ONE];
        let z_1 = vec![G1::ScalarField::from(7)];

        let params = PublicParams::<
            G1,
            G2,
            C1,
            C2,
            PoseidonSponge<G1::ScalarField>,
            CubicCircuit<G1::ScalarField>,
        >::setup(ro_config, &circuit, &(), &())?;

        let recursive_snark = PCDNode::prove_step(&params, &circuit, 0, &z_0)?;
        recursive_snark.verify(&params)?;

        assert_eq!(&recursive_snark.z_j, &z_1);

        Ok(())
    }

    #[test]
    fn ivc_multiple_steps() {
        ivc_multiple_steps_with_cycle::<
            ark_pallas::PallasConfig,
            ark_vesta::VestaConfig,
            PedersenCommitment<ark_pallas::Projective>,
            PedersenCommitment<ark_vesta::Projective>,
        >()
        .unwrap()
    }

    fn ivc_multiple_steps_with_cycle<G1, G2, C1, C2>() -> Result<(), cyclefold::Error>
    where
        G1: SWCurveConfig,
        G2: SWCurveConfig<BaseField = G1::ScalarField, ScalarField = G1::BaseField>,
        G1::BaseField: PrimeField + Absorb,
        G2::BaseField: PrimeField + Absorb,
        C1: CommitmentScheme<Projective<G1>, Commitment = Projective<G1>, SetupAux = ()>,
        C2: CommitmentScheme<Projective<G2>, Commitment = Projective<G2>, SetupAux = ()>,
    {
        let filter = filter::Targets::new().with_target(SUPERNOVA_TARGET, tracing::Level::DEBUG);
        let _guard = tracing_subscriber::registry()
            .with(
                tracing_subscriber::fmt::layer().with_span_events(FmtSpan::ENTER | FmtSpan::CLOSE),
            )
            .with(filter)
            .set_default();

        let ro_config = poseidon_config();

        let circuit = CubicCircuit::<G1::ScalarField>::default();
        let z = [
            &[G1::ScalarField::ONE],
            &[G1::ScalarField::from(7)],
            &[G1::ScalarField::from(355)],
            &[G1::ScalarField::from(44739235)],
        ];

        let params = PublicParams::<
            G1,
            G2,
            C1,
            C2,
            PoseidonSponge<G1::ScalarField>,
            CubicCircuit<G1::ScalarField>,
        >::setup(ro_config, &circuit, &(), &())?;

        let node_0 = PCDNode::prove_step(&params, &circuit, 0, z[0])?;
        let node_1 = PCDNode::prove_step(&params, &circuit, 2, z[2])?;

        let root = PCDNode::prove_from(&params, &circuit, &node_0, &node_1)?;

        assert_eq!(&root.z_i, &z[0]);
        assert_eq!(&root.z_j, &z[3]);

        root.verify(&params)?;

        Ok(())
    }
}
