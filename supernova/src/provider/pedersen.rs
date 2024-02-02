use std::marker::PhantomData;

use crate::{commitment::CommitmentScheme, LOG_TARGET};
use ark_ec::{CurveGroup, ScalarMul, VariableBaseMSM};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};

#[derive(Debug)]
pub struct PedersenCommitment<G>(PhantomData<G>);

impl<G> CommitmentScheme<G> for PedersenCommitment<G>
where
    G: CurveGroup,
    G::MulBase: CanonicalSerialize + CanonicalDeserialize,
{
    type PP = Vec<G::MulBase>;
    type SetupAux = ();

    type Commitment = G;

    fn setup(n: usize, _aux: &Self::SetupAux) -> Self::PP {
        // TODO: replace test rng.
        let mut rng = ark_std::test_rng();
        let ps: Vec<G> = (0..n).map(|_| G::rand(&mut rng)).collect();
        ScalarMul::batch_convert_to_mul_base(&ps)
    }

    fn commit(bases: &Self::PP, scalars: &[G::ScalarField]) -> G {
        let _span = tracing::debug_span!(
            target: LOG_TARGET,
            "pedersen::commit",
            msm_size = scalars.len(),
        )
        .entered();

        VariableBaseMSM::msm_unchecked(bases, scalars)
    }
}
