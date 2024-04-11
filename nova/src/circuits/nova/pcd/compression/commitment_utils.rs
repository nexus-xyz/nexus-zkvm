use ark_ec::CurveGroup;
use ark_spartan::{
    math::Math,
    polycommitments::{PCSKeys, PolyCommitmentScheme, VectorCommitmentScheme},
};
use ark_std::marker::PhantomData;

use crate::commitment::CommitmentScheme;

pub struct PolyVectorCommitment<G, PC>
where
    G: CurveGroup,
    PC: PolyCommitmentScheme<G>,
{
    _group: PhantomData<G>,
    _poly_commitment: PhantomData<PC>,
}

impl<G: CurveGroup, PC: PolyCommitmentScheme<G>> CommitmentScheme<G> for PolyVectorCommitment<G, PC>
where
    G: CurveGroup,
    PC::Commitment: Copy + Into<G> + From<G>,
{
    type SetupAux = PC::SRS;
    type PP = PCSKeys<G, PC>;
    type Commitment = PC::Commitment;

    /// This function is just for testing purposes: in practice, we will need to
    /// load PC's SRS from a file.
    fn setup(n: usize, _label: &[u8], srs: &PC::SRS) -> Self::PP {
        PC::trim(srs, n.log_2())
    }

    fn commit(pp: &Self::PP, x: &[G::ScalarField]) -> Self::Commitment {
        <PC as VectorCommitmentScheme<G>>::commit(x, &pp.ck)
    }
}
