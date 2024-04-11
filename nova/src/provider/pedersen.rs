use std::marker::PhantomData;

use ark_ec::{CurveGroup, ScalarMul, VariableBaseMSM};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::rand::SeedableRng;
use sha3::digest::{ExtendableOutput, Update, XofReader};

use crate::{commitment::CommitmentScheme, LOG_TARGET};

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

    fn setup(n: usize, label: &[u8], _aux: &Self::SetupAux) -> Self::PP {
        let _span = tracing::debug_span!(
            target: LOG_TARGET,
            "pedersen::setup",
            ?n,
        )
        .entered();

        // from a16z/jolt
        //
        // https://github.com/a16z/jolt/blob/a665343662c7082c33be4766298324db798cfaa9/jolt-core/src/poly/pedersen.rs#L18-L36
        let mut shake = sha3::Shake256::default();
        shake.update(label);
        let mut buf = vec![];
        G::generator().serialize_compressed(&mut buf).unwrap();
        shake.update(&buf);

        let mut reader = shake.finalize_xof();
        let mut seed = [0u8; 32];
        reader.read(&mut seed);
        let mut rng = rand_chacha::ChaCha20Rng::from_seed(seed);

        let mut gens = Vec::with_capacity(n);
        for _ in 0..n {
            gens.push(G::rand(&mut rng));
        }
        ScalarMul::batch_convert_to_mul_base(&gens)
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
