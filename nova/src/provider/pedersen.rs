use std::marker::PhantomData;

use crate::{commitment::CommitmentScheme, LOG_TARGET};
use ark_ec::{
    short_weierstrass::{Affine, Projective, SWCurveConfig},
    ScalarMul, VariableBaseMSM,
};
use ark_ff::{field_hashers::hash_to_field, PrimeField};
use sha3::digest::{ExtendableOutput, Update};

pub use crate::provider::hashtocurve::SVDWMap;

#[derive(Debug)]
pub struct PedersenCommitment<G>(PhantomData<G>);

impl<G> CommitmentScheme<Projective<G>> for PedersenCommitment<G>
where
    G: SWCurveConfig + SVDWMap,
    G::BaseField: PrimeField,
{
    type PP = Vec<Affine<G>>;
    type SetupAux = [u8];

    type Commitment = Projective<G>;

    fn setup(n: usize, _bytes: &Self::SetupAux) -> Self::PP {
        let _span = tracing::debug_span!(
            target: LOG_TARGET,
            "pedersen::setup",
            %n,
        )
        .entered();

        #[cfg(not(test))]
        let bases = batch_map_to_curve(b"from_uniform_bytes", _bytes, n);
        #[cfg(test)]
        let bases = {
            let mut rng = ark_std::test_rng();
            let ps: Vec<Projective<G>> = (0..n)
                .map(|_| <Projective<G> as ark_std::UniformRand>::rand(&mut rng))
                .collect();
            ark_ec::ScalarMul::batch_convert_to_mul_base(&ps)
        };

        bases
    }

    fn commit(bases: &Self::PP, scalars: &[G::ScalarField]) -> Self::Commitment {
        let _span = tracing::debug_span!(
            target: LOG_TARGET,
            "pedersen::commit",
            msm_size = scalars.len(),
        )
        .entered();

        VariableBaseMSM::msm_unchecked(bases, scalars)
    }
}

#[doc(hidden)]
pub fn batch_map_to_curve<G>(domain: &[u8], bytes: &[u8], len: usize) -> Vec<Affine<G>>
where
    G: SWCurveConfig + SVDWMap,
    G::BaseField: PrimeField,
{
    const SEC_PARAM: usize = 128;

    let mut hasher = sha3::Shake256::default();
    hasher.update(domain);
    hasher.update(bytes);
    let mut reader = hasher.finalize_xof();

    let mut points = Vec::with_capacity(len);

    for _ in 0..len {
        let u1 =
            hash_to_field::<G::BaseField, <sha3::Shake256 as ExtendableOutput>::Reader, SEC_PARAM>(
                &mut reader,
            );
        let u2 =
            hash_to_field::<G::BaseField, <sha3::Shake256 as ExtendableOutput>::Reader, SEC_PARAM>(
                &mut reader,
            );
        let p1 = G::map_to_curve(u1);
        let p2 = G::map_to_curve(u2);

        points.push(p1 + p2);
    }

    ScalarMul::batch_convert_to_mul_base(&points)
}
