use std::marker::PhantomData;

use crate::commitment::CommitmentScheme;
use ark_ec::{Group, ScalarMul, VariableBaseMSM};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PedersenCommitment<G>(PhantomData<G>);

impl<G: VariableBaseMSM> CommitmentScheme<G> for PedersenCommitment<G> {
    type PP = Vec<G>;

    type Commitment = G;

    fn setup(n: usize) -> Self::PP {
        // TODO: replace test rng.
        let mut rng = ark_std::test_rng();
        (0..n).map(|_| G::rand(&mut rng)).collect()
    }

    fn commit(pp: &Self::PP, x: &[G::ScalarField]) -> G {
        let h = ScalarMul::batch_convert_to_mul_base(pp);
        let bases = &h;
        let scalars = x;
        VariableBaseMSM::msm_unchecked(bases, scalars)
    }

    fn open(pp: &Self::PP, c: G, x: &[<G as Group>::ScalarField]) -> bool {
        Self::commit(pp, x) == c
    }
}

#[cfg(test)]
mod tests {
    use ark_std::UniformRand;
    use ark_test_curves::bls12_381::Fr as ScalarField;
    use ark_test_curves::bls12_381::G1Projective as G;

    use super::*;

    #[test]
    fn commitment_matches() {
        let n = 3;
        let mut rng = ark_std::test_rng();

        let x = &(0..n)
            .map(|_| ScalarField::rand(&mut rng))
            .collect::<Vec<ScalarField>>()[..];

        let pp = PedersenCommitment::<G>::setup(n);
        let c = PedersenCommitment::<G>::commit(&pp, x);
        let res = PedersenCommitment::<G>::open(&pp, c, x);

        assert!(res)
    }
}
