use crate::commitment::CommitmentScheme;
use ark_ec::{Group, VariableBaseMSM};
use ark_std::UniformRand;
use ark_test_curves::bls12_381::{G1Affine as GAffine, G1Projective as G};

pub struct PedersenCommitment {}

// TODO: This should be generic over any group
impl CommitmentScheme<G> for PedersenCommitment {
    type PP = (Vec<G>, G);

    fn setup(n: usize) -> Self::PP {
        let mut rng = ark_std::test_rng();
        let h = G::rand(&mut rng);
        let g = (0..n).map(|_| G::rand(&mut rng)).collect();

        (g, h)
    }

    fn commit(pp: &Self::PP, x: &[<G as Group>::ScalarField], r: <G as Group>::ScalarField) -> G {
        let gs = &pp.0.iter().map(|x| (*x).into()).collect::<Vec<GAffine>>()[..];
        let h = pp.1.into();
        let bases = &[&[h], gs].concat()[..];
        let scalars = &[&[r], x].concat();
        G::msm(bases, scalars).unwrap()
    }

    fn open(
        pp: &Self::PP,
        c: G,
        x: &[<G as Group>::ScalarField],
        r: <G as Group>::ScalarField,
    ) -> bool {
        Self::commit(pp, x, r) == c
    }
}

#[cfg(test)]
mod tests {
    use ark_test_curves::bls12_381::Fr as ScalarField;

    use super::*;

    #[test]
    fn it_works() {
        let n = 3;
        let mut rng = ark_std::test_rng();

        let x = &(0..n)
            .map(|_| ScalarField::rand(&mut rng))
            .collect::<Vec<ScalarField>>()[..];
        let r = ScalarField::rand(&mut rng);

        let pp = PedersenCommitment::setup(n);
        let c = PedersenCommitment::commit(&pp, x, r);
        let res = PedersenCommitment::open(&pp, c, x, r);

        assert!(res)
    }
}
