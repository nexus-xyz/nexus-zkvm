use ark_ec::Group;

pub trait CommitmentScheme<G: Group> {
    type PP;

    fn setup(n: usize) -> Self::PP;

    fn commit(pp: &Self::PP, x: &[G::ScalarField], r: G::ScalarField) -> G;

    fn open(pp: &Self::PP, c: G, x: &[G::ScalarField], r: G::ScalarField) -> bool;
}
