use std::{
    fmt::Debug,
    ops::{Add, AddAssign, Mul, MulAssign},
};

use ark_ec::CurveGroup;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};

/// Defines basic operations on commitments.
pub trait CommitmentOps<Rhs = Self, Output = Self>:
    Add<Rhs, Output = Output> + AddAssign<Rhs>
{
}

impl<T, Rhs, Output> CommitmentOps<Rhs, Output> for T where
    T: Add<Rhs, Output = Output> + AddAssign<Rhs>
{
}

/// A helper trait for types implementing a multiplication of a commitment with a scalar.
pub trait ScalarMul<Rhs, Output = Self>: Mul<Rhs, Output = Output> + MulAssign<Rhs> {}

impl<T, Rhs, Output> ScalarMul<Rhs, Output> for T where T: Mul<Rhs, Output = Output> + MulAssign<Rhs>
{}

pub trait Commitment<G: CurveGroup>:
    Default
    + Debug
    + PartialEq
    + Eq
    + Copy
    + Clone
    + Send
    + Sync
    + CommitmentOps
    + ScalarMul<G::ScalarField>
    + Into<G>
    + From<G>
    + CanonicalSerialize
    + CanonicalDeserialize
{
    /// Converts `self` into the affine representation.
    fn into_affine(self) -> G::Affine {
        self.into().into_affine()
    }
}

impl<G: CurveGroup, T> Commitment<G> for T where
    T: Default
        + Debug
        + PartialEq
        + Eq
        + Copy
        + Clone
        + Send
        + Sync
        + CommitmentOps
        + ScalarMul<G::ScalarField>
        + Into<G>
        + From<G>
        + CanonicalSerialize
        + CanonicalDeserialize
{
}

pub trait CommitmentScheme<G: CurveGroup>: Send + Sync {
    /// Commitment scheme public parameters.
    type PP: CanonicalSerialize + CanonicalDeserialize + Sync;

    /// Auxiliary data used for setup (such as an SRS)
    type SetupAux;

    /// Commitment type.
    type Commitment: Commitment<G>;

    /// Samples new public parameters of a specified size.
    fn setup(n: usize, aux: &Self::SetupAux) -> Self::PP;

    /// Commits to the given vector using provided public parameters.
    fn commit(pp: &Self::PP, x: &[G::ScalarField]) -> Self::Commitment;
}
