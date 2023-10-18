use std::ops::{Add, AddAssign, Mul, MulAssign};

use ark_ec::PrimeGroup;
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

pub trait Commitment<G: PrimeGroup>:
    Default + PartialEq + Copy + Clone + Send + CommitmentOps + ScalarMul<G::ScalarField>
{
}
impl<G: PrimeGroup, T> Commitment<G> for T where
    T: Default + PartialEq + Copy + Clone + Send + CommitmentOps + ScalarMul<G::ScalarField>
{
}

pub trait CommitmentScheme<G: PrimeGroup> {
    /// Commitment scheme public parameters.
    type PP: CanonicalSerialize + CanonicalDeserialize + Sync;

    /// Commitment type.
    type Commitment: Commitment<G>;

    /// Samples new public parameters of a specified size.
    fn setup(n: usize) -> Self::PP;

    /// Commits to the given vector using provided public parameters.
    fn commit(pp: &Self::PP, x: &[G::ScalarField]) -> Self::Commitment;

    /// Verifies committed value.
    fn open(pp: &Self::PP, c: Self::Commitment, x: &[G::ScalarField]) -> bool;
}
