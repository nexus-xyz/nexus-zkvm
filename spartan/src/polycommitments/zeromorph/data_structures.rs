use crate::dense_mlpoly::DensePolynomial;
use crate::polycommitments::{PolyCommitmentScheme, PolyCommitmentTrait, VectorCommitmentTrait};
use crate::transcript::AppendToTranscript;
use ark_ec::CurveGroup;
use ark_ff::PrimeField;
use ark_poly_commit::{PCCommitment, PCRandomness, PolynomialCommitment as UnivarPolyCommitment};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::fmt::Debug;
use ark_std::rand::RngCore;
use ark_std::{marker::PhantomData, vec::Vec};

impl<G: CurveGroup, C: PCCommitment> PolyCommitmentTrait<G> for C
where
  C: PartialEq + Debug + AppendToTranscript<G>,
{
  fn zero(_n: usize) -> Self {
    C::empty()
  }
}
