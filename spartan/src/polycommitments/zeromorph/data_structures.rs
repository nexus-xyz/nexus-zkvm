use crate::dense_mlpoly::DensePolynomial;
use crate::math::Math;
use crate::polycommitments::{
  PolyCommitmentScheme, PolyCommitmentTrait, SRSTrait, VectorCommitmentTrait,
};
use crate::transcript::AppendToTranscript;
use ark_ec::CurveGroup;
use ark_ff::PrimeField;
use ark_poly_commit::{
  PCCommitment, PCRandomness, PCUniversalParams, PolynomialCommitment as UnivarPolyCommitment,
};
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

impl<U: PCUniversalParams> SRSTrait for U {
  fn setup(num_poly_vars: usize, label: &'static [u8], rng: &mut impl RngCore) -> Self {
    Self::setup(num_poly_vars.log_2() as usize, label, rng)
  }
}
