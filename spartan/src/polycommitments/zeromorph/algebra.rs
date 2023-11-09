//use super::unipoly::*;
use crate::dense_mlpoly::DensePolynomial;
use ark_poly::DenseUVPolynomial;

/// This implements the linear isomorphism from the space of multilinear polynomials
/// in n variables to the space of univariate polynomials of degree less than 2^n.
impl<F: PrimeField> From<DensePolynomial<F>> for DenseUVPolynomial<F> {
  fn from(p: DensePolynomial<F>) -> Self {
    let unipoly = from_coefficients_vec(p.Z);
    assert!(unipoly.degree() < 2usize.pow(p.get_num_vars() as u32));
    unipoly
  }
}
