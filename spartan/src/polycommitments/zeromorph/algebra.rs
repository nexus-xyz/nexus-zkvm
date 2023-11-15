//use super::unipoly::*;
use super::transcript_utils::PolyCommitmentTranscript;
use super::Zeromorph;
use crate::dense_mlpoly::DensePolynomial;
use crate::math::Math;
use ark_ec::CurveGroup;
use ark_ff::{Field, PrimeField};
use ark_poly::DenseUVPolynomial;
use ark_poly_commit::PolynomialCommitment as UnivarPCS;
use ark_std::{One, Zero};

/// This implements the linear isomorphism from the space of multilinear polynomials
/// in n variables to the space of univariate polynomials of degree less than 2^n.

pub fn multilinear_to_univar<F: PrimeField, P: DenseUVPolynomial<F>>(p: DensePolynomial<F>) -> P {
  let coeff_vec: Vec<F> = (*p.vec()).clone();
  let unipoly = P::from_coefficients_vec(coeff_vec);
  assert!(unipoly.degree() < 2usize.pow(p.get_num_vars() as u32));
  unipoly
}
pub fn get_quotients<F: PrimeField>(
  p: &DensePolynomial<F>,
  r: &[F],
  eval: &F,
) -> Vec<DensePolynomial<F>> {
  todo!()
}
// This is the polynomial F(x) = Phi_(n-k)(x^(2^k)) from the paper; as Phi_(n-k) = sum_{i=0}^{2^(n-k)-1} x^i = (x^(2^(n-k)) - 1)/(x - 1),
// the roots of F are exactly the 2^nth roots of unity which are not 2^k-th roots of unity, i.e. 2-power roots of unity whose order
// is between 2^(k+1) and 2^n.
pub fn eval_generalized_cyclotomic_polynomial<F: PrimeField>(n: usize, k: usize, x: F) -> F {
  let num_nonzero_terms = (n - k).pow2();
  // x^(2^k)
  let x_2_k = (0..k).fold(x, |x, _| x.square());
  (0..num_nonzero_terms)
    .fold((F::zero(), F::one()), |(sum, x_pow), _| {
      (sum + x_pow, x_pow * x_2_k)
    })
    .0
}

//fn get_shift_polys(eval_point: Vec<F>) -> Vec<DensePolynomial<F>> {
//  let n = eval_point.len();
//  (0..n)
//    .map(|k| Zeromorph::<G, P, U>::generalized_cyclotomic_polynomial(n, k))
//    .zip()
//    .collect()
//} j
pub fn get_Zx_coefficients<F: PrimeField>(x: F, eval_point: &[F]) -> Vec<F> {
  let n = eval_point.len();
  let mut result = vec![F::zero(); n];
  let mut x_2_k = x;
  for k in 0..eval_point.len() {
    let poly0 = eval_generalized_cyclotomic_polynomial(n, k, x);
    let poly1 = eval_generalized_cyclotomic_polynomial(n, k + 1, x);
    result[k] = x_2_k * poly1 - eval_point[k] * poly0;
    x_2_k = x_2_k.square();
  }
  result
}

pub fn univar_of_constant<F: PrimeField, P: DenseUVPolynomial<F>>(c: F, num_vars: usize) -> P {
  let coeff_vec = vec![c; num_vars];
  P::from_coefficients_vec(coeff_vec)
}

pub fn truncate<F: PrimeField, P: DenseUVPolynomial<F>>(p: P, degree: usize) -> P {
  let mut coeffs = p.coeffs().to_vec();
  coeffs.truncate(degree);
  P::from_coefficients_vec(coeffs)
}

pub fn scale<F: PrimeField, P: DenseUVPolynomial<F>>(p: &P, scalar: F) -> P {
  let mut coeffs = p.coeffs().to_vec();
  coeffs.iter_mut().for_each(|c| *c *= scalar);
  P::from_coefficients_vec(coeffs)
}
