//use super::unipoly::*;
use crate::dense_mlpoly::DensePolynomial;
use crate::math::Math;
use ark_ff::PrimeField;
use ark_poly::{
  univariate::DensePolynomial as DenseUnivarPolynomial, DenseUVPolynomial, Polynomial,
};

/// This implements the linear isomorphism from the space of multilinear polynomials
/// in n variables to the space of univariate polynomials of degree less than 2^n.

pub fn multilinear_to_univar<F: PrimeField>(p: &DensePolynomial<F>) -> DenseUnivarPolynomial<F> {
  let coeff_vec: Vec<F> = p.vec().clone();
  let unipoly = DenseUnivarPolynomial::from_coefficients_vec(coeff_vec);
  assert!(unipoly.degree() < 2usize.pow(p.get_num_vars() as u32));
  unipoly
}
fn times_X_ell_minus_u_ell<F: PrimeField>(
  evals: &DensePolynomial<F>,
  ell: usize,
  u: F,
) -> DensePolynomial<F> {
  let mut new_vec = evals.vec().clone();
  for (e, i) in new_vec.iter_mut().zip(0..evals.len()) {
    if i >> ell & 1 == 1 {
      *e *= F::one() - u;
    } else {
      *e *= -u;
    }
  }
  DensePolynomial::new(new_vec)
}
pub fn poly_sub<F: PrimeField>(
  p: &DensePolynomial<F>,
  q: &DensePolynomial<F>,
) -> DensePolynomial<F> {
  assert_eq!(p.get_num_vars(), q.get_num_vars());
  let mut p_vec = p.vec().clone();
  let q_vec = q.vec();
  for (p, q) in p_vec.iter_mut().zip(q_vec.iter()) {
    *p -= q;
  }
  DensePolynomial::new(p_vec)
}

pub fn poly_add<F: PrimeField>(
  p: &DensePolynomial<F>,
  q: &DensePolynomial<F>,
) -> DensePolynomial<F> {
  assert_eq!(p.get_num_vars(), q.get_num_vars());
  let mut p_vec = p.vec().clone();
  let q_vec = q.vec();
  for (p, q) in p_vec.iter_mut().zip(q_vec.iter()) {
    *p += q;
  }
  DensePolynomial::new(p_vec)
}

pub fn get_truncated_quotients<F: PrimeField>(
  p: &DensePolynomial<F>,
  r: &[F],
) -> Vec<DenseUnivarPolynomial<F>> {
  let n = r.len();
  let mut quotients = vec![];
  let mut f_n_minus_1_minus_k = p.clone();
  for k in (0..n).rev() {
    let mut f0 = f_n_minus_1_minus_k.clone();
    let mut f1 = f_n_minus_1_minus_k.clone();
    f0.bound_poly_var_top(&F::zero());
    f1.bound_poly_var_top(&F::one());
    let q = poly_sub(&f1, &f0);
    if k > 0 {
      f_n_minus_1_minus_k.bound_poly_var_top(&F::zero());
      f_n_minus_1_minus_k = poly_add(&f_n_minus_1_minus_k, &scale_ML(&quotients[k], r[k]));
    }
    quotients[k] = q;
  }
  quotients
    .into_iter()
    .map(|q| multilinear_to_univar(&q))
    .collect()
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

pub fn get_zeta_x_coefficients<F: PrimeField>(x: F, y: F, num_vars: usize) -> Vec<F> {
  let mut y_pow = F::one();
  let mut x_pow = x;
  let mut x_max_pow = x;
  for _ in 0..num_vars {
    x_max_pow = x_pow.square();
  }
  let mut result = vec![F::zero(); num_vars];
  for c in result.iter_mut() {
    *c = y_pow * (x_max_pow / x_pow);
    y_pow *= y;
    x_pow = x_pow.square();
  }

  result
}

pub fn univar_of_constant<F: PrimeField>(c: F, num_vars: usize) -> DenseUnivarPolynomial<F> {
  let coeff_vec = vec![c; num_vars];
  DenseUnivarPolynomial::from_coefficients_vec(coeff_vec)
}

//pub fn truncate<F: PrimeField, P: DenseUVPolynomial<F>>(p: P, degree: usize) -> P {
//  let mut coeffs = p.coeffs().to_vec();
//  coeffs.truncate(degree);
//  P::from_coefficients_vec(coeffs)
//}

//pub(crate) fn scale_UV<F: PrimeField>(
//  p: &DenseUnivarPolynomial<F>,
//  scalar: F,
//) -> DenseUnivarPolynomial<F> {
//  let mut coeffs = p.coeffs().to_vec();
//  coeffs.iter_mut().for_each(|c| *c *= scalar);
//  DenseUnivarPolynomial::from_coefficients_vec(coeffs)
//}

pub(crate) fn scale_ML<F: PrimeField>(p: &DensePolynomial<F>, scalar: F) -> DensePolynomial<F> {
  let mut coeffs = p.vec().clone();
  coeffs.iter_mut().for_each(|c| *c *= scalar);
  DensePolynomial::new(coeffs)
}

fn shift<F: PrimeField>(
  p: &DenseUnivarPolynomial<F>,
  shift_degree: usize,
) -> DenseUnivarPolynomial<F> {
  let mut coeffs = p.coeffs().to_vec();
  for _ in 0..shift_degree {
    coeffs.insert(0, F::zero());
  }
  DenseUnivarPolynomial::from_coefficients_vec(coeffs)
}

pub fn shift_and_combine_with_powers<F: PrimeField>(
  polys: &Vec<DenseUnivarPolynomial<F>>,
  y: F,
  num_vars: usize,
) -> DenseUnivarPolynomial<F> {
  let mut coeffs = polys
    .iter()
    .enumerate()
    .map(|(k, p)| shift(p, Math::pow2(num_vars) - Math::pow2(k)))
    .fold((vec![], F::one()), |(mut result, y_pow), p| {
      for (i, c) in p.coeffs().iter().enumerate() {
        result[i] += y_pow * c;
      }
      (result, y_pow * y)
    })
    .0;
  DenseUnivarPolynomial::from_coefficients_vec(coeffs)
}
