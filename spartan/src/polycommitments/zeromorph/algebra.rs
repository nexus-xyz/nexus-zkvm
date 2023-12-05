use crate::dense_mlpoly::DensePolynomial;
use crate::math::Math;
use ark_ff::PrimeField;
use ark_poly::{
  univariate::DensePolynomial as DenseUnivarPolynomial, DenseUVPolynomial, Polynomial,
};

/// This converts an integer x = x0 + 2*x1 + ... + 2^n*xn to the integer y = xn + 2*xn-1 + ... + 2^n*x0
fn reverse_n_bits(n: usize, x: usize) -> usize {
  let mut result = 0;
  for i in 0..n {
    if x & (1 << i) != 0 {
      result |= 1 << (n - 1 - i);
    }
  }
  result
}

/// This implements the linear isomorphism from the space of multilinear polynomials
/// in n variables to the space of univariate polynomials of degree less than 2^n.
pub fn multilinear_to_univar<F: PrimeField>(p: &DensePolynomial<F>) -> DenseUnivarPolynomial<F> {
  let n = p.get_num_vars();
  let mut coeff_vec: Vec<F> = vec![F::zero(); p.len()];
  // The coefficient vector for p is encoded so that p.vec()[i] = p([in, ..., i1, i0])
  // with i = i0 + 2*i1 + ... + 2^n*in. However, the multilinear-to-univariate transformation
  // in the zeromorph paper is defined so that the coefficient of x^i is p([i0, i1, ..., in])
  for (i, c) in p.vec().iter().enumerate() {
    // p.len() is not necessarily a power of 2, so we need to extend it with zeros before we can
    // reverse the bits safely.
    coeff_vec.resize(Math::pow2(p.get_num_vars()), F::zero());
    coeff_vec[reverse_n_bits(n, i)] = *c;
  }
  let unipoly = DenseUnivarPolynomial::from_coefficients_vec(coeff_vec);
  assert!(unipoly.degree() < 2usize.pow(p.get_num_vars() as u32));
  unipoly
}
pub fn poly_sub<F: PrimeField>(
  p: &DensePolynomial<F>,
  q: &DensePolynomial<F>,
) -> DensePolynomial<F> {
  assert_eq!(p.get_num_vars(), q.get_num_vars());
  let mut p_vec = p.vec().clone();
  p_vec.truncate(p.len());
  for (p, q) in p_vec.iter_mut().zip(q.vec().iter().take(q.len())) {
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
  p_vec.truncate(p.len());
  for (p, q) in p_vec.iter_mut().zip(q.vec().iter().take(q.len())) {
    *p += q;
  }
  DensePolynomial::new(p_vec)
}

/// This function computes the quotients q0, q1, ..., qn-1 such that p - p(r) = q0*(x0 - r0) + q1*(x1 - r1) + ... + qn-1*(xn-1 - rn-1)
/// with qi a function of the first i variables only. It outputs the truncated univariate polynomials U_n(qi)^{<2^i} for i = 0, ..., n-1.
/// This uses the algorithm described in Appendix A of the Zeromorph paper.
pub fn get_truncated_quotients<F: PrimeField>(
  p: &DensePolynomial<F>,
  r: &[F],
) -> Vec<DenseUnivarPolynomial<F>> {
  let n = r.len();
  let mut quotients = vec![DensePolynomial::new(vec![F::zero()]); n];
  let mut f_n_minus_1_minus_k = p.clone();
  for k in (0..n).rev() {
    let mut f0 = f_n_minus_1_minus_k.clone();
    let mut f1 = f_n_minus_1_minus_k.clone();
    f0.bound_poly_var_bot(&F::zero());
    f1.bound_poly_var_bot(&F::one());
    let q = poly_sub(&f1, &f0);
    if k > 0 {
      f_n_minus_1_minus_k.bound_poly_var_bot(&F::zero());
      f_n_minus_1_minus_k = poly_add(&f_n_minus_1_minus_k, &scale_ML(&q, r[k]));
    }
    quotients[k] = q;
  }
  quotients
    .into_iter()
    .map(|q| multilinear_to_univar(&q))
    .collect()
}
/// This is the polynomial F(x) = Phi_(n-k)(x^(2^k)) = (x^(2^n) - 1)/(x^(2^k) - 1) from the paper.
pub fn eval_generalized_cyclotomic_polynomial<F: PrimeField>(n: usize, k: usize, x: F) -> F {
  // x^(2^k)
  let mut x_2_k = x;
  let mut x_pow = x;
  for i in 0..n {
    x_pow = x_pow.square();
    if i + 1 == k {
      x_2_k = x_pow;
    }
  }
  // x^(2^n)
  let x_2_n = x_pow;
  (x_2_n - F::one()) / (x_2_k - F::one())
}

/// This computes the coefficients needed to compute the partially evaluated identity polynomial
/// Z(X) = U_n(f) - U_n(f(r)) - \sum_{i=0}^{n-1} U_n[qi(X) * (X_i - r_i)].
/// We have U_n[qk(X)*(X_k - r_k)] = (X^(2^k) Phi_(n-k-1)(X^{2^{k+1}}) - r_k *Phi_(n-k)(X^{2^k}})) U_n(qk)^{<{2^k}} =: G_k(X) U_n(qk)^{<{2^k}}
/// This function outputs [G_k(x)]_{k=0}^{n-1}.
pub fn get_Zx_coefficients<F: PrimeField>(x: F, eval_point: &[F]) -> Vec<F> {
  let n = eval_point.len();
  let mut result = vec![F::zero(); n];
  let mut x_2_k = x;
  for k in 0..eval_point.len() {
    // TODO: this implementation could be made more efficient by reusing the computation of x^(2^k)
    let poly0 = eval_generalized_cyclotomic_polynomial(n, k, x);
    let poly1 = eval_generalized_cyclotomic_polynomial(n, k + 1, x);
    result[k] = x_2_k * poly1 - eval_point[k] * poly0;
    x_2_k = x_2_k.square();
  }
  result
}

/// This computes the coefficients needed to compute the combined shifted polynomial
/// zeta_x = q_hat - \sum_{i=0}^{n-1} y^i x^{2^n - 2^i} U_n(q_i)^{<2^i}.
/// The output is [y^i x^{2^n - 2^i}]_{i=0}^{n-1}.
pub fn get_zeta_x_coefficients<F: PrimeField>(x: F, y: F, num_vars: usize) -> Vec<F> {
  let mut y_pow = F::one();
  let mut x_pow = x;
  let mut x_max_pow = x;
  for _ in 0..num_vars {
    x_max_pow = x_max_pow.square();
  }
  let mut result = vec![F::zero(); num_vars];
  for c in result.iter_mut() {
    *c = y_pow * (x_max_pow / x_pow);
    y_pow *= y;
    x_pow = x_pow.square();
  }

  result
}

pub fn scale_ML<F: PrimeField>(p: &DensePolynomial<F>, scalar: F) -> DensePolynomial<F> {
  let mut coeffs = p.vec().clone();
  coeffs.iter_mut().for_each(|c| *c *= scalar);
  DensePolynomial::new(coeffs)
}

pub fn shift<F: PrimeField>(
  p: &DenseUnivarPolynomial<F>,
  shift_degree: usize,
) -> DenseUnivarPolynomial<F> {
  let mut coeffs = vec![F::zero(); shift_degree];
  coeffs.extend(p.coeffs().iter());
  DenseUnivarPolynomial::from_coefficients_vec(coeffs)
}

/// This computes the polynomial q_hat = \sum_{k=0}^{n-1} y^k X^{2^n - 2^k} polys[k].
pub fn shift_and_combine_with_powers<F: PrimeField>(
  polys: &[DenseUnivarPolynomial<F>],
  y: F,
  num_vars: usize,
) -> DenseUnivarPolynomial<F> {
  let mut coeffs =
    DenseUnivarPolynomial::from_coefficients_vec(vec![F::zero(); Math::pow2(num_vars)]);
  let mut y_pow = F::one();
  for (k, p) in polys.iter().enumerate() {
    assert!(p.degree() < Math::pow2(k));
    let p_shifted = shift(p, Math::pow2(num_vars) - Math::pow2(k));
    coeffs += &(&p_shifted * y_pow);
    y_pow *= y;
  }
  coeffs
}

// /// This computes the quotient q(x) in p(x) = q(x) * (x - r) + p(r) using "Ruffini's rule".
// pub fn quotient_univar_by_linear_factor<F: PrimeField>(
//   p: &DenseUnivarPolynomial<F>,
//   r: F,
// ) -> DenseUnivarPolynomial<F> {
//   let mut coeffs: Vec<F> = p.coeffs().clone().iter_mut().rev().collect();
//   let mut prev = F::zero();
//   for i in 0..coeffs.len() {
//     let tmp = coeffs[i];
//     coeffs[i] += prev;
//     prev = tmp * r;
//   }
//   coeffs.pop();
//   DenseUnivarPolynomial::from_coefficients_slice(coeffs)
// }

#[cfg(test)]
mod tests {
  use super::*;
  use crate::dense_mlpoly::DensePolynomial as DenseMLPoly;
  use ark_bls12_381::G1Projective;
  use ark_ec::CurveGroup;
  use ark_ff::{One, Zero};
  fn multilinear_to_univar_test_helper<G: CurveGroup>() {
    let p_coeffs = (0..4u8).map(G::ScalarField::from).collect::<Vec<_>>();
    let p = DenseMLPoly::<G::ScalarField>::new(p_coeffs);
    assert_eq!(p.get_num_vars(), 2);
    assert_eq!(
      p.evaluate::<G>(&[G::ScalarField::zero(), G::ScalarField::zero()]),
      G::ScalarField::from(0u8)
    );
    assert_eq!(
      p.evaluate::<G>(&[G::ScalarField::zero(), G::ScalarField::one()]),
      G::ScalarField::from(1u8)
    );
    assert_eq!(
      p.evaluate::<G>(&[G::ScalarField::one(), G::ScalarField::zero()]),
      G::ScalarField::from(2u8)
    );
    assert_eq!(
      p.evaluate::<G>(&[G::ScalarField::one(), G::ScalarField::one()]),
      G::ScalarField::from(3u8)
    );
    let uni_poly = multilinear_to_univar(&p);
    // uni_poly should be the polynomial p(0,0)x^0 + p(1,0)x^1 + p(0,1)x^2 + p(1,1)x^3
    // which is 0 + 2x + x^2 + 3x^3; so U_2(p)(2) should be 0 + 2*2 + 2^2 + 3*2^3 = 32
    assert_eq!(
      uni_poly.evaluate(&G::ScalarField::from(2u8)),
      G::ScalarField::from(32u8)
    );
  }

  #[test]
  fn multilinear_to_univar_test() {
    multilinear_to_univar_test_helper::<G1Projective>();
  }

  fn get_truncated_quotients_test_helper<G: CurveGroup>() {
    let p_evals = [1u8, 2, 1, 4]
      .into_iter()
      .map(G::ScalarField::from)
      .collect::<Vec<_>>();
    let p = DenseMLPoly::<G::ScalarField>::new(p_evals);
    assert_eq!(
      p.evaluate::<G>(&[G::ScalarField::zero(), G::ScalarField::zero()]),
      G::ScalarField::from(1u8)
    );
    assert_eq!(
      p.evaluate::<G>(&[G::ScalarField::zero(), G::ScalarField::one()]),
      G::ScalarField::from(2u8)
    );
    assert_eq!(
      p.evaluate::<G>(&[G::ScalarField::one(), G::ScalarField::zero()]),
      G::ScalarField::from(1u8)
    );
    assert_eq!(
      p.evaluate::<G>(&[G::ScalarField::one(), G::ScalarField::one()]),
      G::ScalarField::from(4u8)
    );

    let r = vec![G::ScalarField::from(4u8), G::ScalarField::from(3u8)];
    // We have p(u) = 1 * [(1-u0)(1-u1)] + 2 * [(1-u0)(u1)] + 1 * [u0(1-u1)] + 4 * [u0u1]
    // so p(u0, u1) = 1 - u0 - u1 + u0u1 - 2u0u1 + 2u1 - u0u1 + u0 + 4u0u1 = 2u0u1 + u1 + 1
    // So for r = (4, 3), p(r) = 2 * 12 + 3 + 1 = 28

    let v = p.evaluate::<G>(&r);
    assert_eq!(v, G::ScalarField::from(28u8));
    let quotients = get_truncated_quotients(&p, &r);
    assert_eq!(quotients.len(), 2);
    assert_eq!(quotients[0].degree(), 0);
    assert_eq!(quotients[1].degree(), 1);

    // We want to compute q0, q1 such that p(u0, u1) - 11 = (u1 - 3)q1 + (u0 - 4)q0
    // where q1 is a function of u0, and q0 is constant.

    // This is p - 28 = (u1 - 3)*(2u0 + 1) + (u0 - 4)*6
    // so q1 = 2u0 + 1, q0 = 6

    // The evals of q1 are q1(0,0) = 1, q1(0,1) = 3, q1(1,0) = 1, q1(1,1) = 3
    // and the evals of q0 are q0(0,0) = q0(0,1) = q0(1,0) = q0(1,1) = 6
    // So, transforming them to univariate polynomials gives U_2(q1) = 1 + 3x + x^2 + 3x^3 and U_2(q0) = 6 + 6x + 6x^2 + 6x^3
    // Taking the truncations gives U_2(q1)^{<2} = 1 + 3x and U_2(q0)^{<1} = 6

    assert_eq!(
      quotients[0],
      DenseUnivarPolynomial::from_coefficients_slice(&[6u8.into()])
    );
    assert_eq!(
      quotients[1],
      DenseUnivarPolynomial::from_coefficients_slice(&[1u8.into(), 3u8.into()])
    );
  }
  #[test]
  fn get_truncated_quotients_test() {
    get_truncated_quotients_test_helper::<G1Projective>();
  }

  fn eval_generalized_cyclotomic_polynomial_test_helper<G: CurveGroup>() {
    let n = 4;
    let k = 2;
    let x = G::ScalarField::from(2u8);
    // We want to evaluate F(x) = Phi_(n-k)(x^(2^k)) = Phi_2(x^4) = 1 + x^4 + x^8 + x^12
    // Plugging in x = 2, we get F(2) = 1 + 16 + 256 + 4096 = 4369
    assert_eq!(
      eval_generalized_cyclotomic_polynomial::<G::ScalarField>(n, k, x),
      G::ScalarField::from(4369u16)
    );
  }
  #[test]
  fn eval_generalized_cyclotomic_polynomial_test() {
    eval_generalized_cyclotomic_polynomial_test_helper::<G1Projective>();
  }

  fn get_Zx_coefficients_test_helper<G: CurveGroup>() {
    let r = vec![G::ScalarField::from(4u8), G::ScalarField::from(3u8)];
    let x = G::ScalarField::from(2u8);
    // The Zx coefficients should be G_0(x) = (x^1 Phi_1(x^2) - r0 * Phi_2(x)) = x * (1 + x^2) - 4 * (1 + x + x^2 + x^3) = -4 - 3x - 4x^2 - 3x^3
    // and G_1(x) = (x^2 Phi_0(x^4) - r1 * Phi_1(x^2)) = x^2 * (1) - 3 * (1 + x^2) = -3 -2x^2
    let expected0 = DenseUnivarPolynomial::from_coefficients_slice(&[
      -G::ScalarField::from(4u8),
      -G::ScalarField::from(3u8),
      -G::ScalarField::from(4u8),
      -G::ScalarField::from(3u8),
    ])
    .evaluate(&G::ScalarField::from(2u8));
    assert_eq!(expected0, -G::ScalarField::from(50u8));
    let expected1 = DenseUnivarPolynomial::from_coefficients_slice(&[
      -G::ScalarField::from(3u8),
      G::ScalarField::zero(),
      -G::ScalarField::from(2u8),
    ])
    .evaluate(&G::ScalarField::from(2u8));
    assert_eq!(expected1, -G::ScalarField::from(11u8));
    let actual = get_Zx_coefficients(x, &r);
    assert_eq!(actual.len(), 2);
    assert_eq!(actual[0], expected0);
    assert_eq!(actual[1], expected1);
  }
  #[test]
  fn get_Zx_coefficients_test() {
    get_Zx_coefficients_test_helper::<G1Projective>();
  }

  fn get_zeta_x_coefficients_test_helper<G: CurveGroup>() {
    let x = G::ScalarField::from(2u8);
    let y = G::ScalarField::from(3u8);
    let num_vars = 2;
    let actual = get_zeta_x_coefficients(x, y, num_vars);
    assert_eq!(actual.len(), 2);
    // We should have actual[0] = y^0 * x^(2^2 - 2^0) = 1 * 2^3 = 8
    assert_eq!(actual[0], G::ScalarField::from(8u8));
    // We should have actual[1] = y^1 * x^(2^2 - 2^1) = 3 * 2^2 = 12
    assert_eq!(actual[1], G::ScalarField::from(12u8));
  }
  #[test]
  fn get_zeta_x_coefficients_test() {
    get_zeta_x_coefficients_test_helper::<G1Projective>();
  }
  fn shift_test_helper<G: CurveGroup>() {
    // This is p(x) = 1 + 2x + 3x^2 + 4x^3; p(2) = 1 + 2 * 2 + 3 * 4 + 4 * 8 = 49
    let unshifted =
      DenseUnivarPolynomial::from_coefficients_vec((1..5u8).map(G::ScalarField::from).collect());
    assert_eq!(
      unshifted.evaluate(&G::ScalarField::from(2u8)),
      G::ScalarField::from(49u8)
    );
    let shifted = shift(&unshifted, 2);
    // This should be p(x) * x^2 = x^2 + 2x^3 + 3x^4 + 4x^5; p(2) = 196
    assert_eq!(
      shifted.evaluate(&G::ScalarField::from(2u8)),
      G::ScalarField::from(196u16)
    );
  }
  #[test]
  fn shift_test() {
    shift_test_helper::<G1Projective>();
  }

  fn shift_and_combine_with_powers_test_helper<G: CurveGroup>() {
    let polys = [
      DenseUnivarPolynomial::from_coefficients_slice(&[G::ScalarField::from(1u8)]),
      DenseUnivarPolynomial::from_coefficients_slice(&[
        G::ScalarField::from(2u8),
        G::ScalarField::from(3u8),
      ]),
    ];
    let y = G::ScalarField::from(5u8);
    let num_vars = 2;
    let actual = shift_and_combine_with_powers(&polys, y, num_vars);
    assert_eq!(actual.degree(), 3);
    // We should have actual = (1)x^3 + y*(2 + 3x)x^2 = 10x^2 + 16x^3
    assert_eq!(
      actual,
      DenseUnivarPolynomial::from_coefficients_slice(&[
        G::ScalarField::from(0u8),
        G::ScalarField::from(0u8),
        G::ScalarField::from(10u8),
        G::ScalarField::from(16u8),
      ])
    );
  }
  #[test]
  fn shift_and_combine_with_powers_test() {
    shift_and_combine_with_powers_test_helper::<G1Projective>();
  }
}
