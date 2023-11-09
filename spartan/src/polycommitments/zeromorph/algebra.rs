//use super::unipoly::*;
use super::transcript_utils::PolyCommitmentTranscript;
use super::Zeromorph;
use crate::dense_mlpoly::DensePolynomial;
use ark_ec::CurveGroup;
use ark_ff::PrimeField;
use ark_poly::DenseUVPolynomial;
use ark_poly_commit::PolynomialCommitment as UnivarPCS;

/// This implements the linear isomorphism from the space of multilinear polynomials
/// in n variables to the space of univariate polynomials of degree less than 2^n.
impl<
    G: CurveGroup,
    P: DenseUVPolynomial<G::ScalarField>,
    U: UnivarPCS<G::ScalarField, P, PolyCommitmentTranscript>,
  > Zeromorph<G, P, U>
{
  pub fn multilinear_to_univar(p: DensePolynomial<G::ScalarField>) -> P {
    let coeff_vec: Vec<G::ScalarField> = (*p.vec()).clone();
    let unipoly = P::from_coefficients_vec(coeff_vec);
    assert!(unipoly.degree() < 2usize.pow(p.get_num_vars() as u32));
    unipoly
  }
}
