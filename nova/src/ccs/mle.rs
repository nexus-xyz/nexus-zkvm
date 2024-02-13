//! Helper code for multilinear extensions

use ark_ff::{Field, PrimeField};
use ark_poly::{
    multivariate::Term, DenseMVPolynomial, DenseMultilinearExtension, MultilinearExtension,
    SparseMultilinearExtension,
};

use super::super::sparse::SparseMatrix;
use super::super::utils::iter_bits_le;

/// Utility function for mle -> mvp conversion.
fn compute_coeffs_from_evals<F: PrimeField>(pts: &[F]) -> Vec<F> {
    let n = pts.len();

    // This code recursively implements sum over subsets to compute
    // the terms of the polynomial from its defining evaluations.
    //
    // see: https://crypto.stackexchange.com/a/84416
    if n == 1 {
        return pts.to_vec();
    }

    let h = n / 2;
    let l = compute_coeffs_from_evals(&pts[0..h]);
    let r = compute_coeffs_from_evals(&pts[h..n]);

    [
        l.clone(),
        l.iter()
            .zip(r.iter())
            .map(|(vl, vr)| *vr - vl)
            .collect::<Vec<F>>(),
    ]
    .concat()
}

/// Converts an mle into a generic multivariate polynomial.
pub fn mle_to_mvp<F: PrimeField, M: DenseMVPolynomial<F>>(mle: &DenseMultilinearExtension<F>) -> M {
    let evals = mle.to_evaluations();
    let coeffs = compute_coeffs_from_evals(evals.as_slice());

    let n = 1 << mle.num_vars;

    let terms: Vec<(F, M::Term)> = (0..n)
        .map(|i| {
            let bytes = (i as u32).to_le_bytes();
            let mut bits = iter_bits_le(&bytes);

            let mut t: Vec<(usize, usize)> = vec![];
            (0..mle.num_vars).for_each(|j| {
                if bits.next().unwrap() {
                    t.push((j, 1));
                }
            });

            (coeffs[i], M::Term::new(t))
        })
        .collect();

    M::from_coefficients_vec(mle.num_vars, terms)
}

/// Converts a matrix into a (sparse) mle.
pub fn matrix_to_mle<F: PrimeField>(
    m: usize,
    n: usize,
    M: &SparseMatrix<F>,
) -> SparseMultilinearExtension<F> {
    assert!(m > 0 && n > 0);

    // compute s and s'
    let s1 = (m - 1).checked_ilog2().unwrap_or(0) + 1;
    let s2 = (n - 1).checked_ilog2().unwrap_or(0) + 1;

    // number of columns in padded matrix
    let n = if n == 1 { 2 } else { n.next_power_of_two() };

    let evaluations: Vec<(usize, F)> = M.iter().map(|(i, j, value)| ((i * n + j), value)).collect();

    SparseMultilinearExtension::from_evaluations((s1 + s2) as usize, &evaluations)
}

/// Converts a vector into a (dense) mle.
pub fn vec_to_mle<F: Field>(z: &[F]) -> DenseMultilinearExtension<F> {
    let n = z.len();
    assert!(n > 0);

    let mut z = z.to_owned();
    z.resize(if n == 1 { 2 } else { n.next_power_of_two() }, F::zero());

    // compute s'
    let s = (n - 1).checked_ilog2().unwrap_or(0) + 1;

    DenseMultilinearExtension::from_evaluations_vec(s as usize, z)
}

/// Folds a vector into an mle representing another, as the lower-order entries (i.e., given vector `z` and `mle` encoding a vector `y`, returns an MLE encoding `z || y`).
pub fn fold_vec_to_mle_low<F: Field>(
    z: &[F],
    mle: &DenseMultilinearExtension<F>,
) -> DenseMultilinearExtension<F> {
    let mut n = z.len();
    assert!(n > 0);

    let mut z = z.to_owned();
    z.extend(&mle.to_evaluations());

    n = z.len();
    z.resize(if n == 1 { 2 } else { n.next_power_of_two() }, F::zero());

    // compute s'
    let s = (n - 1).checked_ilog2().unwrap_or(0) + 1;

    DenseMultilinearExtension::from_evaluations_vec(s as usize, z)
}

#[cfg(test)]
mod tests {
    use super::*;

    use ark_poly::polynomial::multivariate::{SparsePolynomial, SparseTerm};
    use ark_poly::Polynomial;
    use ark_std::{UniformRand, Zero};
    use ark_test_curves::bls12_381::{Fr, G1Projective as G};

    use crate::r1cs::tests::to_field_sparse;
    use crate::utils::iter_bits_le;

    #[test]
    fn test_coeffs_from_evals() {
        // evaluations vector: [ 10, 32, 57, 81 ]
        // encoded multilinear polynomial by evaluations: 10(1-x)(1-y) + 32x(1-y) + 57(1-x)y + 81xy
        // ... multiply out and collect terms...
        // encoded multilinear polynomial by coefficients: 10 + 22x + 47y + 2xy
        //
        // from: https://crypto.stackexchange.com/a/84416
        let pts = [Fr::from(10), Fr::from(32), Fr::from(57), Fr::from(81)];
        let exp = [Fr::from(10), Fr::from(22), Fr::from(47), Fr::from(2)];

        let coeffs = compute_coeffs_from_evals(&pts);

        assert_eq!(exp.len(), coeffs.len());
        assert!(exp.iter().zip(coeffs.iter()).all(|(e, c)| e == c));
    }

    #[test]
    fn test_mle_to_mvp() {
        let pts = [Fr::from(10), Fr::from(32), Fr::from(57), Fr::from(81)];
        let mle = DenseMultilinearExtension::<Fr>::from_evaluations_slice(2, &pts);
        let mvp: SparsePolynomial<Fr, SparseTerm> = mle_to_mvp(&mle);

        let exp = vec![
            (Fr::from(10), SparseTerm::new(vec![])),
            (Fr::from(47), SparseTerm::new(vec![(1, 1)])), // mvp repr reorders internally
            (Fr::from(22), SparseTerm::new(vec![(0, 1)])),
            (Fr::from(2), SparseTerm::new(vec![(0, 1), (1, 1)])),
        ];

        let terms = mvp.terms();

        assert_eq!(exp.len(), terms.len());
        assert!(exp.iter().zip(terms.iter()).all(|(e, t)| e == t));
    }

    #[test]
    fn test_matrix_to_mle() {
        const NUM_ROWS: usize = 3;
        const NUM_COLS: usize = 5;

        const NUM_VARS: usize = 3 + 2; // 3 bits to represent column index + 2 for rows
        #[rustfmt::skip]
        const M: &[&[u64]] = &[
            &[1, 2, 3, 4, 5],
            &[6, 7, 8, 9, 10],
            &[11, 12, 13, 14, 15],
        ];

        let sparse_m = SparseMatrix::new(&to_field_sparse::<G>(M), NUM_ROWS, NUM_COLS);
        let mle = matrix_to_mle(NUM_ROWS, NUM_COLS, &sparse_m);

        assert_eq!(mle.num_vars, NUM_VARS);

        let m = NUM_ROWS.next_power_of_two();
        let n = NUM_COLS.next_power_of_two();

        for (i, row) in M.iter().enumerate().take(m) {
            for (j, entry) in row.iter().enumerate().take(n) {
                let row_mask = (1 << 3) * i; // shift column bits
                let _j = j | row_mask;

                let j_bytes = _j.to_le_bytes();
                let j_bits: Vec<Fr> = iter_bits_le(j_bytes.as_slice())
                    .map(Fr::from)
                    .take(NUM_VARS)
                    .collect();

                let eval = mle.evaluate(&j_bits);

                let expected = if i < NUM_ROWS && j < NUM_COLS {
                    (*entry).into()
                } else {
                    Fr::zero()
                };
                assert_eq!(eval, expected);
            }
        }
    }

    #[test]
    fn test_vec_to_mle() {
        const LEN: usize = 100;
        const NUM_VARS: usize = 7; // 7 bits to represent each index (100 < 128 = 2^7)

        let mut rng = ark_std::test_rng();
        let z: Vec<Fr> = (0..LEN).map(|_| Fr::rand(&mut rng)).collect();
        let mle = vec_to_mle(&z);

        let n = LEN.next_power_of_two();
        for (i, entry) in z.iter().enumerate().take(n) {
            let i_bytes = i.to_le_bytes();
            let i_bits: Vec<Fr> = iter_bits_le(i_bytes.as_slice())
                .map(Fr::from)
                .take(NUM_VARS)
                .collect();

            let eval = mle.evaluate(&i_bits);

            let expected = if i < LEN { *entry } else { Fr::zero() };
            assert_eq!(eval, expected);
        }
    }

    #[test]
    fn test_fold_vec_to_mle_low() {
        const VEC_LEN: usize = 30;
        const MLE_LEN: usize = 60;
        const TOT_LEN: usize = 90; // 60 + 30

        const NUM_VARS: usize = 7; // 7 bits to represent each index in combination mle (30 + 60 < 128 = 2^7)

        let mut rng = ark_std::test_rng();
        let z1: Vec<Fr> = (0..MLE_LEN).map(|_| Fr::rand(&mut rng)).collect();
        let z2: Vec<Fr> = (0..VEC_LEN).map(|_| Fr::rand(&mut rng)).collect();
        let mle1 = vec_to_mle(&z1);
        let mle2 = fold_vec_to_mle_low(&z2, &mle1);

        let n = TOT_LEN;
        for i in 0..n {
            let i_bytes = i.to_le_bytes();
            let i_bits: Vec<Fr> = iter_bits_le(i_bytes.as_slice())
                .map(Fr::from)
                .take(NUM_VARS)
                .collect();

            let eval = mle2.evaluate(&i_bits);

            if (0..VEC_LEN).contains(&i) {
                assert_eq!(eval, z2[i]);
            } else if (VEC_LEN..TOT_LEN).contains(&i) {
                assert_eq!(eval, z1[i - VEC_LEN]);
            } else {
                assert_eq!(eval, Fr::zero());
            }
        }
    }
}
