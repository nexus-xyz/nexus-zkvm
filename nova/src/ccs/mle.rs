//! Helper code for multilinear extensions

use ark_ff::PrimeField;
use ark_spartan::dense_mlpoly::DensePolynomial as DenseMultilinearExtension;
use ark_spartan::sparse_mlpoly::{
    SparsePolyEntry as MultilinearEvaluation, SparsePolynomial as SparseMultilinearExtension,
};

use super::super::sparse::SparseMatrix;

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

    let s = 1 << s1;

    let evaluations: Vec<MultilinearEvaluation<F>> = M
        .iter()
        .map(|(i, j, value)| MultilinearEvaluation::new(j * s + i, value))
        .collect();

    SparseMultilinearExtension::<F>::new((s1 + s2) as usize, evaluations)
}

/// Converts a vector into a (dense) mle.
pub fn vec_to_mle<F: PrimeField>(z: &[F]) -> DenseMultilinearExtension<F> {
    let n = z.len();
    assert!(n > 0);

    let mut z = z.to_owned();
    z.resize(n.next_power_of_two(), F::zero());

    DenseMultilinearExtension::<F>::new(z)
}

#[cfg(test)]
mod tests {
    use super::*;

    use ark_std::{UniformRand, Zero};
    use ark_test_curves::bls12_381::{Fr, G1Projective as G};

    use crate::r1cs::tests::to_field_sparse;
    use crate::utils::iter_bits_le;

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

        let m = NUM_ROWS.next_power_of_two();
        let n = NUM_COLS.next_power_of_two();

        for (i, row) in M.iter().enumerate().take(m) {
            for (j, entry) in row.iter().enumerate().take(n) {
                let col_mask = (1 << 2) * j; // shift column bits
                let _i = i | col_mask;

                let i_bytes = _i.to_le_bytes();
                let mut i_bits: Vec<Fr> = iter_bits_le(i_bytes.as_slice())
                    .map(Fr::from)
                    .take(NUM_VARS)
                    .collect();

                i_bits.reverse();
                let eval = mle.evaluate(&i_bits);

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
            let mut i_bits: Vec<Fr> = iter_bits_le(i_bytes.as_slice())
                .map(Fr::from)
                .take(NUM_VARS)
                .collect::<Vec<Fr>>();

            i_bits.reverse();
            let eval = mle.evaluate::<G>(&i_bits);

            let expected = if i < LEN { *entry } else { Fr::zero() };
            assert_eq!(eval, expected);
        }
    }
}
