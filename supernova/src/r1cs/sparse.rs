//! # Sparse Matrices
//!
//! This module defines a custom implementation of CSR/CSC sparse matrices.
//! Specifically, we implement sparse matrix / dense vector multiplication
//! to compute the `A z`, `B z`, and `C z` in Nova.

use ark_ff::PrimeField;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};

#[cfg(feature = "parallel")]
use rayon::{iter::ParallelIterator, slice::ParallelSlice};

use super::MatrixRef;

/// CSR format sparse matrix, We follow the names used by scipy.
/// Detailed explanation here: https://stackoverflow.com/questions/52299420/scipy-csr-matrix-understand-indptr
#[derive(Clone, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize)]
pub struct SparseMatrix<F: PrimeField> {
    /// all non-zero values in the matrix
    pub data: Vec<F>,
    /// column indices
    pub indices: Vec<usize>,
    /// row information
    pub indptr: Vec<usize>,
    /// number of columns
    pub cols: usize,
}

impl<F: PrimeField> SparseMatrix<F> {
    /// 0x0 empty matrix
    pub fn empty() -> Self {
        SparseMatrix {
            data: vec![],
            indices: vec![],
            indptr: vec![0],
            cols: 0,
        }
    }

    /// Construct from the COO representation;
    /// We assume that the rows are sorted during construction.
    pub fn new(matrix: MatrixRef<'_, F>, rows: usize, cols: usize) -> Self {
        let mut new_matrix = vec![vec![]; rows];
        let matrix_iter = matrix
            .iter()
            .enumerate()
            .flat_map(|(i, row)| row.iter().map(move |&(f, j)| (i, j, f)));
        for (row, col, val) in matrix_iter {
            new_matrix[row].push((col, val));
        }

        for row in new_matrix.iter() {
            assert!(row.windows(2).all(|w| w[0].0 < w[1].0));
        }

        let mut indptr = vec![0; rows + 1];
        for (i, row) in new_matrix.iter().enumerate() {
            indptr[i + 1] = indptr[i] + row.len();
        }

        let mut indices = vec![];
        let mut data = vec![];
        for row in new_matrix {
            let (idx, val): (Vec<usize>, Vec<F>) = row.into_iter().unzip();
            indices.extend(idx);
            data.extend(val);
        }

        SparseMatrix {
            data,
            indices,
            indptr,
            cols,
        }
    }

    /// Retrieves the data for row slice [i..j] from `ptrs`.
    /// We assume that `ptrs` is indexed from `indptrs` and do not check if the
    /// returned slice is actually a valid row.
    pub fn get_row_unchecked(&self, ptrs: &[usize; 2]) -> impl Iterator<Item = (&F, &usize)> {
        self.data[ptrs[0]..ptrs[1]]
            .iter()
            .zip(&self.indices[ptrs[0]..ptrs[1]])
    }

    /// Multiply by a dense vector;
    pub fn multiply_vec(&self, vector: &[F]) -> Vec<F> {
        assert_eq!(self.cols, vector.len());

        self.multiply_vec_unchecked(vector)
    }

    /// Multiply by a dense vector;
    /// This does not check that the shape of the matrix/vector are compatible.
    pub fn multiply_vec_unchecked(&self, vector: &[F]) -> Vec<F> {
        #[cfg(feature = "parallel")]
        let iter = self.indptr.par_windows(2);
        #[cfg(not(feature = "parallel"))]
        let iter = self.indptr.windows(2);

        iter.map(|ptrs| {
            self.get_row_unchecked(ptrs.try_into().unwrap())
                .map(|(val, col_idx)| *val * vector[*col_idx])
                .sum()
        })
        .collect()
    }

    /// number of non-zero entries
    pub fn len(&self) -> usize {
        *self.indptr.last().unwrap()
    }

    /// empty matrix
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// returns a custom iterator
    pub fn iter(&self) -> Iter<'_, F> {
        let mut row = 0;
        while self.indptr[row + 1] == 0 {
            row += 1;
        }
        Iter {
            matrix: self,
            row,
            i: 0,
            nnz: *self.indptr.last().unwrap(),
        }
    }
}

/// Iterator for sparse matrix
pub struct Iter<'a, F: PrimeField> {
    matrix: &'a SparseMatrix<F>,
    row: usize,
    i: usize,
    nnz: usize,
}

impl<'a, F: PrimeField> Iterator for Iter<'a, F> {
    type Item = (usize, usize, F);

    fn next(&mut self) -> Option<Self::Item> {
        // are we at the end?
        if self.i == self.nnz {
            return None;
        }

        // compute current item
        let curr_item = (
            self.row,
            self.matrix.indices[self.i],
            self.matrix.data[self.i],
        );

        // advance the iterator
        self.i += 1;
        // edge case at the end
        if self.i == self.nnz {
            return Some(curr_item);
        }
        // if `i` has moved to next row
        while self.i >= self.matrix.indptr[self.row + 1] {
            self.row += 1;
        }

        Some(curr_item)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    type Fr = ark_test_curves::bls12_381::Fr;

    #[test]
    fn test_matrix_creation() {
        let matrix_data = vec![
            vec![(Fr::from(2), 1)],
            vec![(Fr::from(3), 2)],
            vec![(Fr::from(4), 0)],
        ];
        let sparse_matrix = SparseMatrix::<Fr>::new(&matrix_data, 3, 3);

        assert_eq!(
            sparse_matrix.data,
            vec![Fr::from(2), Fr::from(3), Fr::from(4)]
        );
        assert_eq!(sparse_matrix.indices, vec![1, 2, 0]);
        assert_eq!(sparse_matrix.indptr, vec![0, 1, 2, 3]);
    }

    #[test]
    fn test_matrix_vector_multiplication() {
        let matrix_data = vec![
            vec![(Fr::from(2), 1), (Fr::from(7), 2)],
            vec![(Fr::from(3), 2)],
            vec![(Fr::from(4), 0)],
        ];
        let sparse_matrix = SparseMatrix::<Fr>::new(&matrix_data, 3, 3);
        let vector = vec![Fr::from(1), Fr::from(2), Fr::from(3)];

        let result = sparse_matrix.multiply_vec(&vector);

        assert_eq!(result, vec![Fr::from(25), Fr::from(9), Fr::from(4)]);
    }
}
