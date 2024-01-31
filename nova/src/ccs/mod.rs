use ark_std::fmt;

use ark_crypto_primitives::sponge::Absorb;
use ark_ec::{AdditiveGroup, CurveGroup};
use ark_ff::{Field, PrimeField};
use ark_relations::r1cs::ConstraintSystemRef;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};

use ark_std::Zero;
use std::ops::Neg;

#[cfg(feature = "parallel")]
use rayon::iter::{IntoParallelIterator, ParallelIterator};

use super::{absorb::AbsorbNonNative, commitment::CommitmentScheme};

pub use super::sparse::{MatrixRef, SparseMatrix};

mod vector_ops;
use vector_ops::{elem_add, elem_mul, scalar_mul};

use super::r1cs::R1CSShape;
pub use ark_relations::r1cs::Matrix;

pub type VMatrixRef<'a, F> = &'a Vec<Vec<(F, usize)>>;

#[derive(Debug, Copy, Clone, PartialEq)]
pub enum Error {
    ConstraintNumberMismatch,
    InputLengthMismatch,
    InvalidWitnessLength,
    InvalidInputLength,
    InvalidConversion,
    InvalidMultiset,
    MultisetCardinalityMismatch,
    NotSatisfied,
}

/// A trait capturing that the type encodes a constraint matrix
pub trait ConstraintMatrix<F: PrimeField> {
    fn validate(&self, num_constraints: usize, num_vars: usize, num_io: usize)
        -> Result<(), Error>;
    fn sparsify(&self, rows: usize, columns: usize) -> SparseMatrix<F>;
}

/// A (macro'd) implementation of the ConstraintMatrix trait for explicitly specified matricies
macro_rules! impl_Explicit_Constraint_Matrix {
    (for $($t:ty),+) => {
        $(impl<F: PrimeField> ConstraintMatrix<F> for $t {
            fn validate(&self, num_constraints: usize, num_vars: usize, num_io: usize) -> Result<(), Error> {
                for (i, row) in self.iter().enumerate() {
                    for (_value, j) in row {
                        if i >= num_constraints {
                            return Err(Error::ConstraintNumberMismatch);
                        }
                        if *j >= num_io + num_vars {
                            return Err(Error::InputLengthMismatch);
                        }
                    }
                }

                Ok(())
            }

            fn sparsify(&self, rows: usize, columns: usize) -> SparseMatrix<F> {
                SparseMatrix::new(self, rows, columns)
            }
        })*
    }
}
impl_Explicit_Constraint_Matrix!(for MatrixRef<'_, F>, VMatrixRef<'_, F>);

/// An implementation of the ConstraintMatrix trait for sparse matricies
impl<F: PrimeField> ConstraintMatrix<F> for SparseMatrix<F> {
    fn validate(
        &self,
        _num_constraints: usize,
        _num_vars: usize,
        _num_io: usize,
    ) -> Result<(), Error> {
        Ok(())
    }

    fn sparsify(&self, _rows: usize, _columns: usize) -> SparseMatrix<F> {
        self.clone()
    }
}

/// A type that holds the shape of the CCS matrices
#[derive(Debug, Clone, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize)]
pub struct CCSShape<G: CurveGroup> {
    /// `m` in the Nova paper.
    pub num_constraints: usize,
    /// Witness length.
    ///
    /// `m - l - 1` in the Nova paper.
    pub num_vars: usize,
    /// Length of the public input `X`. It is expected to have a leading
    /// `ScalarField::ONE` element, thus this field must be non-zero.
    ///
    /// `l + 1`, w.r.t. the Nova paper.
    pub num_io: usize,
    /// Number of matricies.
    ///
    /// `t` in the CCS paper.
    pub num_matricies: usize,
    /// Number of multisets
    ///
    /// `q` in the CCS paper.
    pub num_multisets: usize,
    /// Max cardinality of the multisets
    ///
    /// `d` in the CCS paper.
    pub max_cardinality: usize,
    pub Ms: Vec<SparseMatrix<G::ScalarField>>,
    pub Ss: Vec<Vec<usize>>,
    pub cs: Vec<G::ScalarField>,
}

impl<G: CurveGroup> fmt::Display for CCSShape<G> {
    #[rustfmt::skip]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let Ms = self.Ms.iter().map(|x| format!("[_, {}]", x.len())).collect::<Vec<_>>().join(", ");
        let Ss = self.Ss.iter().map(|x| format!("[_, {}]", x.len())).collect::<Vec<_>>().join(", ");
        let cs = self.cs.iter().map(|x| format!("{}", x)).collect::<Vec<_>>().join(", ");

        write!(f, "CCSShape {{ num_constraints: {}, num_vars: {}, num_io: {}, num_matricies: {}, num_multisets: {}, max_cardinality: {}, Ms: {}, Ss: {}, cs: {} }}",
               self.num_constraints,
               self.num_vars,
               self.num_io,
               self.num_matricies,
               self.num_multisets,
               self.max_cardinality,
               Ms,
               Ss,
               cs,
        )
    }
}

impl<G: CurveGroup> CCSShape<G> {
    /// Create an object of type `CCSShape` from the specified matricies and constant data structures
    pub fn new<MT: ConstraintMatrix<G::ScalarField>>(
        num_constraints: usize,
        num_vars: usize,
        num_io: usize,
        num_matricies: usize,
        num_multisets: usize,
        max_cardinality: usize,
        Ms: Vec<MT>,
        Ss: Vec<Vec<usize>>,
        cs: Vec<G::ScalarField>,
    ) -> Result<CCSShape<G>, Error> {
        if num_io == 0 {
            return Err(Error::InvalidInputLength);
        }

        Ms.iter()
            .try_for_each(|M| M.validate(num_constraints, num_vars, num_io))?;

        assert_eq!(Ms.len(), num_matricies);
        assert_eq!(Ss.len(), num_multisets);
        assert_eq!(cs.len(), num_multisets);

        for S in Ss.iter() {
            if S.len() > max_cardinality {
                return Err(Error::MultisetCardinalityMismatch);
            }

            S.iter().try_for_each(|idx| {
                if idx >= &num_matricies {
                    Err(Error::InvalidMultiset)
                } else {
                    Ok(())
                }
            })?;
        }

        let rows = num_constraints;
        let columns = num_io + num_vars;

        let sMs = Ms
            .iter()
            .map(|M| M.sparsify(rows, columns))
            .collect::<Vec<SparseMatrix<G::ScalarField>>>();

        Ok(Self {
            num_constraints,
            num_io,
            num_vars,
            num_matricies,
            num_multisets,
            max_cardinality,
            Ms: sMs,
            Ss,
            cs,
        })
    }

    /// Checks if the CCS instance together with the witness `W` satisfies the CCS constraints determined by `shape`.
    pub fn is_satisfied<C: CommitmentScheme<G>>(
        &self,
        U: &CCSInstance<G, C>,
        W: &CCSWitness<G>,
        pp: &C::PP,
    ) -> Result<(), Error> {
        assert_eq!(W.W.len(), self.num_vars);
        assert_eq!(U.X.len(), self.num_io);

        let z = [U.X.as_slice(), W.W.as_slice()].concat();

        let mut acc = vec![G::ScalarField::ZERO; self.num_constraints];

        for i in 0..self.num_multisets {
            let Ms_i: Vec<&SparseMatrix<G::ScalarField>> =
                self.Ss[i].iter().map(|j| &self.Ms[*j]).collect();

            let hadamard_i: Vec<G::ScalarField> = Ms_i.iter().fold(
                vec![G::ScalarField::ONE; self.num_constraints],
                |acc, M_j| elem_mul(&acc, &M_j.multiply_vec(&z)),
            );

            let res_i: Vec<G::ScalarField> = scalar_mul(&hadamard_i, &self.cs[i]);

            acc = elem_add(&acc, &res_i);
        }

        if ark_std::cfg_into_iter!(0..self.num_constraints).any(|idx| !acc[idx].is_zero()) {
            return Err(Error::NotSatisfied);
        }

        if U.commitment_W != C::commit(pp, &W.W) {
            return Err(Error::NotSatisfied);
        }

        Ok(())
    }
}

/// Create an object of type `CCSShape` from the specified R1CS shape
impl<G: CurveGroup> From<R1CSShape<G>> for CCSShape<G> {
    fn from(shape: R1CSShape<G>) -> Self {
        Self {
            num_constraints: shape.num_constraints,
            num_io: shape.num_io,
            num_vars: shape.num_vars,
            num_matricies: 3,
            num_multisets: 2,
            max_cardinality: 2,
            Ms: vec![shape.A.clone(), shape.B.clone(), shape.C.clone()],
            Ss: vec![vec![0, 1], vec![2]],
            cs: vec![G::ScalarField::ONE, G::ScalarField::ONE.neg()],
        }
    }
}

impl<G: CurveGroup> From<ConstraintSystemRef<G::ScalarField>> for CCSShape<G> {
    fn from(cs: ConstraintSystemRef<G::ScalarField>) -> Self {
        assert!(cs.should_construct_matrices());
        let matrices = cs.to_matrices().unwrap();

        let num_constraints = cs.num_constraints();
        let num_vars = cs.num_witness_variables();
        let num_io = cs.num_instance_variables();

        let rows = num_constraints;
        let columns = num_io + num_vars;
        Self {
            num_constraints,
            num_io,
            num_vars,
            num_matricies: 3,
            num_multisets: 2,
            max_cardinality: 2,
            Ms: vec![
                SparseMatrix::new(&matrices.a, rows, columns),
                SparseMatrix::new(&matrices.b, rows, columns),
                SparseMatrix::new(&matrices.c, rows, columns),
            ],
            Ss: vec![vec![0, 1], vec![2]],
            cs: vec![G::ScalarField::ONE, G::ScalarField::ONE.neg()],
        }
    }
}

/// A type that holds a witness for a given CCS instance.
#[derive(Clone, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize)]
pub struct CCSWitness<G: CurveGroup> {
    pub W: Vec<G::ScalarField>,
}

/// A type that holds an CCS instance.
#[derive(CanonicalSerialize, CanonicalDeserialize)]
pub struct CCSInstance<G: CurveGroup, C: CommitmentScheme<G>> {
    /// Commitment to witness.
    pub commitment_W: C::Commitment,
    /// X is assumed to start with a `ScalarField::ONE`.
    pub X: Vec<G::ScalarField>,
}

impl<G: CurveGroup, C: CommitmentScheme<G>> Clone for CCSInstance<G, C> {
    fn clone(&self) -> Self {
        Self {
            commitment_W: self.commitment_W,
            X: self.X.clone(),
        }
    }
}

impl<G: CurveGroup, C: CommitmentScheme<G>> fmt::Debug for CCSInstance<G, C>
where
    C::Commitment: fmt::Debug,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CCSInstance")
            .field("commitment_W", &self.commitment_W)
            .field("X", &self.X)
            .finish()
    }
}

impl<G: CurveGroup, C: CommitmentScheme<G>> PartialEq for CCSInstance<G, C> {
    fn eq(&self, other: &Self) -> bool {
        self.commitment_W == other.commitment_W && self.X == other.X
    }
}

impl<G: CurveGroup, C: CommitmentScheme<G>> Eq for CCSInstance<G, C> where C::Commitment: Eq {}

impl<G, C> Absorb for CCSInstance<G, C>
where
    G: CurveGroup + AbsorbNonNative<G::ScalarField>,
    G::ScalarField: Absorb,
    C: CommitmentScheme<G>,
    C::Commitment: Into<G>,
{
    fn to_sponge_bytes(&self, _: &mut Vec<u8>) {
        unreachable!()
    }

    fn to_sponge_field_elements<F: PrimeField>(&self, dest: &mut Vec<F>) {
        <G as AbsorbNonNative<G::ScalarField>>::to_sponge_field_elements(
            &self.commitment_W.into(),
            dest,
        );

        (&self.X[1..]).to_sponge_field_elements(dest);
    }
}

impl<G: CurveGroup> CCSWitness<G> {
    /// A method to create a witness object using a vector of scalars.
    pub fn new(shape: &CCSShape<G>, W: &[G::ScalarField]) -> Result<Self, Error> {
        if shape.num_vars != W.len() {
            Err(Error::InvalidWitnessLength)
        } else {
            Ok(Self { W: W.to_owned() })
        }
    }

    pub fn zero(shape: &CCSShape<G>) -> Self {
        Self {
            W: vec![G::ScalarField::ZERO; shape.num_vars],
        }
    }

    /// Commits to the witness using the supplied generators
    pub fn commit<C: CommitmentScheme<G>>(&self, pp: &C::PP) -> C::Commitment {
        C::commit(pp, &self.W)
    }
}

impl<G: CurveGroup, C: CommitmentScheme<G>> CCSInstance<G, C> {
    /// A method to create an instance object using constituent elements.
    pub fn new(
        shape: &CCSShape<G>,
        commitment_W: &C::Commitment,
        X: &[G::ScalarField],
    ) -> Result<Self, Error> {
        if X.is_empty() {
            return Err(Error::InvalidInputLength);
        }
        if shape.num_io != X.len() {
            Err(Error::InvalidInputLength)
        } else {
            Ok(Self {
                commitment_W: *commitment_W,
                X: X.to_owned(),
            })
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(non_upper_case_globals)]
    #![allow(clippy::needless_range_loop)]

    use super::*;
    use crate::pedersen::PedersenCommitment;

    use ark_relations::r1cs::Matrix;
    use ark_test_curves::bls12_381::G1Projective as G;

    fn to_field_sparse<G: CurveGroup>(matrix: &[&[u64]]) -> Matrix<G::ScalarField> {
        let mut coo_matrix = Matrix::new();

        for row in matrix {
            let mut sparse_row = Vec::new();
            for (j, &f) in row.iter().enumerate() {
                if f == 0 {
                    continue;
                }
                sparse_row.push((G::ScalarField::from(f), j));
            }
            coo_matrix.push(sparse_row);
        }

        coo_matrix
    }

    fn to_field_elements<G: CurveGroup>(x: &[i64]) -> Vec<G::ScalarField> {
        x.iter().copied().map(G::ScalarField::from).collect()
    }

    #[test]
    #[rustfmt::skip]
    fn invalid_input() {
        let a = {
            let a: &[&[u64]] = &[
                &[1, 2, 3],
                &[3, 4, 5],
                &[6, 7, 8],
            ];
            to_field_sparse::<G>(a)
        };

        assert_eq!(
            CCSShape::<G>::new(2, 2, 2, 3, 2, 2, vec![&a, &a, &a], vec![vec![0, 1], vec![2]], to_field_elements::<G>(&[1, -1])),
            Err(Error::ConstraintNumberMismatch)
        );
        assert_eq!(
            CCSShape::<G>::new(3, 0, 1, 3, 2, 2, vec![&a, &a, &a], vec![vec![0, 1], vec![2]], to_field_elements::<G>(&[1, -1])),
            Err(Error::InputLengthMismatch)
        );
        assert_eq!(
            CCSShape::<G>::new(3, 1, 2, 3, 1, 2, vec![&a, &a, &a], vec![vec![0, 1, 2]], to_field_elements::<G>(&[1])),
            Err(Error::MultisetCardinalityMismatch)
        );
        assert_eq!(
            CCSShape::<G>::new(3, 1, 2, 3, 2, 2, vec![&a, &a, &a], vec![vec![3, 1], vec![2]], to_field_elements::<G>(&[1, -1])),
            Err(Error::InvalidMultiset)
        );
    }

    #[test]
    fn zero_instance_is_satisfied() -> Result<(), Error> {
        #[rustfmt::skip]
        let a = {
            let a: &[&[u64]] = &[
                &[1, 2, 3],
                &[3, 4, 5],
                &[6, 7, 8],
            ];
            to_field_sparse::<G>(a)
        };

        const NUM_CONSTRAINTS: usize = 3;
        const NUM_WITNESS: usize = 1;
        const NUM_PUBLIC: usize = 2;

        let pp = PedersenCommitment::<G>::setup(NUM_WITNESS, &());
        let shape = CCSShape::<G>::new(
            NUM_CONSTRAINTS,
            NUM_WITNESS,
            NUM_PUBLIC,
            3,
            2,
            2,
            vec![&a, &a, &a],
            vec![vec![0, 1], vec![2]],
            to_field_elements::<G>(&[1, -1]),
        )?;

        let X = to_field_elements::<G>(&[0, 0]);
        let W = to_field_elements::<G>(&[0]);
        let commitment_W = PedersenCommitment::<G>::commit(&pp, &W);

        let instance = CCSInstance::<G, PedersenCommitment<G>>::new(&shape, &commitment_W, &X)?;
        let witness = CCSWitness::<G>::new(&shape, &W)?;

        shape.is_satisfied(&instance, &witness, &pp)?;
        Ok(())
    }

    #[test]
    fn shape_conversion_from_r1cs() -> Result<(), Error> {
        #[rustfmt::skip]
        let a = {
            let a: &[&[u64]] = &[
                &[1, 2, 3],
                &[3, 4, 5],
                &[6, 7, 8],
            ];
            to_field_sparse::<G>(a)
        };

        const NUM_CONSTRAINTS: usize = 3;
        const NUM_WITNESS: usize = 1;
        const NUM_PUBLIC: usize = 2;

        let pp = PedersenCommitment::<G>::setup(NUM_WITNESS, &());
        let r1cs_shape: R1CSShape<G> =
            R1CSShape::<G>::new(NUM_CONSTRAINTS, NUM_WITNESS, NUM_PUBLIC, &a, &a, &a).unwrap();

        let ccs_shape = CCSShape::from(r1cs_shape);

        let X = to_field_elements::<G>(&[0, 0]);
        let W = to_field_elements::<G>(&[0]);
        let commitment_W = PedersenCommitment::<G>::commit(&pp, &W);

        let instance = CCSInstance::<G, PedersenCommitment<G>>::new(&ccs_shape, &commitment_W, &X)?;
        let witness = CCSWitness::<G>::new(&ccs_shape, &W)?;

        ccs_shape.is_satisfied(&instance, &witness, &pp)?;

        Ok(())
    }

    // Example from Vitalik's blog for equation x**3 + x + 5 == 35.
    //
    // Note that our implementation shuffles columns such that witness comes first.

    const A: &[&[u64]] = &[
        &[0, 0, 1, 0, 0, 0],
        &[0, 0, 0, 1, 0, 0],
        &[0, 0, 1, 0, 1, 0],
        &[5, 0, 0, 0, 0, 1],
    ];
    const B: &[&[u64]] = &[
        &[0, 0, 1, 0, 0, 0],
        &[0, 0, 1, 0, 0, 0],
        &[1, 0, 0, 0, 0, 0],
        &[1, 0, 0, 0, 0, 0],
    ];
    const C: &[&[u64]] = &[
        &[0, 0, 0, 1, 0, 0],
        &[0, 0, 0, 0, 1, 0],
        &[0, 0, 0, 0, 0, 1],
        &[0, 1, 0, 0, 0, 0],
    ];

    #[test]
    fn is_satisfied() -> Result<(), Error> {
        let (a, b, c) = {
            (
                to_field_sparse::<G>(A),
                to_field_sparse::<G>(B),
                to_field_sparse::<G>(C),
            )
        };

        const NUM_CONSTRAINTS: usize = 4;
        const NUM_WITNESS: usize = 4;
        const NUM_PUBLIC: usize = 2;

        let pp = PedersenCommitment::<G>::setup(NUM_WITNESS, &());
        let shape = CCSShape::<G>::new(
            NUM_CONSTRAINTS,
            NUM_WITNESS,
            NUM_PUBLIC,
            3,
            2,
            2,
            vec![&a, &b, &c],
            vec![vec![0, 1], vec![2]],
            to_field_elements::<G>(&[1, -1]),
        )?;
        let X = to_field_elements::<G>(&[1, 35]);
        let W = to_field_elements::<G>(&[3, 9, 27, 30]);
        let commitment_W = PedersenCommitment::<G>::commit(&pp, &W);

        let instance = CCSInstance::<G, PedersenCommitment<G>>::new(&shape, &commitment_W, &X)?;
        let witness = CCSWitness::<G>::new(&shape, &W)?;

        shape.is_satisfied(&instance, &witness, &pp)?;

        // Change commitment.
        let invalid_commitment = commitment_W.double();
        let instance =
            CCSInstance::<G, PedersenCommitment<G>>::new(&shape, &invalid_commitment, &X)?;
        assert_eq!(
            shape.is_satisfied(&instance, &witness, &pp),
            Err(Error::NotSatisfied)
        );

        // Provide invalid witness.
        let invalid_W = to_field_elements::<G>(&[4, 9, 27, 30]);
        let commitment_invalid_W = PedersenCommitment::<G>::commit(&pp, &W);
        let instance =
            CCSInstance::<G, PedersenCommitment<G>>::new(&shape, &commitment_invalid_W, &X)?;
        let invalid_witness = CCSWitness::<G>::new(&shape, &invalid_W)?;
        assert_eq!(
            shape.is_satisfied(&instance, &invalid_witness, &pp),
            Err(Error::NotSatisfied)
        );

        // Provide invalid public input.
        let invalid_X = to_field_elements::<G>(&[1, 36]);
        let instance =
            CCSInstance::<G, PedersenCommitment<G>>::new(&shape, &commitment_W, &invalid_X)?;
        assert_eq!(
            shape.is_satisfied(&instance, &witness, &pp),
            Err(Error::NotSatisfied)
        );
        Ok(())
    }
}
