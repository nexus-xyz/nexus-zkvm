use ark_ec::{AdditiveGroup, CurveGroup};
use ark_ff::Field;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};

use ark_std::Zero;
use std::ops::Neg;

#[cfg(feature = "parallel")]
use rayon::iter::{
    IndexedParallelIterator, IntoParallelRefIterator, IntoParallelRefMutIterator, ParallelIterator,
};

use super::commitment::CommitmentScheme;

pub use super::sparse::{MatrixRef, SparseMatrix};

use super::r1cs::R1CSShape;

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

/// A type that holds the shape of the CCS matrices
#[derive(Debug, Clone, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize)]
pub struct CCSShape<G: CurveGroup> {
    /// `m` in the CCS/HyperNova papers.
    pub num_constraints: usize,
    /// Witness length.
    ///
    /// `m - l - 1` in the CCS/HyperNova papers.
    pub num_vars: usize,
    /// Length of the public input `X`. It is expected to have a leading
    /// `ScalarField::ONE` element, thus this field must be non-zero.
    ///
    /// `l + 1`, w.r.t. the CCS/HyperNova papers.
    pub num_io: usize,
    /// Number of matrices.
    ///
    /// `t` in the CCS/HyperNova papers.
    pub num_matrices: usize,
    /// Number of multisets.
    ///
    /// `q` in the CCS/HyperNova papers.
    pub num_multisets: usize,
    /// Max cardinality of the multisets.
    ///
    /// `d` in the CCS/HyperNova papers.
    pub max_cardinality: usize,
    /// Set of constraint matrices.
    pub Ms: Vec<SparseMatrix<G::ScalarField>>,
    /// Multisets of selector indices, each paired with a constant multiplier.
    pub cSs: Vec<(G::ScalarField, Vec<usize>)>,
}

impl<G: CurveGroup> CCSShape<G> {
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
        let Mzs: Vec<Vec<G::ScalarField>> = ark_std::cfg_iter!(&self.Ms)
            .map(|M| M.multiply_vec(&z))
            .collect();

        let mut acc = vec![G::ScalarField::ZERO; self.num_constraints];
        for (c, S) in &self.cSs {
            let mut circle_product = vec![*c; self.num_constraints];

            for idx in S {
                ark_std::cfg_iter_mut!(circle_product)
                    .enumerate()
                    .for_each(|(j, x)| *x *= Mzs[*idx][j]);
            }

            ark_std::cfg_iter_mut!(acc)
                .enumerate()
                .for_each(|(i, s)| *s += circle_product[i]);
        }

        if ark_std::cfg_iter!(acc).any(|s| !s.is_zero()) {
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
            num_matrices: 3,
            num_multisets: 2,
            max_cardinality: 2,
            Ms: vec![shape.A, shape.B, shape.C],
            cSs: vec![
                (G::ScalarField::ONE, vec![0, 1]),
                (G::ScalarField::ONE.neg(), vec![2]),
            ],
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

impl<G: CurveGroup, C: CommitmentScheme<G>> PartialEq for CCSInstance<G, C> {
    fn eq(&self, other: &Self) -> bool {
        self.commitment_W == other.commitment_W && self.X == other.X
    }
}

impl<G: CurveGroup, C: CommitmentScheme<G>> Eq for CCSInstance<G, C> where C::Commitment: Eq {}

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

    use ark_test_curves::bls12_381::G1Projective as G;

    use crate::r1cs::tests::{to_field_elements, to_field_sparse, A, B, C};

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
        let r1cs_shape: R1CSShape<G> =
            R1CSShape::<G>::new(NUM_CONSTRAINTS, NUM_WITNESS, NUM_PUBLIC, &a, &b, &c).unwrap();

        let ccs_shape = CCSShape::from(r1cs_shape);

        let X = to_field_elements::<G>(&[1, 35]);
        let W = to_field_elements::<G>(&[3, 9, 27, 30]);
        let commitment_W = PedersenCommitment::<G>::commit(&pp, &W);

        let instance = CCSInstance::<G, PedersenCommitment<G>>::new(&ccs_shape, &commitment_W, &X)?;
        let witness = CCSWitness::<G>::new(&ccs_shape, &W)?;

        ccs_shape.is_satisfied(&instance, &witness, &pp)?;

        // Change commitment.
        let invalid_commitment = commitment_W.double();
        let instance =
            CCSInstance::<G, PedersenCommitment<G>>::new(&ccs_shape, &invalid_commitment, &X)?;
        assert_eq!(
            ccs_shape.is_satisfied(&instance, &witness, &pp),
            Err(Error::NotSatisfied)
        );

        // Provide invalid witness.
        let invalid_W = to_field_elements::<G>(&[4, 9, 27, 30]);
        let commitment_invalid_W = PedersenCommitment::<G>::commit(&pp, &W);
        let instance =
            CCSInstance::<G, PedersenCommitment<G>>::new(&ccs_shape, &commitment_invalid_W, &X)?;
        let invalid_witness = CCSWitness::<G>::new(&ccs_shape, &invalid_W)?;
        assert_eq!(
            ccs_shape.is_satisfied(&instance, &invalid_witness, &pp),
            Err(Error::NotSatisfied)
        );

        // Provide invalid public input.
        let invalid_X = to_field_elements::<G>(&[1, 36]);
        let instance =
            CCSInstance::<G, PedersenCommitment<G>>::new(&ccs_shape, &commitment_W, &invalid_X)?;
        assert_eq!(
            ccs_shape.is_satisfied(&instance, &witness, &pp),
            Err(Error::NotSatisfied)
        );
        Ok(())
    }
}
