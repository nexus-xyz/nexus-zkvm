use ark_ec::{AdditiveGroup, CurveGroup};
use ark_ff::Field;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_spartan::{
    dense_mlpoly::DensePolynomial as DenseMultilinearExtension,
    polycommitments::PolyCommitmentScheme,
    sparse_mlpoly::SparsePolynomial as SparseMultilinearExtension,
};

use std::ops::Neg;

#[cfg(feature = "parallel")]
use rayon::iter::{IntoParallelIterator, IntoParallelRefIterator, ParallelIterator};

use super::super::r1cs::R1CSShape;
pub use super::super::sparse::{MatrixRef, SparseMatrix};
use super::mle::{compose_mle_input, matrix_to_mle, vec_to_mle};

#[derive(Debug, Copy, Clone, PartialEq)]
pub enum Error {
    InvalidWitnessLength,
    InvalidInputLength,
    InvalidEvaluationPoint,
    InvalidTargets,
    NotSatisfied,
}

pub struct LCCSShape<G: CurveGroup> {
    /// `m` in the CCS/HyperNova papers.
    pub num_constraints: usize,
    /// Witness length.
    ///
    /// `m - l - 1` in the CCS/HyperNova papers.
    pub num_vars: usize,
    /// Length of the public input `X`. It is expected to have a leading
    /// `ScalarField` element (`u`), thus this field must be non-zero.
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
    pub Ms: Vec<SparseMultilinearExtension<G::ScalarField>>,
    /// Multisets of selector indices, each paired with a constant multiplier.
    pub cSs: Vec<(G::ScalarField, Vec<usize>)>,
}

impl<G: CurveGroup> LCCSShape<G> {
    pub fn is_satisfied<C: PolyCommitmentScheme<G>>(
        &self,
        U: &LCCSInstance<G, C>,
        W: &LCCSWitness<G>,
        ck: &C::PolyCommitmentKey,
    ) -> Result<(), Error> {
        assert_eq!(U.X.len(), self.num_io);
        let X = vec_to_mle(U.X.as_slice());
        let z = DenseMultilinearExtension::<G::ScalarField>::merge(&[X, W.W.to_owned()]);

        let n = (self.num_io + self.num_vars).next_power_of_two();
        let s = (n - 1).checked_ilog2().unwrap_or(0) + 1;

        let Mzs: Vec<G::ScalarField> = ark_std::cfg_iter!(&self.Ms)
            .map(|M| {
                (0..n)
                    .map(|y| {
                        let ry = compose_mle_input(U.rs.as_slice(), y, s as usize);
                        M.evaluate(ry.as_slice()) * z.evaluate::<G>(&ry[U.rs.len()..])
                    })
                    .sum()
            })
            .collect();

        if ark_std::cfg_into_iter!(0..self.num_matrices).any(|idx| Mzs[idx] != U.vs[idx]) {
            return Err(Error::NotSatisfied);
        }

        if U.commitment_W != C::commit(&W.W, ck) {
            return Err(Error::NotSatisfied);
        }

        Ok(())
    }
}

/// Create an object of type `LCCSShape` from the specified R1CS shape
impl<G: CurveGroup> From<R1CSShape<G>> for LCCSShape<G> {
    fn from(shape: R1CSShape<G>) -> Self {
        let rows = shape.num_constraints;
        let columns = shape.num_io + shape.num_vars;

        Self {
            num_constraints: shape.num_constraints,
            num_io: shape.num_io,
            num_vars: shape.num_vars,
            num_matrices: 3,
            num_multisets: 2,
            max_cardinality: 2,
            Ms: vec![
                matrix_to_mle(rows, columns, &shape.A),
                matrix_to_mle(rows, columns, &shape.B),
                matrix_to_mle(rows, columns, &shape.C),
            ],
            cSs: vec![
                (G::ScalarField::ONE, vec![0, 1]),
                (G::ScalarField::ONE.neg(), vec![2]),
            ],
        }
    }
}

/// A type that holds a witness for a given LCCS instance.
#[derive(Clone, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize)]
pub struct LCCSWitness<G: CurveGroup> {
    pub W: DenseMultilinearExtension<G::ScalarField>,
}

/// A type that holds an LCCS instance.
#[derive(CanonicalSerialize, CanonicalDeserialize)]
pub struct LCCSInstance<G: CurveGroup, C: PolyCommitmentScheme<G>> {
    /// Commitment to MLE of witness.
    ///
    /// C in HyperNova/CCS papers.
    pub commitment_W: C::Commitment,
    /// X is assumed to start with a `ScalarField` field element `u`.
    pub X: Vec<G::ScalarField>,
    /// (Random) evaluation point
    pub rs: Vec<G::ScalarField>,
    /// Evaluation targets
    pub vs: Vec<G::ScalarField>,
}

impl<G: CurveGroup, C: PolyCommitmentScheme<G>> Clone for LCCSInstance<G, C> {
    fn clone(&self) -> Self {
        Self {
            commitment_W: self.commitment_W.clone(),
            X: self.X.clone(),
            rs: self.rs.clone(),
            vs: self.vs.clone(),
        }
    }
}

impl<G: CurveGroup, C: PolyCommitmentScheme<G>> PartialEq for LCCSInstance<G, C> {
    fn eq(&self, other: &Self) -> bool {
        self.commitment_W == other.commitment_W && self.X == other.X
    }
}

impl<G: CurveGroup, C: PolyCommitmentScheme<G>> Eq for LCCSInstance<G, C> {}

impl<G: CurveGroup> LCCSWitness<G> {
    /// A method to create a witness object using a vector of scalars.
    pub fn new(shape: &LCCSShape<G>, W: &[G::ScalarField]) -> Result<Self, Error> {
        if shape.num_vars != W.len() {
            Err(Error::InvalidWitnessLength)
        } else {
            Ok(Self { W: vec_to_mle(W) })
        }
    }

    pub fn zero(shape: &LCCSShape<G>) -> Self {
        Self {
            W: vec_to_mle(vec![G::ScalarField::ZERO; shape.num_vars].as_slice()),
        }
    }

    /// Commits to the witness using the supplied key
    pub fn commit<C: PolyCommitmentScheme<G>>(&self, ck: &C::PolyCommitmentKey) -> C::Commitment {
        C::commit(&self.W, ck)
    }
}

impl<G: CurveGroup, C: PolyCommitmentScheme<G>> LCCSInstance<G, C> {
    /// A method to create an instance object using constituent elements.
    pub fn new(
        shape: &LCCSShape<G>,
        commitment_W: &C::Commitment,
        X: &[G::ScalarField],
        rs: &[G::ScalarField],
        vs: &[G::ScalarField],
    ) -> Result<Self, Error> {
        if X.is_empty() || shape.num_io != X.len() {
            Err(Error::InvalidInputLength)
        } else if ((shape.num_constraints - 1).checked_ilog2().unwrap_or(0) + 1) != rs.len() as u32
        {
            Err(Error::InvalidEvaluationPoint)
        } else if shape.num_matrices != vs.len() {
            Err(Error::InvalidTargets)
        } else {
            Ok(Self {
                commitment_W: commitment_W.clone(),
                X: X.to_owned(),
                rs: rs.to_owned(),
                vs: vs.to_owned(),
            })
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(non_upper_case_globals)]
    #![allow(clippy::needless_range_loop)]

    use super::*;

    use ark_spartan::polycommitments::zeromorph::Zeromorph;
    use ark_spartan::polycommitments::PCSKeys;
    use ark_std::{test_rng, UniformRand};
    use ark_test_curves::bls12_381::{Bls12_381 as E, Fr, G1Projective as G};

    use crate::r1cs::tests::{to_field_elements, to_field_sparse, A, B, C};

    type Z = Zeromorph<E>;

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

        let r1cs_shape: R1CSShape<G> =
            R1CSShape::<G>::new(NUM_CONSTRAINTS, NUM_WITNESS, NUM_PUBLIC, &a, &a, &a).unwrap();

        let lccs_shape = LCCSShape::from(r1cs_shape);

        let mut rng = test_rng();
        let SRS = Z::setup(4, b"test", &mut rng).unwrap();
        let PCSKeys { ck, .. } = Z::trim(&SRS, 4);

        let X = to_field_elements::<G>(&[0, 0]);
        let W = to_field_elements::<G>(&[0]);
        let witness = LCCSWitness::<G>::new(&lccs_shape, &W)?;

        let commitment_W = witness.commit::<Z>(&ck);

        let s1 = (NUM_CONSTRAINTS - 1).checked_ilog2().unwrap_or(0) + 1;
        let rs: Vec<Fr> = (0..s1).map(|_| Fr::rand(&mut rng)).collect();

        let z = DenseMultilinearExtension::<Fr>::merge(&[vec_to_mle(&X), vec_to_mle(&W)]);

        let n = (NUM_WITNESS + NUM_PUBLIC).next_power_of_two();
        let s2 = (n - 1).checked_ilog2().unwrap_or(0) + 1;

        let vs: Vec<Fr> = ark_std::cfg_iter!(&lccs_shape.Ms)
            .map(|M| {
                (0..n)
                    .map(|idx| {
                        let ry = compose_mle_input(rs.as_slice(), idx, s2 as usize);
                        M.evaluate(ry.as_slice()) * z.evaluate::<G>(&ry[rs.len()..])
                    })
                    .sum()
            })
            .collect();

        let instance = LCCSInstance::<G, Z>::new(&lccs_shape, &commitment_W, &X, &rs, &vs)?;

        lccs_shape.is_satisfied::<Z>(&instance, &witness, &ck)?;

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

        let r1cs_shape: R1CSShape<G> =
            R1CSShape::<G>::new(NUM_CONSTRAINTS, NUM_WITNESS, NUM_PUBLIC, &a, &b, &c).unwrap();

        let lccs_shape = LCCSShape::from(r1cs_shape);

        let mut rng = test_rng();
        let SRS = Z::setup(8, b"test", &mut rng).unwrap();
        let PCSKeys { ck, .. } = Z::trim(&SRS, 8);

        let X = to_field_elements::<G>(&[1, 35]);
        let W = to_field_elements::<G>(&[3, 9, 27, 30]);
        let witness = LCCSWitness::<G>::new(&lccs_shape, &W)?;

        let commitment_W = witness.commit::<Z>(&ck);

        let s1 = (NUM_CONSTRAINTS - 1).checked_ilog2().unwrap_or(0) + 1;
        let rs: Vec<Fr> = (0..s1).map(|_| Fr::rand(&mut rng)).collect();

        let z = DenseMultilinearExtension::<Fr>::merge(&[vec_to_mle(&X), vec_to_mle(&W)]);

        let n = (NUM_WITNESS + NUM_PUBLIC).next_power_of_two();
        let s2 = (n - 1).checked_ilog2().unwrap_or(0) + 1;

        let vs: Vec<Fr> = ark_std::cfg_iter!(&lccs_shape.Ms)
            .map(|M| {
                (0..n)
                    .map(|y| {
                        let ry = compose_mle_input(rs.as_slice(), y, s2 as usize);
                        M.evaluate(ry.as_slice()) * z.evaluate::<G>(&ry[rs.len()..])
                    })
                    .sum()
            })
            .collect();

        let instance = LCCSInstance::<G, Z>::new(&lccs_shape, &commitment_W, &X, &rs, &vs)?;

        lccs_shape.is_satisfied::<Z>(&instance, &witness, &ck)?;

        // Change commitment.
        let invalid_commitment = commitment_W + commitment_W;
        let instance = LCCSInstance::<G, Z>::new(&lccs_shape, &invalid_commitment, &X, &rs, &vs)?;
        assert_eq!(
            lccs_shape.is_satisfied(&instance, &witness, &ck),
            Err(Error::NotSatisfied)
        );

        // Provide invalid witness.
        let invalid_W = to_field_elements::<G>(&[4, 9, 27, 30]);
        let invalid_witness = LCCSWitness::<G>::new(&lccs_shape, &invalid_W)?;
        let commitment_invalid_W = invalid_witness.commit::<Z>(&ck);

        let instance = LCCSInstance::<G, Z>::new(&lccs_shape, &commitment_invalid_W, &X, &rs, &vs)?;
        assert_eq!(
            lccs_shape.is_satisfied(&instance, &invalid_witness, &ck),
            Err(Error::NotSatisfied)
        );

        // Provide invalid public input.
        let invalid_X = to_field_elements::<G>(&[1, 36]);
        let instance = LCCSInstance::<G, Z>::new(&lccs_shape, &commitment_W, &invalid_X, &rs, &vs)?;
        assert_eq!(
            lccs_shape.is_satisfied(&instance, &witness, &ck),
            Err(Error::NotSatisfied)
        );

        Ok(())
    }
}
