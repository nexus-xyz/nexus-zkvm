use ark_ec::{AdditiveGroup, CurveGroup};
use ark_poly::{Polynomial, DenseMultilinearExtension, SparseMultilinearExtension};
use ark_poly_commit::{LabeledPolynomial, PolynomialCommitment};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_crypto_primitives::sponge::CryptographicSponge;

use ark_std::ops::Index;

#[cfg(feature = "parallel")]
use rayon::iter::{
    IntoParallelIterator, IntoParallelRefIterator, ParallelIterator,
};

use super::mle::{matrix_to_mle, vec_to_mle, fold_vec_to_mle_low};
use super::super::utils::index_to_le_field_encoding;
pub use super::super::sparse::{MatrixRef, SparseMatrix};

#[derive(Debug, Copy, Clone, PartialEq)]
pub enum Error {
    ConstraintNumberMismatch,
    InputLengthMismatch,
    InvalidWitnessLength,
    InvalidInputLength,
    InvalidConversion,
    InvalidMultiset,
    MultisetCardinalityMismatch,
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
    fn validate(
        num_constraints: usize,
        num_vars: usize,
        num_io: usize,
        M: MatrixRef<'_, G::ScalarField>,
    ) -> Result<(), Error> {
        for (i, row) in M.iter().enumerate() {
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

    /// Create an object of type `LCCSShape` from the explicitly specified CCS matrices
    pub fn new(
        num_constraints: usize,
        num_vars: usize,
        num_io: usize,
        num_matrices: usize,
        num_multisets: usize,
        max_cardinality: usize,
        Ms: Vec<MatrixRef<'_, G::ScalarField>>,
        cSs: Vec<(G::ScalarField, Vec<usize>)>,
    ) -> Result<LCCSShape<G>, Error> {
        if num_io == 0 {
            return Err(Error::InvalidInputLength);
        }

        Ms.iter().try_for_each(|M| Self::validate(num_constraints, num_vars, num_io, M))?;

        assert_eq!(Ms.len(), num_matrices);
        assert_eq!(cSs.len(), num_multisets);

        for (_c, S) in cSs.iter() {
            if S.len() > max_cardinality {
                return Err(Error::MultisetCardinalityMismatch);
            }

            S.iter().try_for_each(|idx| {
                if idx >= &num_matrices {
                    Err(Error::InvalidMultiset)
                } else {
                    Ok(())
                }
            })?;
        }

        let rows = num_constraints;
        let columns = num_io + num_vars;
        Ok(Self {
            num_constraints,
            num_vars,
            num_io,
            num_matrices,
            num_multisets,
            max_cardinality,
            Ms: Ms.iter().map(|M| matrix_to_mle(rows, columns, &SparseMatrix::new(M, rows, columns))).collect(),
            cSs,
        })
    }

    pub fn is_satisfied<S: CryptographicSponge, P: PolynomialCommitment<G::ScalarField, DenseMultilinearExtension<G::ScalarField>, S> + PartialEq>(
        &self,
        U: &LCCSInstance<G, S, P>,
        W: &LCCSWitness<G>,
        ck: &P::CommitterKey,
    ) -> Result<(), Error> {
        assert_eq!(U.X.len(), self.num_io);

        let z: DenseMultilinearExtension<G::ScalarField> = fold_vec_to_mle_low(&U.X, &W.W);

        let s = (self.num_io + self.num_vars - 1).checked_ilog2().unwrap_or(0) + 1; // s' in papers

       let rys: Vec<Vec<G::ScalarField>> = (0..s as usize).map(|y| [U.rs.as_slice(), index_to_le_field_encoding(y as u32, Some(s)).as_slice()].concat()).collect();

        let Mzs: Vec<G::ScalarField> = ark_std::cfg_iter!(&self.Ms)
            .map(|M| (0..s as usize).map(|y| M.evaluate(&rys[y]) * z.index(y)).sum())
            .collect();

        if ark_std::cfg_into_iter!(0..self.num_matrices).any(|idx| Mzs[idx] != U.vs[idx]) {
            return Err(Error::NotSatisfied);
        }

        let lw = LabeledPolynomial::<G::ScalarField, DenseMultilinearExtension<G::ScalarField>>::new("witness".to_string(), W.W, Some(W.W.num_vars), None);
        if U.commitment_W != *P::commit(ck, &[lw], None).unwrap().0[0].commitment() {
            return Err(Error::NotSatisfied);
        }

        Ok(())
    }
}

/// A type that holds a witness for a given LCCS instance.
#[derive(Clone, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize)]
pub struct LCCSWitness<G: CurveGroup> {
    pub W: DenseMultilinearExtension<G::ScalarField>,
}

/// A type that holds an LCCS instance.
#[derive(CanonicalSerialize, CanonicalDeserialize)]
pub struct LCCSInstance<G: CurveGroup, S: CryptographicSponge, P: PolynomialCommitment<G::ScalarField, DenseMultilinearExtension<G::ScalarField>, S> + PartialEq> {
    /// Commitment to MLE of witness.
    ///
    /// C in HyperNova/CCS papers.
    pub commitment_W: P::Commitment,
    /// X is assumed to start with a `ScalarField` field element `u`.
    pub X: Vec<G::ScalarField>,
    /// (Random) evaluation point
    pub rs: Vec<G::ScalarField>,
    /// Evaluation targets
    pub vs: Vec<G::ScalarField>,
}

impl<G: CurveGroup, S: CryptographicSponge, P: PolynomialCommitment<G::ScalarField, DenseMultilinearExtension<G::ScalarField>, S> + PartialEq> Clone for LCCSInstance<G, S, P> {
    fn clone(&self) -> Self {
        Self {
            commitment_W: self.commitment_W,
            X: self.X.clone(),
            rs: self.rs.clone(),
            vs: self.vs.clone(),
        }
    }
}

impl<G: CurveGroup, S: CryptographicSponge, P: PolynomialCommitment<G::ScalarField, DenseMultilinearExtension<G::ScalarField>, S> + PartialEq> PartialEq for LCCSInstance<G, S, P> {
    fn eq(&self, other: &Self) -> bool {
        self.commitment_W == other.commitment_W && self.X == other.X
    }
}

impl<G: CurveGroup, S: CryptographicSponge, P: PolynomialCommitment<G::ScalarField, DenseMultilinearExtension<G::ScalarField>, S> + PartialEq> Eq for LCCSInstance<G, S, P> where P::Commitment: Eq {}

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
    pub fn commit<S: CryptographicSponge, P: PolynomialCommitment<G::ScalarField, DenseMultilinearExtension<G::ScalarField>, S> + PartialEq>(
        &self,
        ck: &P::CommitterKey
    ) -> P::Commitment {
        let lw = LabeledPolynomial::<G::ScalarField, DenseMultilinearExtension<G::ScalarField>>::new("witness".to_string(), self.W, Some(self.W.num_vars), None);
        let wc = P::commit(ck, &[lw], None).unwrap().0[0].commitment();

        *wc
    }
}

impl<G: CurveGroup, S: CryptographicSponge, P: PolynomialCommitment<G::ScalarField, DenseMultilinearExtension<G::ScalarField>, S> + PartialEq> LCCSInstance<G, S, P> {
    /// A method to create an instance object using constituent elements.
    pub fn new(
        shape: &LCCSShape<G>,
        commitment_W: &P::Commitment,
        X: &[G::ScalarField],
        rs: Vec<G::ScalarField>,
        vs: Vec<G::ScalarField>,
    ) -> Result<Self, Error> {
        if X.is_empty() {
            return Err(Error::InvalidInputLength);
        } else if shape.num_io != X.len() {
            Err(Error::InvalidInputLength)
        } else if ((shape.num_constraints - 1).checked_ilog2().unwrap_or(0) + 1) != rs.len() as u32 {
            Err(Error::InvalidEvaluationPoint)
        } else if shape.num_matrices != vs.len() {
            Err(Error::InvalidTargets)
        } else {
            Ok(Self {
                commitment_W: *commitment_W,
                X: X.to_owned(),
                rs: rs,
                vs: vs,
            })
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(non_upper_case_globals)]
    #![allow(clippy::needless_range_loop)]

    use super::*;

    use ark_std::rand;
    use ark_ff::Field;
    use ark_poly_commit::marlin_pst13_pc::MarlinPST13;
    use ark_crypto_primitives::sponge::poseidon::PoseidonSponge;
    use ark_test_curves::bls12_381::{Bls12_381, G1Projective as G};

     use std::ops::Neg;

    type F = <ark_ec::short_weierstrass::Projective<ark_test_curves::bls12_381::g1::Config> as ark_ec::PrimeGroup>::ScalarField;

    type DMLE = DenseMultilinearExtension<F>;
    type MPST = MarlinPST13::<Bls12_381, DMLE, PoseidonSponge<F>>;

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

        let lccs_shape =  LCCSShape::<G>::new(NUM_CONSTRAINTS,
                                              NUM_WITNESS,
                                              NUM_PUBLIC,
                                              3,
                                              2,
                                              2,
                                              vec![&a, &a, &a],
                                              vec![
                                                  (F::ONE, vec![0, 1]),
                                                  (F::ONE.neg(), vec![2]),
                                              ],
        )?;

        let X = to_field_elements::<G>(&[0, 0]);
        let W = to_field_elements::<G>(&[0]);
        let witness = LCCSWitness::<G>::new(&lccs_shape, &W)?;

        let up = MPST::setup(witness.W.num_vars, false, None);
        let (ck, _vk) = MPST::trim(&up, witness.W.num_vars, 0, witness.W.num_vars);

        let commitment_W = witness.commit::<PoseidonSponge<F>, MPST>(&ck);

        let s = (NUM_CONSTRAINTS - 1).checked_ilog2().unwrap_or(0) + 1;

        let mut rng = rand::thread_rng();
        let rs: Vec<F> = (0..s).map(|_| F::random(rng)).collect();

        let instance = LCCSInstance::<G, PoseidonSponge<F>, MPST>::new(&lccs_shape, &commitment_W, &X, rs, )?;

        lccs_shape.is_satisfied(&instance, &witness, &ck)?;
        Ok(())
    }
/*
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
*/
}
