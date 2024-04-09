use ark_crypto_primitives::sponge::Absorb;
use ark_ec::{AdditiveGroup, CurveGroup};
use ark_ff::{Field, PrimeField};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_spartan::polycommitments::PolyCommitmentScheme;
use ark_std::{fmt, fmt::Display, ops::Neg, Zero};

#[cfg(feature = "parallel")]
use rayon::iter::{
    IndexedParallelIterator, IntoParallelIterator, IntoParallelRefIterator,
    IntoParallelRefMutIterator, ParallelIterator,
};

pub use super::sparse::{MatrixRef, SparseMatrix};
use super::{absorb::AbsorbNonNative, r1cs::R1CSShape};
use mle::vec_to_mle;

pub mod mle;

#[derive(Debug, Copy, Clone, PartialEq)]
pub enum Error {
    InvalidWitnessLength,
    InvalidInputLength,
    InvalidEvaluationPoint,
    InvalidTargets,
    NotSatisfied,
}

impl std::error::Error for Error {}

impl Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidWitnessLength => write!(f, "invalid witness length"),
            Self::InvalidInputLength => write!(f, "invalid input length"),
            Self::InvalidEvaluationPoint => write!(f, "invalid evaluation point"),
            Self::InvalidTargets => write!(f, "invalid targets"),
            Self::NotSatisfied => write!(f, "not satisfied"),
        }
    }
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
    pub fn is_satisfied<C: PolyCommitmentScheme<G>>(
        &self,
        U: &CCSInstance<G, C>,
        W: &CCSWitness<G>,
        ck: &C::PolyCommitmentKey,
    ) -> Result<(), Error> {
        assert_eq!(W.W.len(), self.num_vars);
        assert_eq!(U.X.len(), self.num_io);

        let z = [U.X.as_slice(), W.W.as_slice()].concat();
        let Mzs: Vec<Vec<G::ScalarField>> = ark_std::cfg_iter!(&self.Ms)
            .map(|M| M.multiply_vec(&z))
            .collect();

        let mut acc = vec![G::ScalarField::ZERO; self.num_constraints];
        for (c, S) in &self.cSs {
            let mut hadamard_product = vec![*c; self.num_constraints];

            for idx in S {
                ark_std::cfg_iter_mut!(hadamard_product)
                    .enumerate()
                    .for_each(|(j, x)| *x *= Mzs[*idx][j]);
            }

            ark_std::cfg_iter_mut!(acc)
                .enumerate()
                .for_each(|(i, s)| *s += hadamard_product[i]);
        }

        if ark_std::cfg_iter!(acc).any(|s| !s.is_zero()) {
            return Err(Error::NotSatisfied);
        }

        if U.commitment_W != W.commit::<C>(ck) {
            return Err(Error::NotSatisfied);
        }

        Ok(())
    }

    pub fn is_satisfied_linearized<C: PolyCommitmentScheme<G>>(
        &self,
        U: &LCCSInstance<G, C>,
        W: &CCSWitness<G>,
        ck: &C::PolyCommitmentKey,
    ) -> Result<(), Error> {
        assert_eq!(W.W.len(), self.num_vars);
        assert_eq!(U.X.len(), self.num_io);

        let z = [U.X.as_slice(), W.W.as_slice()].concat();
        let Mzs: Vec<G::ScalarField> = ark_std::cfg_iter!(&self.Ms)
            .map(|M| vec_to_mle(M.multiply_vec(&z).as_slice()).evaluate::<G>(U.rs.as_slice()))
            .collect();

        if ark_std::cfg_into_iter!(0..self.num_matrices).any(|idx| Mzs[idx] != U.vs[idx]) {
            return Err(Error::NotSatisfied);
        }

        if U.commitment_W != W.commit::<C>(ck) {
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
pub struct CCSInstance<G: CurveGroup, C: PolyCommitmentScheme<G>> {
    /// Commitment to witness.
    pub commitment_W: C::Commitment,
    /// X is assumed to start with a `ScalarField::ONE`.
    pub X: Vec<G::ScalarField>,
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

    /// Commits to the witness as a polynomial using the supplied key
    pub fn commit<C: PolyCommitmentScheme<G>>(&self, ck: &C::PolyCommitmentKey) -> C::Commitment {
        C::commit(&vec_to_mle(&self.W), ck)
    }

    /// Folds an incoming [`CCSWitness`] into the current one.
    pub fn fold(&self, W2: &CCSWitness<G>, rho: &G::ScalarField) -> Result<Self, Error> {
        let W1 = &self.W;
        let W2 = &W2.W;

        if W1.len() != W2.len() {
            return Err(Error::InvalidWitnessLength);
        }

        let W: Vec<G::ScalarField> = ark_std::cfg_iter!(W1)
            .zip(W2)
            .map(|(a, b)| *a + *rho * *b)
            .collect();

        Ok(Self { W })
    }
}

impl<G, C> Absorb for CCSInstance<G, C>
where
    G: CurveGroup + AbsorbNonNative<G::ScalarField>,
    G::ScalarField: Absorb,
    C: PolyCommitmentScheme<G>,
    C::Commitment: Into<Vec<G>>,
{
    fn to_sponge_bytes(&self, _: &mut Vec<u8>) {
        unreachable!()
    }

    fn to_sponge_field_elements<F: PrimeField>(&self, dest: &mut Vec<F>) {
        self.commitment_W.clone().into().iter().for_each(|c| {
            <G as AbsorbNonNative<G::ScalarField>>::to_sponge_field_elements(c, dest)
        });

        (&self.X[1..]).to_sponge_field_elements(dest);
    }
}

impl<G: CurveGroup, C: PolyCommitmentScheme<G>> CCSInstance<G, C> {
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
                commitment_W: commitment_W.clone(),
                X: X.to_owned(),
            })
        }
    }
}

impl<G: CurveGroup, C: PolyCommitmentScheme<G>> fmt::Debug for CCSInstance<G, C>
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

impl<G: CurveGroup, C: PolyCommitmentScheme<G>> Clone for CCSInstance<G, C> {
    fn clone(&self) -> Self {
        Self {
            commitment_W: self.commitment_W.clone(),
            X: self.X.clone(),
        }
    }
}

impl<G: CurveGroup, C: PolyCommitmentScheme<G>> PartialEq for CCSInstance<G, C> {
    fn eq(&self, other: &Self) -> bool {
        self.commitment_W == other.commitment_W && self.X == other.X
    }
}

impl<G: CurveGroup, C: PolyCommitmentScheme<G>> Eq for CCSInstance<G, C> where C::Commitment: Eq {}

impl<G, C> Absorb for LCCSInstance<G, C>
where
    G: CurveGroup + AbsorbNonNative<G::ScalarField>,
    G::ScalarField: Absorb,
    C: PolyCommitmentScheme<G>,
    C::Commitment: Into<Vec<G>>,
{
    fn to_sponge_bytes(&self, _: &mut Vec<u8>) {
        unreachable!()
    }

    fn to_sponge_field_elements<F: PrimeField>(&self, dest: &mut Vec<F>) {
        self.commitment_W.clone().into().iter().for_each(|c| {
            <G as AbsorbNonNative<G::ScalarField>>::to_sponge_field_elements(c, dest)
        });

        self.X.to_sponge_field_elements(dest);
        self.rs.to_sponge_field_elements(dest);
        self.vs.to_sponge_field_elements(dest);
    }
}

impl<G: CurveGroup, C: PolyCommitmentScheme<G>> LCCSInstance<G, C> {
    /// A method to create an instance object using constituent elements.
    pub fn new(
        shape: &CCSShape<G>,
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

    /// Folds an incoming **non-linearized** [`CCSInstance`] into the current one. Its auxillary inputs include a partial
    /// evaluation point `rs` and the sum of the evaluations at that point extended over the hypercube for both the current
    /// (`sigmas`) and incoming (`thetas`) instances.
    pub fn fold(
        &self,
        U2: &CCSInstance<G, C>,
        rho: &G::ScalarField,
        rs: &[G::ScalarField],
        sigmas: &[G::ScalarField],
        thetas: &[G::ScalarField],
    ) -> Result<Self, Error> {
        // in concept, uX1 = (u_1, x_1), oX2 = (1, x_2)
        // however, we don't guarantee oX2[0] = 1 during construction, so elide it during folding
        let (uX1, comm_W1) = (&self.X, self.commitment_W.clone());
        let (oX2, comm_W2) = (&U2.X, U2.commitment_W.clone());

        if self.rs.len() != rs.len() {
            return Err(Error::InvalidEvaluationPoint);
        }

        if sigmas.len() != thetas.len() {
            return Err(Error::InvalidTargets);
        }

        let (u1, X1) = (&uX1[0], &uX1[1..]);
        let X2 = &oX2[1..];

        let commitment_W = comm_W1 + comm_W2 * *rho;

        let u = [*u1 + *rho];
        let X: Vec<G::ScalarField> = ark_std::cfg_iter!(X1)
            .zip(X2)
            .map(|(a, b)| *a + *b * *rho)
            .collect();

        let vs: Vec<G::ScalarField> = ark_std::cfg_iter!(sigmas)
            .zip(thetas)
            .map(|(sigma, theta)| *sigma + *theta * *rho)
            .collect();

        Ok(Self {
            commitment_W,
            X: [&u, X.as_slice()].concat(),
            rs: rs.to_owned(),
            vs,
        })
    }
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

impl<G: CurveGroup, C: PolyCommitmentScheme<G>> fmt::Debug for LCCSInstance<G, C>
where
    C::Commitment: fmt::Debug,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LCCSInstance")
            .field("commitment_W", &self.commitment_W)
            .field("X", &self.X)
            .field("rs", &self.rs)
            .field("vs", &self.vs)
            .finish()
    }
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
        self.commitment_W == other.commitment_W
            && self.X == other.X
            && self.rs == other.rs
            && self.vs == other.vs
    }
}

impl<G: CurveGroup, C: PolyCommitmentScheme<G>> Eq for LCCSInstance<G, C> where C::Commitment: Eq {}

#[cfg(test)]
mod tests {
    #![allow(non_upper_case_globals)]
    #![allow(clippy::needless_range_loop)]

    use super::*;

    use ark_spartan::polycommitments::zeromorph::Zeromorph;
    use ark_spartan::polycommitments::PCSKeys;
    use ark_std::{test_rng, UniformRand};
    use ark_test_curves::bls12_381::{Bls12_381 as E, Fr, G1Projective as G};

    type Z = Zeromorph<E>;

    use crate::r1cs::tests::{to_field_elements, to_field_sparse, A, B, C};

    #[test]
    fn test_r1cs_to_ccs() -> Result<(), Error> {
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

        let ccs_shape = CCSShape::from(r1cs_shape.clone());
        assert_eq!(ccs_shape.num_constraints, NUM_CONSTRAINTS);
        assert_eq!(ccs_shape.num_constraints, r1cs_shape.num_constraints);

        assert_eq!(ccs_shape.num_vars, NUM_WITNESS);
        assert_eq!(ccs_shape.num_vars, r1cs_shape.num_vars);

        assert_eq!(ccs_shape.num_io, NUM_PUBLIC);
        assert_eq!(ccs_shape.num_io, r1cs_shape.num_io);

        assert_eq!(ccs_shape.num_matrices, 3);
        assert_eq!(ccs_shape.num_multisets, 2);
        assert_eq!(ccs_shape.max_cardinality, 2);

        assert_eq!(ccs_shape.Ms.len(), 3);
        assert_eq!(
            ccs_shape.Ms[0],
            SparseMatrix::new(&a, NUM_CONSTRAINTS, NUM_WITNESS + NUM_PUBLIC)
        );
        assert_eq!(
            ccs_shape.Ms[1],
            SparseMatrix::new(&b, NUM_CONSTRAINTS, NUM_WITNESS + NUM_PUBLIC)
        );
        assert_eq!(
            ccs_shape.Ms[2],
            SparseMatrix::new(&c, NUM_CONSTRAINTS, NUM_WITNESS + NUM_PUBLIC)
        );

        assert_eq!(ccs_shape.cSs.len(), 2);
        assert_eq!(ccs_shape.cSs[0], (Fr::ONE, vec![0, 1]));
        assert_eq!(ccs_shape.cSs[1], (Fr::ONE.neg(), vec![2]));

        Ok(())
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

        let r1cs_shape: R1CSShape<G> =
            R1CSShape::<G>::new(NUM_CONSTRAINTS, NUM_WITNESS, NUM_PUBLIC, &a, &a, &a).unwrap();

        let ccs_shape = CCSShape::from(r1cs_shape);

        let mut rng = test_rng();
        let SRS = Z::setup(3, b"test", &mut rng).unwrap();
        let PCSKeys { ck, .. } = Z::trim(&SRS, 3);

        let X = to_field_elements::<G>(&[0, 0]);
        let W = to_field_elements::<G>(&[0]);
        let witness = CCSWitness::<G>::new(&ccs_shape, &W)?;

        let commitment_W = witness.commit::<Z>(&ck);

        let instance = CCSInstance::<G, Z>::new(&ccs_shape, &commitment_W, &X)?;

        ccs_shape.is_satisfied(&instance, &witness, &ck)?;
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

        let ccs_shape = CCSShape::from(r1cs_shape);

        let mut rng = test_rng();
        let SRS = Z::setup(3, b"test", &mut rng).unwrap();
        let PCSKeys { ck, .. } = Z::trim(&SRS, 3);

        let X = to_field_elements::<G>(&[1, 35]);
        let W = to_field_elements::<G>(&[3, 9, 27, 30]);
        let witness = CCSWitness::<G>::new(&ccs_shape, &W)?;

        let commitment_W = witness.commit::<Z>(&ck);

        let instance = CCSInstance::<G, Z>::new(&ccs_shape, &commitment_W, &X)?;

        ccs_shape.is_satisfied(&instance, &witness, &ck)?;

        // Change commitment.
        let invalid_commitment = commitment_W + commitment_W;
        let instance = CCSInstance::<G, Z>::new(&ccs_shape, &invalid_commitment, &X)?;
        assert_eq!(
            ccs_shape.is_satisfied(&instance, &witness, &ck),
            Err(Error::NotSatisfied)
        );

        // Provide invalid witness.
        let invalid_W = to_field_elements::<G>(&[4, 9, 27, 30]);
        let invalid_witness = CCSWitness::<G>::new(&ccs_shape, &invalid_W)?;
        let commitment_invalid_W = invalid_witness.commit::<Z>(&ck);

        let instance = CCSInstance::<G, Z>::new(&ccs_shape, &commitment_invalid_W, &X)?;
        assert_eq!(
            ccs_shape.is_satisfied(&instance, &invalid_witness, &ck),
            Err(Error::NotSatisfied)
        );

        // Provide invalid public input.
        let invalid_X = to_field_elements::<G>(&[1, 36]);
        let instance = CCSInstance::<G, Z>::new(&ccs_shape, &commitment_W, &invalid_X)?;
        assert_eq!(
            ccs_shape.is_satisfied(&instance, &witness, &ck),
            Err(Error::NotSatisfied)
        );
        Ok(())
    }

    #[test]
    fn zero_instance_is_satisfied_linearized() -> Result<(), Error> {
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

        let ccs_shape = CCSShape::from(r1cs_shape);

        let mut rng = test_rng();
        let SRS = Z::setup(2, b"test", &mut rng).unwrap();
        let PCSKeys { ck, .. } = Z::trim(&SRS, 2);

        let X = to_field_elements::<G>(&[0, 0]);
        let W = to_field_elements::<G>(&[0]);
        let witness = CCSWitness::<G>::new(&ccs_shape, &W)?;

        let commitment_W = witness.commit::<Z>(&ck);

        let s = (NUM_CONSTRAINTS - 1).checked_ilog2().unwrap_or(0) + 1;
        let rs: Vec<Fr> = (0..s).map(|_| Fr::rand(&mut rng)).collect();

        let z = [X.as_slice(), W.as_slice()].concat();
        let vs: Vec<Fr> = ark_std::cfg_iter!(&ccs_shape.Ms)
            .map(|M| vec_to_mle(M.multiply_vec(&z).as_slice()).evaluate::<G>(rs.as_slice()))
            .collect();

        let instance = LCCSInstance::<G, Z>::new(&ccs_shape, &commitment_W, &X, &rs, &vs)?;

        ccs_shape.is_satisfied_linearized::<Z>(&instance, &witness, &ck)?;

        Ok(())
    }

    #[test]
    fn is_satisfied_linearized() -> Result<(), Error> {
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

        let ccs_shape = CCSShape::from(r1cs_shape);

        let mut rng = test_rng();
        let SRS = Z::setup(3, b"test", &mut rng).unwrap();
        let PCSKeys { ck, .. } = Z::trim(&SRS, 3);

        let X = to_field_elements::<G>(&[1, 35]);
        let W = to_field_elements::<G>(&[3, 9, 27, 30]);
        let witness = CCSWitness::<G>::new(&ccs_shape, &W)?;

        let commitment_W = witness.commit::<Z>(&ck);

        let s = (NUM_CONSTRAINTS - 1).checked_ilog2().unwrap_or(0) + 1;
        let rs: Vec<Fr> = (0..s).map(|_| Fr::rand(&mut rng)).collect();

        let z = [X.as_slice(), W.as_slice()].concat();
        let vs: Vec<Fr> = ark_std::cfg_iter!(&ccs_shape.Ms)
            .map(|M| vec_to_mle(M.multiply_vec(&z).as_slice()).evaluate::<G>(rs.as_slice()))
            .collect();

        let instance = LCCSInstance::<G, Z>::new(&ccs_shape, &commitment_W, &X, &rs, &vs)?;

        ccs_shape.is_satisfied_linearized::<Z>(&instance, &witness, &ck)?;

        // Change commitment.
        let invalid_commitment = commitment_W + commitment_W;
        let instance = LCCSInstance::<G, Z>::new(&ccs_shape, &invalid_commitment, &X, &rs, &vs)?;
        assert_eq!(
            ccs_shape.is_satisfied_linearized(&instance, &witness, &ck),
            Err(Error::NotSatisfied)
        );

        // Provide invalid witness.
        let invalid_W = to_field_elements::<G>(&[4, 9, 27, 30]);
        let invalid_witness = CCSWitness::<G>::new(&ccs_shape, &invalid_W)?;
        let commitment_invalid_W = invalid_witness.commit::<Z>(&ck);

        let instance = LCCSInstance::<G, Z>::new(&ccs_shape, &commitment_invalid_W, &X, &rs, &vs)?;
        assert_eq!(
            ccs_shape.is_satisfied_linearized(&instance, &invalid_witness, &ck),
            Err(Error::NotSatisfied)
        );

        // Provide invalid public input.
        let invalid_X = to_field_elements::<G>(&[1, 36]);
        let instance = LCCSInstance::<G, Z>::new(&ccs_shape, &commitment_W, &invalid_X, &rs, &vs)?;
        assert_eq!(
            ccs_shape.is_satisfied_linearized(&instance, &witness, &ck),
            Err(Error::NotSatisfied)
        );

        Ok(())
    }

    #[test]
    fn folded_instance_is_satisfied() -> Result<(), Error> {
        // Fold linearized and non-linearized instances together and verify that resulting
        // linearized instance is satisfied.
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

        let rho: Fr = Fr::from(11);

        let r1cs_shape: R1CSShape<G> =
            R1CSShape::<G>::new(NUM_CONSTRAINTS, NUM_WITNESS, NUM_PUBLIC, &a, &b, &c).unwrap();

        let ccs_shape = CCSShape::from(r1cs_shape);

        let mut rng = test_rng();
        let SRS = Z::setup(3, b"test", &mut rng).unwrap();
        let PCSKeys { ck, .. } = Z::trim(&SRS, 3);

        let X = to_field_elements::<G>(&[1, 35]);
        let W = to_field_elements::<G>(&[3, 9, 27, 30]);
        let W2 = CCSWitness::<G>::new(&ccs_shape, &W)?;

        let commitment_W = W2.commit::<Z>(&ck);

        let U2 = CCSInstance::<G, Z>::new(&ccs_shape, &commitment_W, &X)?;

        let s = (NUM_CONSTRAINTS - 1).checked_ilog2().unwrap_or(0) + 1;
        let rs1: Vec<Fr> = (0..s).map(|_| Fr::rand(&mut rng)).collect();

        let z1 = [X.as_slice(), W.as_slice()].concat();
        let vs1: Vec<Fr> = ark_std::cfg_iter!(&ccs_shape.Ms)
            .map(|M| vec_to_mle(M.multiply_vec(&z1).as_slice()).evaluate::<G>(rs1.as_slice()))
            .collect();

        let U1 = LCCSInstance::<G, Z>::new(&ccs_shape, &commitment_W, &X, &rs1, &vs1)?;
        let W1 = W2.clone();

        let z2 = z1.clone();
        let rs2: Vec<Fr> = (0..s).map(|_| Fr::rand(&mut rng)).collect();

        let sigmas: Vec<Fr> = ark_std::cfg_iter!(&ccs_shape.Ms)
            .map(|M| vec_to_mle(M.multiply_vec(&z1).as_slice()).evaluate::<G>(rs2.as_slice()))
            .collect();

        let thetas: Vec<Fr> = ark_std::cfg_iter!(&ccs_shape.Ms)
            .map(|M| vec_to_mle(M.multiply_vec(&z2).as_slice()).evaluate::<G>(rs2.as_slice()))
            .collect();

        let folded_instance = U1.fold(&U2, &rho, &rs2, &sigmas, &thetas)?;

        let witness = W1.fold(&W2, &rho)?;

        ccs_shape.is_satisfied_linearized(&folded_instance, &witness, &ck)?;
        Ok(())
    }
}
