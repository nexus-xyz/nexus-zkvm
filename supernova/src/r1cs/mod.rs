use ark_std::fmt;

use ark_crypto_primitives::sponge::Absorb;
use ark_ec::{AdditiveGroup, CurveGroup};
use ark_ff::{Field, PrimeField};
use ark_relations::r1cs::ConstraintSystemRef;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::fmt::Display;

#[cfg(feature = "parallel")]
use rayon::iter::{
    IndexedParallelIterator, IntoParallelIterator, IntoParallelRefIterator, ParallelIterator,
};

use super::{absorb::AbsorbNonNative, commitment::CommitmentScheme};

pub mod sparse;
pub use sparse::SparseMatrix;

pub use ark_relations::r1cs::Matrix;
pub type MatrixRef<'a, F> = &'a [Vec<(F, usize)>];

#[derive(Debug, Copy, Clone, PartialEq)]
pub enum Error {
    ConstraintNumberMismatch,
    InputLengthMismatch,
    InvalidWitnessLength,
    InvalidInputLength,

    NotSatisfied,
}

impl std::error::Error for Error {}

impl Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ConstraintNumberMismatch => write!(f, "constraint number mismatch"),
            Self::InputLengthMismatch => write!(f, "input length mismatch"),
            Self::InvalidWitnessLength => write!(f, "invalid witness length"),
            Self::InvalidInputLength => write!(f, "invalid input length"),
            Self::NotSatisfied => write!(f, "not satisfied"),
        }
    }
}

/// A type that holds the shape of the R1CS matrices
#[derive(Debug, Clone, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize)]
pub struct R1CSShape<G: CurveGroup> {
    /// Number of constraints.
    ///
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
    pub A: SparseMatrix<G::ScalarField>,
    pub B: SparseMatrix<G::ScalarField>,
    pub C: SparseMatrix<G::ScalarField>,
}

impl<G: CurveGroup> fmt::Display for R1CSShape<G> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "R1CSShape {{ num_constraints: {}, num_vars: {}, num_io: {}, A: [_, {}], B: [_, {}], C: [_, {}] }}",
            self.num_constraints,
            self.num_vars,
            self.num_io,
            self.A.len(),
            self.B.len(),
            self.C.len(),
        )
    }
}

impl<G: CurveGroup> R1CSShape<G> {
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

    /// Create an object of type `R1CSShape` from the explicitly specified R1CS matrices
    pub fn new(
        num_constraints: usize,
        num_vars: usize,
        num_io: usize,
        A: MatrixRef<'_, G::ScalarField>,
        B: MatrixRef<'_, G::ScalarField>,
        C: MatrixRef<'_, G::ScalarField>,
    ) -> Result<R1CSShape<G>, Error> {
        if num_io == 0 {
            return Err(Error::InvalidInputLength);
        }

        Self::validate(num_constraints, num_vars, num_io, A)?;
        Self::validate(num_constraints, num_vars, num_io, B)?;
        Self::validate(num_constraints, num_vars, num_io, C)?;

        let rows = num_constraints;
        let columns = num_io + num_vars;
        Ok(Self {
            num_constraints,
            num_vars,
            num_io,
            A: SparseMatrix::new(A, rows, columns),
            B: SparseMatrix::new(B, rows, columns),
            C: SparseMatrix::new(C, rows, columns),
        })
    }

    /// Checks if the R1CS instance together with the witness `W` satisfies the R1CS constraints determined by `shape`.
    pub fn is_satisfied<C: CommitmentScheme<G>>(
        &self,
        U: &R1CSInstance<G, C>,
        W: &R1CSWitness<G>,
        pp: &C::PP,
    ) -> Result<(), Error> {
        assert_eq!(W.W.len(), self.num_vars);
        assert_eq!(U.X.len(), self.num_io);

        let z = [U.X.as_slice(), W.W.as_slice()].concat();
        let Az = self.A.multiply_vec(&z);
        let Bz = self.B.multiply_vec(&z);
        let Cz = self.C.multiply_vec(&z);

        if ark_std::cfg_into_iter!(0..self.num_constraints).any(|idx| Az[idx] * Bz[idx] != Cz[idx])
        {
            return Err(Error::NotSatisfied);
        }

        if U.commitment_W != C::commit(pp, &W.W) {
            return Err(Error::NotSatisfied);
        }

        Ok(())
    }

    /// Checks if the relaxed R1CS instance together with the witness `W` satisfies the constraints determined by `shape`.
    pub fn is_relaxed_satisfied<C: CommitmentScheme<G>>(
        &self,
        U: &RelaxedR1CSInstance<G, C>,
        W: &RelaxedR1CSWitness<G>,
        pp: &C::PP,
    ) -> Result<(), Error> {
        assert_eq!(W.W.len(), self.num_vars);
        assert_eq!(U.X.len(), self.num_io);
        assert_eq!(W.E.len(), self.num_constraints);

        let z = [U.X.as_slice(), W.W.as_slice()].concat();
        let Az = self.A.multiply_vec(&z);
        let Bz = self.B.multiply_vec(&z);
        let Cz = self.C.multiply_vec(&z);

        let u = U.X[0];

        if ark_std::cfg_into_iter!(0..self.num_constraints)
            .any(|idx| Az[idx] * Bz[idx] != u * Cz[idx] + W.E[idx])
        {
            return Err(Error::NotSatisfied);
        }

        let (commitment_W, commitment_E) = (C::commit(pp, &W.W), C::commit(pp, &W.E));

        if U.commitment_W != commitment_W || U.commitment_E != commitment_E {
            return Err(Error::NotSatisfied);
        }

        Ok(())
    }
}

impl<G: CurveGroup> From<ConstraintSystemRef<G::ScalarField>> for R1CSShape<G> {
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
            num_vars,
            num_io,
            A: SparseMatrix::new(&matrices.a, rows, columns),
            B: SparseMatrix::new(&matrices.b, rows, columns),
            C: SparseMatrix::new(&matrices.c, rows, columns),
        }
    }
}

/// A type that holds a witness for a given R1CS instance.
#[derive(Clone, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize)]
pub struct R1CSWitness<G: CurveGroup> {
    pub W: Vec<G::ScalarField>,
}

/// A type that holds an R1CS instance.
#[derive(CanonicalSerialize, CanonicalDeserialize)]
pub struct R1CSInstance<G: CurveGroup, C: CommitmentScheme<G>> {
    /// Commitment to witness.
    pub commitment_W: C::Commitment,
    /// X is assumed to start with a `ScalarField::ONE`.
    pub X: Vec<G::ScalarField>,
}

impl<G: CurveGroup, C: CommitmentScheme<G>> Clone for R1CSInstance<G, C> {
    fn clone(&self) -> Self {
        Self {
            commitment_W: self.commitment_W,
            X: self.X.clone(),
        }
    }
}

impl<G: CurveGroup, C: CommitmentScheme<G>> fmt::Debug for R1CSInstance<G, C>
where
    C::Commitment: fmt::Debug,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("R1CSInstance")
            .field("commitment_W", &self.commitment_W)
            .field("X", &self.X)
            .finish()
    }
}

impl<G: CurveGroup, C: CommitmentScheme<G>> PartialEq for R1CSInstance<G, C> {
    fn eq(&self, other: &Self) -> bool {
        self.commitment_W == other.commitment_W && self.X == other.X
    }
}

impl<G: CurveGroup, C: CommitmentScheme<G>> Eq for R1CSInstance<G, C> where C::Commitment: Eq {}

impl<G, C> Absorb for R1CSInstance<G, C>
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

impl<G: CurveGroup> R1CSWitness<G> {
    /// A method to create a witness object using a vector of scalars.
    pub fn new(shape: &R1CSShape<G>, W: &[G::ScalarField]) -> Result<Self, Error> {
        if shape.num_vars != W.len() {
            Err(Error::InvalidWitnessLength)
        } else {
            Ok(Self { W: W.to_owned() })
        }
    }

    pub fn zero(shape: &R1CSShape<G>) -> Self {
        Self {
            W: vec![G::ScalarField::ZERO; shape.num_vars],
        }
    }

    /// Commits to the witness using the supplied generators
    pub fn commit<C: CommitmentScheme<G>>(&self, pp: &C::PP) -> C::Commitment {
        C::commit(pp, &self.W)
    }
}

impl<G: CurveGroup, C: CommitmentScheme<G>> R1CSInstance<G, C> {
    /// A method to create an instance object using constituent elements.
    pub fn new(
        shape: &R1CSShape<G>,
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

/// A type that holds a witness for a given Relaxed R1CS instance.
#[derive(Default, Clone, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize)]
pub struct RelaxedR1CSWitness<G: CurveGroup> {
    pub W: Vec<G::ScalarField>,
    pub E: Vec<G::ScalarField>,
}

/// A type that holds a Relaxed R1CS instance.
#[derive(CanonicalSerialize, CanonicalDeserialize)]
pub struct RelaxedR1CSInstance<G: CurveGroup, C: CommitmentScheme<G>> {
    pub commitment_W: C::Commitment,
    pub commitment_E: C::Commitment,
    /// X is assumed to start with `u`.
    pub X: Vec<G::ScalarField>,
}

impl<G: CurveGroup, C: CommitmentScheme<G>> Clone for RelaxedR1CSInstance<G, C> {
    fn clone(&self) -> Self {
        Self {
            commitment_W: self.commitment_W,
            commitment_E: self.commitment_E,
            X: self.X.clone(),
        }
    }
}

impl<G: CurveGroup, C: CommitmentScheme<G>> fmt::Debug for RelaxedR1CSInstance<G, C>
where
    C::Commitment: fmt::Debug,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RelaxedR1CSInstance")
            .field("commitment_W", &self.commitment_W)
            .field("commitment_E", &self.commitment_E)
            .field("X", &self.X)
            .finish()
    }
}

impl<G: CurveGroup, C: CommitmentScheme<G>> PartialEq for RelaxedR1CSInstance<G, C> {
    fn eq(&self, other: &Self) -> bool {
        self.commitment_W == other.commitment_W
            && self.commitment_E == other.commitment_E
            && self.X == other.X
    }
}

impl<G: CurveGroup, C: CommitmentScheme<G>> Eq for RelaxedR1CSInstance<G, C> where C::Commitment: Eq {}

impl<G, C> Absorb for RelaxedR1CSInstance<G, C>
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
        <G as AbsorbNonNative<G::ScalarField>>::to_sponge_field_elements(
            &self.commitment_E.into(),
            dest,
        );

        self.X.to_sponge_field_elements(dest);
    }
}

impl<G: CurveGroup, C: CommitmentScheme<G>> From<&R1CSInstance<G, C>>
    for RelaxedR1CSInstance<G, C>
{
    fn from(instance: &R1CSInstance<G, C>) -> Self {
        Self {
            commitment_W: instance.commitment_W,
            commitment_E: C::Commitment::default(),
            X: instance.X.clone(),
        }
    }
}

impl<G: CurveGroup> RelaxedR1CSWitness<G> {
    pub fn zero(shape: &R1CSShape<G>) -> Self {
        Self {
            W: vec![G::ScalarField::ZERO; shape.num_vars],
            E: vec![G::ScalarField::ZERO; shape.num_constraints],
        }
    }
    /// Initializes a new [`RelaxedR1CSWitness`] from an [`R1CSWitness`].
    pub fn from_r1cs_witness(shape: &R1CSShape<G>, witness: &R1CSWitness<G>) -> Self {
        Self {
            W: witness.W.clone(),
            E: vec![G::ScalarField::ZERO; shape.num_constraints],
        }
    }

    /// Folds an incoming **non-relaxed** [`R1CSWitness`] into the current one.
    pub fn fold(
        &self,
        W2: &R1CSWitness<G>,
        T: &[G::ScalarField],
        r: &G::ScalarField,
    ) -> Result<Self, Error> {
        let (W1, E1) = (&self.W, &self.E);
        let W2 = &W2.W;

        if W1.len() != W2.len() {
            return Err(Error::InvalidWitnessLength);
        }

        let W: Vec<G::ScalarField> = ark_std::cfg_iter!(W1)
            .zip(W2)
            .map(|(a, b)| *a + *r * *b)
            .collect();
        // Note that W2 is not relaxed, thus E2 = 0.
        let E: Vec<G::ScalarField> = ark_std::cfg_iter!(E1)
            .zip(T)
            .map(|(a, b)| *a + *r * *b)
            .collect();
        Ok(Self { W, E })
    }

    /// Folds an incoming [`RelaxedR1CSWitness`] into the current one.
    pub fn fold_with_relaxed(
        &self,
        W2: &RelaxedR1CSWitness<G>,
        T: &[G::ScalarField],
        r: &G::ScalarField,
    ) -> Result<Self, Error> {
        let (W1, E1) = (&self.W, &self.E);
        let (W2, E2) = (&W2.W, &W2.E);

        if W1.len() != W2.len() || E1.len() != E2.len() {
            return Err(Error::InvalidWitnessLength);
        }

        let W: Vec<G::ScalarField> = ark_std::cfg_iter!(W1)
            .zip(W2)
            .map(|(a, b)| *a + *r * *b)
            .collect();

        let r_square = r.square();
        let E: Vec<G::ScalarField> = ark_std::cfg_iter!(E1)
            .zip(E2)
            .zip(T)
            .map(|((e1, e2), t)| *e1 + *r * *t + r_square * e2)
            .collect();
        Ok(Self { W, E })
    }
}

impl<G: CurveGroup, C: CommitmentScheme<G>> RelaxedR1CSInstance<G, C> {
    pub fn new(shape: &R1CSShape<G>) -> Self {
        Self {
            commitment_W: C::Commitment::default(),
            commitment_E: C::Commitment::default(),
            X: vec![G::ScalarField::ZERO; shape.num_io],
        }
    }

    /// Folds an incoming **non-relaxed** [`R1CSInstance`] into the current one.
    pub fn fold(
        &self,
        U2: &R1CSInstance<G, C>,
        comm_T: &C::Commitment,
        r: &G::ScalarField,
    ) -> Result<Self, Error> {
        let (X1, comm_W1, comm_E1) = (&self.X, self.commitment_W, self.commitment_E);
        let (X2, comm_W2) = (&U2.X, &U2.commitment_W);

        let X: Vec<G::ScalarField> = ark_std::cfg_iter!(X1)
            .zip(X2)
            .map(|(a, b)| *a + *r * *b)
            .collect();
        let commitment_W = comm_W1 + *comm_W2 * *r;
        // Note that U2 is not relaxed, thus E2 = 0 and u2 = 1.
        let commitment_E = comm_E1 + *comm_T * *r;

        Ok(Self {
            commitment_W,
            commitment_E,
            X,
        })
    }

    /// Folds an incoming [`RelaxedR1CSInstance`] into the current one.
    pub fn fold_with_relaxed(
        &self,
        U2: &RelaxedR1CSInstance<G, C>,
        comm_T: &C::Commitment,
        r: &G::ScalarField,
    ) -> Result<Self, Error> {
        let (X1, comm_W1, comm_E1) = (&self.X, self.commitment_W, self.commitment_E);
        let (X2, comm_W2, comm_E2) = (&U2.X, &U2.commitment_W, &U2.commitment_E);

        let X: Vec<G::ScalarField> = ark_std::cfg_iter!(X1)
            .zip(X2)
            .map(|(a, b)| *a + *r * *b)
            .collect();
        let commitment_W = comm_W1 + *comm_W2 * *r;
        let commitment_E = comm_E1 + *comm_T * *r + *comm_E2 * r.square();

        Ok(Self {
            commitment_W,
            commitment_E,
            X,
        })
    }
}

/// A method to compute a commitment to the cross-term `T` given a
/// Relaxed R1CS instance-witness pair and **not relaxed** R1CS instance-witness pair.
pub fn commit_T<G: CurveGroup, C: CommitmentScheme<G>>(
    shape: &R1CSShape<G>,
    pp: &C::PP,
    U1: &RelaxedR1CSInstance<G, C>,
    W1: &RelaxedR1CSWitness<G>,
    U2: &R1CSInstance<G, C>,
    W2: &R1CSWitness<G>,
) -> Result<(Vec<G::ScalarField>, C::Commitment), Error> {
    let z1 = [&U1.X, &W1.W[..]].concat();
    let Az1 = shape.A.multiply_vec(&z1);
    let Bz1 = shape.B.multiply_vec(&z1);
    let Cz1 = shape.C.multiply_vec(&z1);

    let z2 = [&U2.X, &W2.W[..]].concat();
    let Az2 = shape.A.multiply_vec(&z2);
    let Bz2 = shape.B.multiply_vec(&z2);
    let Cz2 = shape.C.multiply_vec(&z2);

    // Circle-product.
    let Az1_Bz2: Vec<G::ScalarField> = ark_std::cfg_iter!(Az1)
        .zip(&Bz2)
        .map(|(&a, &b)| a * b)
        .collect();
    let Az2_Bz1: Vec<G::ScalarField> = ark_std::cfg_iter!(Az2)
        .zip(&Bz1)
        .map(|(&a, &b)| a * b)
        .collect();

    // Scalar product.
    // u2 = 1 since U2 is non-relaxed instance, thus no multiplication required for Cz1.
    let u1 = U1.X[0];
    let u1_Cz2: Vec<G::ScalarField> = ark_std::cfg_into_iter!(Cz2).map(|cz2| u1 * cz2).collect();

    // Compute cross-term.
    let T: Vec<G::ScalarField> = ark_std::cfg_into_iter!(0..Az1_Bz2.len())
        .map(|i| Az1_Bz2[i] + Az2_Bz1[i] - u1_Cz2[i] - Cz1[i])
        .collect();

    let comm_T = C::commit(pp, &T);

    Ok((T, comm_T))
}

/// A method to compute a commitment to the cross-term `T` given two pairs of Relaxed R1CS instance and witness.
pub fn commit_T_with_relaxed<G: CurveGroup, C: CommitmentScheme<G>>(
    shape: &R1CSShape<G>,
    pp: &C::PP,
    U1: &RelaxedR1CSInstance<G, C>,
    W1: &RelaxedR1CSWitness<G>,
    U2: &RelaxedR1CSInstance<G, C>,
    W2: &RelaxedR1CSWitness<G>,
) -> Result<(Vec<G::ScalarField>, C::Commitment), Error> {
    let z1 = [&U1.X, &W1.W[..]].concat();
    let Az1 = shape.A.multiply_vec(&z1);
    let Bz1 = shape.B.multiply_vec(&z1);
    let Cz1 = shape.C.multiply_vec(&z1);

    let z2 = [&U2.X, &W2.W[..]].concat();
    let Az2 = shape.A.multiply_vec(&z2);
    let Bz2 = shape.B.multiply_vec(&z2);
    let Cz2 = shape.C.multiply_vec(&z2);

    // Circle-product.
    let Az1_Bz2: Vec<G::ScalarField> = ark_std::cfg_iter!(Az1)
        .zip(&Bz2)
        .map(|(&a, &b)| a * b)
        .collect();
    let Az2_Bz1: Vec<G::ScalarField> = ark_std::cfg_iter!(Az2)
        .zip(&Bz1)
        .map(|(&a, &b)| a * b)
        .collect();

    // Scalar product.
    let u1 = U1.X[0];
    let u2 = U2.X[0];
    let u1_Cz2: Vec<G::ScalarField> = ark_std::cfg_into_iter!(Cz2).map(|cz2| u1 * cz2).collect();
    let u2_Cz1: Vec<G::ScalarField> = ark_std::cfg_into_iter!(Cz1).map(|cz1| u2 * cz1).collect();

    // Compute cross-term.
    let T: Vec<G::ScalarField> = ark_std::cfg_into_iter!(0..Az1_Bz2.len())
        .map(|i| Az1_Bz2[i] + Az2_Bz1[i] - u1_Cz2[i] - u2_Cz1[i])
        .collect();

    let comm_T = C::commit(pp, &T);

    Ok((T, comm_T))
}

#[cfg(test)]
mod tests {
    #![allow(non_upper_case_globals)]
    #![allow(clippy::needless_range_loop)]

    use super::*;
    use crate::pedersen::PedersenCommitment;

    use ark_ff::Field;
    use ark_relations::r1cs::Matrix;
    use ark_test_curves::bls12_381::{Fr as Scalar, G1Projective as G};

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

    fn to_field_elements<G: CurveGroup>(x: &[u64]) -> Vec<G::ScalarField> {
        x.iter().copied().map(G::ScalarField::from).collect()
    }

    #[test]
    fn invalid_input() {
        #[rustfmt::skip]
        let a = {
            let a: &[&[u64]] = &[
                &[1, 2, 3],
                &[3, 4, 5],
                &[6, 7, 8],
            ];
            to_field_sparse::<G>(a)
        };

        assert_eq!(
            R1CSShape::<G>::new(2, 2, 2, &a, &a, &a),
            Err(Error::ConstraintNumberMismatch)
        );
        assert_eq!(
            R1CSShape::<G>::new(3, 0, 1, &a, &a, &a),
            Err(Error::InputLengthMismatch)
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

        let shape = R1CSShape::<G>::new(NUM_CONSTRAINTS, NUM_WITNESS, NUM_PUBLIC, &a, &a, &a)?;
        let instance = RelaxedR1CSInstance::<G, PedersenCommitment<G>>::new(&shape);
        let witness = RelaxedR1CSWitness::<G>::zero(&shape);

        shape.is_relaxed_satisfied(&instance, &witness, &pp)?;
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
        let shape = R1CSShape::<G>::new(NUM_CONSTRAINTS, NUM_WITNESS, NUM_PUBLIC, &a, &b, &c)?;
        let X = to_field_elements::<G>(&[1, 35]);
        let W = to_field_elements::<G>(&[3, 9, 27, 30]);
        let commitment_W = PedersenCommitment::<G>::commit(&pp, &W);

        let instance = R1CSInstance::<G, PedersenCommitment<G>>::new(&shape, &commitment_W, &X)?;
        let witness = R1CSWitness::<G>::new(&shape, &W)?;

        shape.is_satisfied(&instance, &witness, &pp)?;

        // Change commitment.
        let invalid_commitment = commitment_W.double();
        let instance =
            R1CSInstance::<G, PedersenCommitment<G>>::new(&shape, &invalid_commitment, &X)?;
        assert_eq!(
            shape.is_satisfied(&instance, &witness, &pp),
            Err(Error::NotSatisfied)
        );

        // Provide invalid witness.
        let invalid_W = to_field_elements::<G>(&[4, 9, 27, 30]);
        let commitment_invalid_W = PedersenCommitment::<G>::commit(&pp, &W);
        let instance =
            R1CSInstance::<G, PedersenCommitment<G>>::new(&shape, &commitment_invalid_W, &X)?;
        let invalid_witness = R1CSWitness::<G>::new(&shape, &invalid_W)?;
        assert_eq!(
            shape.is_satisfied(&instance, &invalid_witness, &pp),
            Err(Error::NotSatisfied)
        );

        // Provide invalid public input.
        let invalid_X = to_field_elements::<G>(&[1, 36]);
        let instance =
            R1CSInstance::<G, PedersenCommitment<G>>::new(&shape, &commitment_W, &invalid_X)?;
        assert_eq!(
            shape.is_satisfied(&instance, &witness, &pp),
            Err(Error::NotSatisfied)
        );
        Ok(())
    }

    #[test]
    fn relaxed_from_r1cs_is_satisfied() -> Result<(), Error> {
        // Convert previous test to relaxed instance and verify it's satisfied.
        // Essentially, a simple test for u = 1 and E = 0.
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
        let shape = R1CSShape::<G>::new(NUM_CONSTRAINTS, NUM_WITNESS, NUM_PUBLIC, &a, &b, &c)?;

        let X = to_field_elements::<G>(&[1, 35]);
        let W = to_field_elements::<G>(&[3, 9, 27, 30]);
        let commitment_W = PedersenCommitment::<G>::commit(&pp, &W);

        let instance = R1CSInstance::<G, PedersenCommitment<G>>::new(&shape, &commitment_W, &X)?;
        let witness = R1CSWitness::<G>::new(&shape, &W)?;

        let relaxed_instance = RelaxedR1CSInstance::<G, PedersenCommitment<G>>::from(&instance);
        let relaxed_witness = RelaxedR1CSWitness::<G>::from_r1cs_witness(&shape, &witness);

        shape.is_relaxed_satisfied(&relaxed_instance, &relaxed_witness, &pp)?;
        Ok(())
    }

    #[test]
    fn folded_instance_is_satisfied() -> Result<(), Error> {
        // Finally, fold two instances together and verify that resulting relaxed
        // instance is satisfied.
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
        const r: Scalar = Scalar::ONE;

        let pp = PedersenCommitment::<G>::setup(NUM_WITNESS, &());
        let shape = R1CSShape::<G>::new(NUM_CONSTRAINTS, NUM_WITNESS, NUM_PUBLIC, &a, &b, &c)?;

        let X = to_field_elements::<G>(&[1, 35]);
        let W = to_field_elements::<G>(&[3, 9, 27, 30]);
        let commitment_W = PedersenCommitment::<G>::commit(&pp, &W);

        let U2 = R1CSInstance::<G, PedersenCommitment<G>>::new(&shape, &commitment_W, &X)?;
        let W2 = R1CSWitness::<G>::new(&shape, &W)?;

        let U1 = RelaxedR1CSInstance::<G, PedersenCommitment<G>>::from(&U2);
        let W1 = RelaxedR1CSWitness::<G>::from_r1cs_witness(&shape, &W2);

        let (T, commitment_T) = commit_T(&shape, &pp, &U1, &W1, &U2, &W2)?;
        let folded_instance = U1.fold(&U2, &commitment_T, &r)?;

        // Compute resulting witness.
        let W: Vec<_> =
            W1.W.iter()
                .zip(&W2.W)
                .map(|(w1, w2)| *w1 + r * w2)
                .collect();
        let E: Vec<_> = T.iter().map(|t| r * t).collect();

        let witness = RelaxedR1CSWitness::<G> { W, E };

        shape.is_relaxed_satisfied(&folded_instance, &witness, &pp)?;
        Ok(())
    }

    #[test]
    fn folded_with_relaxed_instance_is_satisfied() -> Result<(), Error> {
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
        const r: Scalar = Scalar::ONE;

        let pp = PedersenCommitment::<G>::setup(NUM_WITNESS, &());
        let shape = R1CSShape::<G>::new(NUM_CONSTRAINTS, NUM_WITNESS, NUM_PUBLIC, &a, &b, &c)?;

        let X = to_field_elements::<G>(&[1, 35]);
        let W = to_field_elements::<G>(&[3, 9, 27, 30]);
        let commitment_W = PedersenCommitment::<G>::commit(&pp, &W);

        let u = R1CSInstance::<G, PedersenCommitment<G>>::new(&shape, &commitment_W, &X)?;
        let w = R1CSWitness::<G>::new(&shape, &W)?;

        let mut U1 = RelaxedR1CSInstance::<G, PedersenCommitment<G>>::from(&u);
        let mut W1 = RelaxedR1CSWitness::<G>::from_r1cs_witness(&shape, &w);

        for _ in 0..3 {
            let (T, comm_T) = commit_T(&shape, &pp, &U1, &W1, &u, &w)?;
            U1 = U1.fold(&u, &comm_T, &r)?;
            W1 = W1.fold(&w, &T, &r)?;
        }

        let U2 = U1.clone();
        let W2 = W1.clone();

        let (T, comm_T) = commit_T_with_relaxed(&shape, &pp, &U1, &W1, &U2, &W2)?;
        let folded_U = U1.fold_with_relaxed(&U2, &comm_T, &r)?;
        let folded_W = W1.fold_with_relaxed(&W2, &T, &r)?;

        shape.is_relaxed_satisfied(&folded_U, &folded_W, &pp)?;
        Ok(())
    }
}
