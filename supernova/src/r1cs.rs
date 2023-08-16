use ark_crypto_primitives::sponge::Absorb;
use ark_ec::{CurveGroup, Group};
use ark_ff::{Field, PrimeField};
use ark_std::Zero;

use super::{commitment::CommitmentScheme, utils};

/// (row_idx, column_idx, value).
///
/// Nova paper assumes constraint matrices to be of a square size, however
/// this limitation can safely be ignored.
pub type SparseMatrix<Scalar> = Vec<(usize, usize, Scalar)>;
pub type SparseMatrixRef<'a, Scalar> = &'a [(usize, usize, Scalar)];

#[derive(Debug)]
pub enum Error {
    ConstraintNumberMismatch,
    InputLengthMismatch,
    OddInputLength,
    InvalidWitnessLength,
    InvalidInputLength,

    NotSatisfied,
}

/// A type that holds the shape of the R1CS matrices
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct R1CSShape<G: Group> {
    /// Number of constraints.
    ///
    /// `m` in the Nova paper.
    num_constraints: usize,
    /// Witness length.
    ///
    /// `m - l - 1` in the Nova paper.
    num_vars: usize,
    /// Length of the public input `X`. It is expected to have a leading
    /// `ScalarField::ONE` element, thus this field must be non-zero.
    ///
    /// `l + 1`, w.r.t. the Nova paper.
    num_io: usize,
    A: SparseMatrix<G::ScalarField>,
    B: SparseMatrix<G::ScalarField>,
    C: SparseMatrix<G::ScalarField>,
}

impl<G: Group> R1CSShape<G> {
    fn validate(
        num_constraints: usize,
        num_vars: usize,
        num_io: usize,
        M: SparseMatrixRef<'_, G::ScalarField>,
    ) -> Result<(), Error> {
        for (row, column, _value) in M {
            if *row >= num_constraints {
                return Err(Error::ConstraintNumberMismatch);
            }
            if *column > num_io + num_vars {
                return Err(Error::InputLengthMismatch);
            }
        }

        Ok(())
    }

    /// Create an object of type `R1CSShape` from the explicitly specified R1CS matrices
    pub fn new(
        num_constraints: usize,
        num_vars: usize,
        num_io: usize,
        A: SparseMatrixRef<'_, G::ScalarField>,
        B: SparseMatrixRef<'_, G::ScalarField>,
        C: SparseMatrixRef<'_, G::ScalarField>,
    ) -> Result<R1CSShape<G>, Error> {
        if num_io == 0 {
            return Err(Error::InvalidInputLength);
        }
        // We require the number of public inputs/outputs to be even
        #[cfg(not(test))]
        if num_io % 2 != 0 {
            return Err(Error::OddInputLength);
        }

        Self::validate(num_constraints, num_vars, num_io, A)?;
        Self::validate(num_constraints, num_vars, num_io, B)?;
        Self::validate(num_constraints, num_vars, num_io, C)?;

        Ok(Self {
            num_constraints,
            num_vars,
            num_io,
            A: A.into(),
            B: B.into(),
            C: C.into(),
        })
    }

    fn sparse_dot(
        &self,
        M: SparseMatrixRef<'_, G::ScalarField>,
        z: &[G::ScalarField],
    ) -> Result<Vec<G::ScalarField>, Error> {
        if z.len() != self.num_io + self.num_vars {
            return Err(Error::InvalidWitnessLength);
        }

        let Mz = M
            .iter()
            .map(|(row, column, value)| (row, *value * z[*column]))
            .fold(
                vec![<G::ScalarField as Zero>::zero(); self.num_constraints],
                |mut Mz, (row, product)| {
                    Mz[*row] += product;
                    Mz
                },
            );

        Ok(Mz)
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

        let Az = self.sparse_dot(&self.A, &z)?;
        let Bz = self.sparse_dot(&self.B, &z)?;
        let Cz = self.sparse_dot(&self.C, &z)?;

        if (0..self.num_constraints).any(|idx| Az[idx] * Bz[idx] != Cz[idx]) {
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

        let Az = self.sparse_dot(&self.A, &z)?;
        let Bz = self.sparse_dot(&self.B, &z)?;
        let Cz = self.sparse_dot(&self.C, &z)?;
        let u = U.X[0];

        if (0..self.num_constraints).any(|idx| Az[idx] * Bz[idx] != u * Cz[idx] + W.E[idx]) {
            return Err(Error::NotSatisfied);
        }

        let commitment_W = C::commit(pp, &W.W);
        let commitment_E = C::commit(pp, &W.E);

        if U.commitment_W != commitment_W || U.commitment_E != commitment_E {
            return Err(Error::NotSatisfied);
        }

        Ok(())
    }
}

/// A type that holds a witness for a given R1CS instance.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct R1CSWitness<G: Group> {
    W: Vec<G::ScalarField>,
}

/// A type that holds an R1CS instance.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct R1CSInstance<G: Group, C: CommitmentScheme<G>> {
    /// Commitment to witness.
    pub(crate) commitment_W: C::Commitment,
    /// X is assumed to start with a `ScalarField::ONE`.
    pub(crate) X: Vec<G::ScalarField>,
}

impl<G, C> Absorb for R1CSInstance<G, C>
where
    G: CurveGroup,
    G::BaseField: PrimeField + Absorb,
    G::ScalarField: Absorb,
    G::Affine: Absorb,
    C: CommitmentScheme<G, Commitment = G>,
{
    fn to_sponge_bytes(&self, _: &mut Vec<u8>) {
        unreachable!()
    }

    fn to_sponge_field_elements<F: PrimeField>(&self, dest: &mut Vec<F>) {
        self.commitment_W
            .into_affine()
            .to_sponge_field_elements(dest);

        for x in &self.X {
            let x_base = utils::scalar_to_base::<G>(x);
            x_base.to_sponge_field_elements(dest);
        }
    }
}

impl<G: Group> R1CSWitness<G> {
    /// A method to create a witness object using a vector of scalars.
    pub fn new(shape: &R1CSShape<G>, W: &[G::ScalarField]) -> Result<Self, Error> {
        if shape.num_vars != W.len() {
            Err(Error::InvalidWitnessLength)
        } else {
            Ok(Self { W: W.to_owned() })
        }
    }

    /// Commits to the witness using the supplied generators
    pub fn commit<C: CommitmentScheme<G>>(&self, pp: &C::PP) -> C::Commitment {
        C::commit(pp, &self.W)
    }
}

impl<G: Group, C: CommitmentScheme<G>> R1CSInstance<G, C> {
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
#[derive(Default, Clone, Debug, PartialEq, Eq)]
pub struct RelaxedR1CSWitness<G: Group> {
    W: Vec<G::ScalarField>,
    E: Vec<G::ScalarField>,
}

/// A type that holds a Relaxed R1CS instance.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RelaxedR1CSInstance<G: Group, C: CommitmentScheme<G>> {
    pub(crate) commitment_W: C::Commitment,
    pub(crate) commitment_E: C::Commitment,
    /// X is assumed to start with `u`.
    pub(crate) X: Vec<G::ScalarField>,
}

impl<G, C> Absorb for RelaxedR1CSInstance<G, C>
where
    G: CurveGroup,
    G::BaseField: PrimeField + Absorb,
    G::ScalarField: Absorb,
    G::Affine: Absorb,
    C: CommitmentScheme<G, Commitment = G>,
{
    fn to_sponge_bytes(&self, _: &mut Vec<u8>) {
        unreachable!()
    }

    fn to_sponge_field_elements<F: PrimeField>(&self, dest: &mut Vec<F>) {
        self.commitment_W
            .into_affine()
            .to_sponge_field_elements(dest);
        self.commitment_E
            .into_affine()
            .to_sponge_field_elements(dest);

        for x in &self.X {
            let x_base = utils::scalar_to_base::<G>(x);
            x_base.to_sponge_field_elements(dest);
        }
    }
}

impl<G: Group, C: CommitmentScheme<G>> From<&R1CSInstance<G, C>> for RelaxedR1CSInstance<G, C> {
    fn from(instance: &R1CSInstance<G, C>) -> Self {
        Self {
            commitment_W: instance.commitment_W,
            commitment_E: C::Commitment::default(),
            X: instance.X.clone(),
        }
    }
}

impl<G: Group> RelaxedR1CSWitness<G> {
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
            E: vec![<G::ScalarField as Field>::ZERO; shape.num_constraints],
        }
    }

    /// Commits to the witness using the supplied generators
    pub fn commit<C: CommitmentScheme<G>>(&self, ck: &C::PP) -> (C::Commitment, C::Commitment) {
        (C::commit(ck, &self.W), C::commit(ck, &self.E))
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

        let W: Vec<G::ScalarField> = W1.iter().zip(W2).map(|(a, b)| *a + *r * *b).collect();
        // Note that W2 is not relaxed, thus E2 = 0.
        let E: Vec<G::ScalarField> = E1.iter().zip(T).map(|(a, b)| *a + *r * *b).collect();
        Ok(Self { W, E })
    }
}

impl<G: Group, C: CommitmentScheme<G>> RelaxedR1CSInstance<G, C> {
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

        let X: Vec<G::ScalarField> = X1.iter().zip(X2).map(|(a, b)| *a + *r * *b).collect();
        let commitment_W = comm_W1 + *comm_W2 * *r;
        // Note that U2 is not relaxed, thus E2 = 0 and u2 = 1.
        let commitment_E = comm_E1 + *comm_T * *r;

        Ok(Self {
            commitment_W,
            commitment_E,
            X,
        })
    }
}

/// A method to compute a commitment to the cross-term `T` given a
/// Relaxed R1CS instance-witness pair and **not relaxed** R1CS instance-witness pair.
pub fn commit_T<G: Group, C: CommitmentScheme<G>>(
    shape: &R1CSShape<G>,
    pp: &C::PP,
    U1: &RelaxedR1CSInstance<G, C>,
    W1: &RelaxedR1CSWitness<G>,
    U2: &R1CSInstance<G, C>,
    W2: &R1CSWitness<G>,
) -> Result<(Vec<G::ScalarField>, C::Commitment), Error> {
    let z1 = [&U1.X, &W1.W[..]].concat();

    let Az1 = shape.sparse_dot(&shape.A, &z1)?;
    let Bz1 = shape.sparse_dot(&shape.B, &z1)?;
    let Cz1 = shape.sparse_dot(&shape.C, &z1)?;

    let z2 = [&U2.X, &W2.W[..]].concat();

    let Az2 = shape.sparse_dot(&shape.A, &z2)?;
    let Bz2 = shape.sparse_dot(&shape.B, &z2)?;
    let Cz2 = shape.sparse_dot(&shape.C, &z2)?;

    // Circle-product.
    let Az1_Bz2: Vec<G::ScalarField> = Az1.iter().zip(&Bz2).map(|(&a, &b)| a * b).collect();
    let Az2_Bz1: Vec<G::ScalarField> = Az2.iter().zip(&Bz1).map(|(&a, &b)| a * b).collect();

    // Scalar product.
    // u2 = 1 since U2 is non-relaxed instance, thus no multiplication required for Cz1.
    let u1 = U1.X[0];
    let u1_Cz2: Vec<G::ScalarField> = Cz2.into_iter().map(|cz2| u1 * cz2).collect();

    // Compute cross-term.
    let mut T = Vec::with_capacity(Az1_Bz2.len());
    for i in 0..Az1_Bz2.len() {
        let t_i = Az1_Bz2[i] + Az2_Bz1[i] - u1_Cz2[i] - Cz1[i];
        T.push(t_i);
    }

    let comm_T = C::commit(pp, &T);

    Ok((T, comm_T))
}

#[cfg(test)]
mod tests {
    #![allow(non_upper_case_globals)]

    use super::*;
    use crate::pedersen::PedersenCommitment;

    use ark_test_curves::bls12_381::{Fr as Scalar, G1Projective as G};
    use assert_matches::assert_matches;

    fn to_field_sparse<G: Group>(matrix: &[&[u64]]) -> SparseMatrix<G::ScalarField> {
        let mut sparse = SparseMatrix::new();

        for i in 0..matrix.len() {
            for j in 0..matrix[i].len() {
                let value = matrix[i][j];
                if value == 0 {
                    continue;
                }

                let big_int = <G::ScalarField as PrimeField>::BigInt::from(value);
                sparse.push((i, j, G::ScalarField::from(big_int)));
            }
        }

        sparse
    }

    fn to_field_elements<G: Group>(x: &[u64]) -> Vec<G::ScalarField> {
        x.iter()
            .map(|x_i| {
                let big_int = <G::ScalarField as PrimeField>::BigInt::from(*x_i);
                G::ScalarField::from(big_int)
            })
            .collect()
    }

    #[test]
    fn invalid_input() {
        #[rustfmt::skip]
        let (A, B, C) = {
            let A: &[&[u64]] = &[
                &[1, 2, 3],
                &[3, 4, 5],
                &[6, 7, 8],
            ];
            let B = A.clone();
            let C = A.clone();
            (
                to_field_sparse::<G>(A),
                to_field_sparse::<G>(B),
                to_field_sparse::<G>(C),
            )
        };

        assert_matches!(
            R1CSShape::<G>::new(2, 2, 2, &A, &B, &C),
            Err(Error::ConstraintNumberMismatch)
        );
        assert_matches!(
            R1CSShape::<G>::new(3, 0, 1, &A, &B, &C),
            Err(Error::InputLengthMismatch)
        );
    }

    #[test]
    fn zero_instance_is_satisfied() {
        #[rustfmt::skip]
        let (A, B, C) = {
            let A: &[&[u64]] = &[
                &[1, 2, 3],
                &[3, 4, 5],
                &[6, 7, 8],
            ];
            let B = A.clone();
            let C = A.clone();
            (
                to_field_sparse::<G>(A),
                to_field_sparse::<G>(B),
                to_field_sparse::<G>(C),
            )
        };

        const NUM_CONSTRAINTS: usize = 3;
        const NUM_WITNESS: usize = 1;
        const NUM_PUBLIC: usize = 2;

        let pp = PedersenCommitment::<G>::setup(NUM_WITNESS);

        let shape = R1CSShape::<G>::new(NUM_CONSTRAINTS, NUM_WITNESS, NUM_PUBLIC, &A, &B, &C)
            .expect("shape is valid");
        let instance = RelaxedR1CSInstance::<G, PedersenCommitment<G>>::new(&shape);
        let witness = RelaxedR1CSWitness::<G>::zero(&shape);

        shape
            .is_relaxed_satisfied(&instance, &witness, &pp)
            .expect("zero instance is satisfied");
    }

    #[test]
    fn is_satisfied() {
        // Example from Vitalik's blog for equation x**3 + x + 5 == 35.
        // Note that our implementation shuffles columns such that witness
        // comes first.
        let (A, B, C) = {
            let A: &[&[u64]] = &[
                &[0, 0, 1, 0, 0, 0],
                &[0, 0, 0, 1, 0, 0],
                &[0, 0, 1, 0, 1, 0],
                &[5, 0, 0, 0, 0, 1],
            ];
            let B: &[&[u64]] = &[
                &[0, 0, 1, 0, 0, 0],
                &[0, 0, 1, 0, 0, 0],
                &[1, 0, 0, 0, 0, 0],
                &[1, 0, 0, 0, 0, 0],
            ];
            let C: &[&[u64]] = &[
                &[0, 0, 0, 1, 0, 0],
                &[0, 0, 0, 0, 1, 0],
                &[0, 0, 0, 0, 0, 1],
                &[0, 1, 0, 0, 0, 0],
            ];
            (
                to_field_sparse::<G>(A),
                to_field_sparse::<G>(B),
                to_field_sparse::<G>(C),
            )
        };

        const NUM_CONSTRAINTS: usize = 4;
        const NUM_WITNESS: usize = 4;
        const NUM_PUBLIC: usize = 2;

        let pp = PedersenCommitment::<G>::setup(NUM_WITNESS);
        let shape = R1CSShape::<G>::new(NUM_CONSTRAINTS, NUM_WITNESS, NUM_PUBLIC, &A, &B, &C)
            .expect("shape is valid");
        let X = to_field_elements::<G>(&[1, 35]);
        let W = to_field_elements::<G>(&[3, 9, 27, 30]);
        let commitment_W = PedersenCommitment::<G>::commit(&pp, &W);

        let instance = R1CSInstance::<G, PedersenCommitment<G>>::new(&shape, &commitment_W, &X)
            .expect("instance is valid");
        let witness = R1CSWitness::<G>::new(&shape, &W).expect("witness shape is valid");

        shape
            .is_satisfied(&instance, &witness, &pp)
            .expect("instance must be satisfied");

        // Change commitment.
        let invalid_commitment = commitment_W.double();
        let instance =
            R1CSInstance::<G, PedersenCommitment<G>>::new(&shape, &invalid_commitment, &X)
                .expect("instance is valid");
        assert_matches!(
            shape.is_satisfied(&instance, &witness, &pp),
            Err(Error::NotSatisfied)
        );

        // Provide invalid witness.
        let invalid_W = to_field_elements::<G>(&[4, 9, 27, 30]);
        let commitment_invalid_W = PedersenCommitment::<G>::commit(&pp, &W);
        let instance =
            R1CSInstance::<G, PedersenCommitment<G>>::new(&shape, &commitment_invalid_W, &X)
                .expect("instance is valid");
        let invalid_witness =
            R1CSWitness::<G>::new(&shape, &invalid_W).expect("witness shape is valid");
        assert_matches!(
            shape.is_satisfied(&instance, &invalid_witness, &pp),
            Err(Error::NotSatisfied)
        );

        // Provide invalid public input.
        let invalid_X = to_field_elements::<G>(&[1, 36]);
        let instance =
            R1CSInstance::<G, PedersenCommitment<G>>::new(&shape, &commitment_W, &invalid_X)
                .expect("instance is valid");
        assert_matches!(
            shape.is_satisfied(&instance, &witness, &pp),
            Err(Error::NotSatisfied)
        );
    }

    #[test]
    fn relaxed_from_r1cs_is_satisfied() {
        // Convert previous test to relaxed instance and verify it's satisfied.
        // Essentially, a simple test for u = 1 and E = 0.
        let (A, B, C) = {
            let A: &[&[u64]] = &[
                &[0, 0, 1, 0, 0, 0],
                &[0, 0, 0, 1, 0, 0],
                &[0, 0, 1, 0, 1, 0],
                &[5, 0, 0, 0, 0, 1],
            ];
            let B: &[&[u64]] = &[
                &[0, 0, 1, 0, 0, 0],
                &[0, 0, 1, 0, 0, 0],
                &[1, 0, 0, 0, 0, 0],
                &[1, 0, 0, 0, 0, 0],
            ];
            let C: &[&[u64]] = &[
                &[0, 0, 0, 1, 0, 0],
                &[0, 0, 0, 0, 1, 0],
                &[0, 0, 0, 0, 0, 1],
                &[0, 1, 0, 0, 0, 0],
            ];
            (
                to_field_sparse::<G>(A),
                to_field_sparse::<G>(B),
                to_field_sparse::<G>(C),
            )
        };

        const NUM_CONSTRAINTS: usize = 4;
        const NUM_WITNESS: usize = 4;
        const NUM_PUBLIC: usize = 2;

        let pp = PedersenCommitment::<G>::setup(NUM_WITNESS);
        let shape = R1CSShape::<G>::new(NUM_CONSTRAINTS, NUM_WITNESS, NUM_PUBLIC, &A, &B, &C)
            .expect("shape is valid");
        let X = to_field_elements::<G>(&[1, 35]);
        let W = to_field_elements::<G>(&[3, 9, 27, 30]);
        let commitment_W = PedersenCommitment::<G>::commit(&pp, &W);

        let instance = R1CSInstance::<G, PedersenCommitment<G>>::new(&shape, &commitment_W, &X)
            .expect("instance is valid");
        let witness = R1CSWitness::<G>::new(&shape, &W).expect("witness shape is valid");

        let relaxed_instance = RelaxedR1CSInstance::<G, PedersenCommitment<G>>::from(&instance);
        let relaxed_witness = RelaxedR1CSWitness::<G>::from_r1cs_witness(&shape, &witness);

        shape
            .is_relaxed_satisfied(&relaxed_instance, &relaxed_witness, &pp)
            .expect("relaxed instance is satisfied");
    }

    #[test]
    fn folded_instance_is_satisfied() {
        // Finally, fold two instances together and verify that resulting relaxed
        // instance is satisfied.
        let (A, B, C) = {
            let A: &[&[u64]] = &[
                &[0, 0, 1, 0, 0, 0],
                &[0, 0, 0, 1, 0, 0],
                &[0, 0, 1, 0, 1, 0],
                &[5, 0, 0, 0, 0, 1],
            ];
            let B: &[&[u64]] = &[
                &[0, 0, 1, 0, 0, 0],
                &[0, 0, 1, 0, 0, 0],
                &[1, 0, 0, 0, 0, 0],
                &[1, 0, 0, 0, 0, 0],
            ];
            let C: &[&[u64]] = &[
                &[0, 0, 0, 1, 0, 0],
                &[0, 0, 0, 0, 1, 0],
                &[0, 0, 0, 0, 0, 1],
                &[0, 1, 0, 0, 0, 0],
            ];
            (
                to_field_sparse::<G>(A),
                to_field_sparse::<G>(B),
                to_field_sparse::<G>(C),
            )
        };

        const NUM_CONSTRAINTS: usize = 4;
        const NUM_WITNESS: usize = 4;
        const NUM_PUBLIC: usize = 2;
        const r: Scalar = <Scalar as Field>::ONE;

        let pp = PedersenCommitment::<G>::setup(NUM_WITNESS);
        let shape = R1CSShape::<G>::new(NUM_CONSTRAINTS, NUM_WITNESS, NUM_PUBLIC, &A, &B, &C)
            .expect("shape is valid");
        let X = to_field_elements::<G>(&[1, 35]);
        let W = to_field_elements::<G>(&[3, 9, 27, 30]);
        let commitment_W = PedersenCommitment::<G>::commit(&pp, &W);

        let U2 = R1CSInstance::<G, PedersenCommitment<G>>::new(&shape, &commitment_W, &X)
            .expect("instance is valid");
        let W2 = R1CSWitness::<G>::new(&shape, &W).expect("witness shape is valid");

        let U1 = RelaxedR1CSInstance::<G, PedersenCommitment<G>>::from(&U2);
        let W1 = RelaxedR1CSWitness::<G>::from_r1cs_witness(&shape, &W2);

        let (T, commitment_T) = commit_T(&shape, &pp, &U1, &W1, &U2, &W2).expect("shape is valid");
        let folded_instance = U1.fold(&U2, &commitment_T, &r).expect("shapes are valid");

        // Compute resulting witness.
        let W: Vec<_> =
            W1.W.iter()
                .zip(&W2.W)
                .map(|(w1, w2)| *w1 + r * w2)
                .collect();
        let E: Vec<_> = T.iter().map(|t| r * t).collect();

        let witness = RelaxedR1CSWitness::<G> { W, E };

        shape
            .is_relaxed_satisfied(&folded_instance, &witness, &pp)
            .expect("relaxed instance is satisfied");
    }
}
