use std::marker::PhantomData;

use ark_crypto_primitives::sponge::{Absorb, CryptographicSponge, FieldElementSize};
use ark_ec::CurveGroup;
use ark_ff::{PrimeField, ToConstraintField};

use ark_spartan::{polycommitments::PolyCommitmentScheme, dense_mlpoly::EqPolynomial};

use crate::{
    absorb::{AbsorbNonNative, CryptographicSpongeExt},
    ccs::{self, CCSShape, CCSInstance, LCCSInstance, CCSWitness, mle::vec_to_mle},
};

pub const SQUEEZE_ELEMENTS_BIT_SIZE: FieldElementSize = FieldElementSize::Truncated(127);

#[derive(Clone)]
pub struct NIMFSProof<G: CurveGroup, C: PolyCommitmentScheme<G>, RO> {
    pub(crate) c: G::BaseField,
    pub(crate) sumcheck_proof: Proof<G::BaseField>,
    pub(crate) sigmas: Vec<G::ScalarField>,
    pub(crate) thetas: Vec<G::ScalarField>,
    _random_oracle: PhantomData<RO>,
}

impl<G, C, RO> NIMFSProof<G, C, RO>
where
    G: CurveGroup + AbsorbNonNative<G::ScalarField>,
    C: PolyCommitmentScheme<G>,
    G::BaseField: PrimeField + Absorb,
    G::ScalarField: Absorb,
    G::Affine: Absorb + ToConstraintField<G::BaseField>,
    RO: CryptographicSponge,
{
    pub fn prove_as_subprotocol(
        random_oracle: &mut RO,
        shape: &CCSShape<G>,
        (U1, W1): (&LCCSInstance<G, C>, &CCSWitness<G>),
        (U2, W2): (&CCSInstance<G, C>, &CCSWitness<G>),
    ) -> Result<(Self, (LCCSInstance<G, C>, CCSWitness<G>), G::BaseField), ccs::Error> {
        random_oracle.absorb_non_native(&U1);
        random_oracle.absorb_non_native(&U2);

        let s: u32 = (shape.num_constraints - 1).checked_ilog2().unwrap_or(0) + 1;
        let rvec_shape = vec![SQUEEZE_ELEMENTS_BIT_SIZE; s];

        let gamma = random_oracle.squeeze_field_elements_with_sizes(&[SQUEEZE_ELEMENTS_BIT_SIZE])[0];
        let beta  = random_oracle.squeeze_field_elements_with_sizes(&rvec_shape.as_slice());

        let rs = random_oracle.squeeze_field_elements_with_sizes(&rvec_shape.as_slice());

        let z1 = [U1.X.as_slice(), W1.W.as_slice()].concat();
        let z2 = [U2.X.as_slice(), W2.W.as_slice()].concat();

        let g = ListOfProductsOfPolynomials::new(s);

        let eq1  = EqPolynomial::new(U1.rs);
        let eqrs = ark_poly::DenseMultilinearExtension::new(s as usize, eq1.evals);

        (1..=shape.num_matrices).for_each(|j| {
            let summand_Lj = vec![vec_to_mle(shape.Ms[j-1].multiply_vec(&z1).as_slice())];
            summand_Lj.map(ark_poly::DenseMultilinearExtension::from).collect();

            summand_Lj.push(eqrs);
            g.add_product(summand_Lj, gamma.pow(j));
        });

        let eq2 = EqPolynomial::new(beta);
        let eqb = ark_poly::DenseMultilinearExtension::new(s as usize, eq2.evals);

        (0..shape.num_multisets).for_each(|i| {
            let summand_Q = shape.cSs[i].1
                .map(|j| vec_to_mle(shape.Ms[j].multiply_vec(&z1).as_slice()))
                .map(ark_poly::DenseMultilinearExtension::from)
                .collect();

            summand_Q.push(eqb);
            g.add_product(summand_Q, shape.cSs[i].0 * gamma.pow(shape.num_matrices + 1));
        });

        let (sumcheck_proof, _sumcheck_state) = ml_sumcheck::prove_as_subprotocol(random_oracle, g);

        let rho = random_oracle.squeeze_field_elements_with_sizes(&[SQUEEZE_ELEMENTS_BIT_SIZE]);

        let sigmas: Vec<G::ScalarField> = ark_std::cfg_iter!(&shape.Ms)
            .map(|M| vec_to_mle(M.multiply_vec(&z1).as_slice()).evaluate::<G>(rs.as_slice()))
            .collect();

        let thetas: Vec<G::ScalarField> = ark_std::cfg_iter!(&shape.Ms)
            .map(|M| vec_to_mle(M.multiply_vec(&z2).as_slice()).evaluate::<G>(rs.as_slice()))
            .collect();

        let U = U1.fold(U2, &rho, &rs, &sigmas, &thetas)?;
        let W = W1.fold(W2, &rho)?;

        Ok((
            Self {
                c,
                sumcheck_proof,
                sigmas,
                thetas,
                _random_oracle: PhantomData,
            },
            (U, W),
            rho,
        ))
    }

    #[cfg(test)]
    pub fn verify_as_subprotocol(
        &self,
        random_oracle: &mut RO,
        U1: &LCCSInstance<G, C>,
        U2: &CCSInstance<G, C>,
    ) -> Result<LCCSInstance<G, C>, ccs::Error> {
        random_oracle.absorb_non_native(&U1);
        random_oracle.absorb_non_native(&U2);

        let s: u32 = (shape.num_constraints - 1).checked_ilog2().unwrap_or(0) + 1;
        let rvec_shape = vec![SQUEEZE_ELEMENTS_BIT_SIZE; s];

        let gamma = random_oracle.squeeze_field_elements_with_sizes(&[SQUEEZE_ELEMENTS_BIT_SIZE])[0];
        let beta  = random_oracle.squeeze_field_elements_with_sizes(&rvec_shape.as_slice());

        let rs = random_oracle.squeeze_field_elements_with_sizes(&rvec_shape.as_slice());

        let _sumcheck_subclaim = ml_sumcheck::verify_as_subprotocol(random_oracle, XXX, XXX, self.sumcheck_proof)?;

        let eqrs = EqPolynomial::new(U1.rs);
        let e1 = eqrs.evaluate(rs.as_slice());

        let eqb = EqPolynomial::new(beta);
        let e2 = eqb.evaluate(rs.as_slice());

        let c = (1..=shape.num_matrices).map(|j| {
            let inner = (0..shape.num_multisets).map(|i| {
                shape.cSs[i].1.fold(shape.cSs[i].0, |acc, k| acc * self.thetas[k])
            }).sum();

            gamma.pow(j) * e1 * self.sigmas[j] + gamma.pow(j + 1) * e2 * inner
        }).sum();

        if shape.c != c {
            Err();
        }

        let rho = random_oracle.squeeze_field_elements_with_sizes(&[SQUEEZE_ELEMENTS_BIT_SIZE]);

        let U = U.fold(U2, &rho &rs, self.sigmas, self.thetas)?;

        Ok(U)
    }
}
