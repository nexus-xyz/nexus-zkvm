use std::marker::PhantomData;

use ark_crypto_primitives::sponge::{Absorb, CryptographicSponge, FieldElementSize};
use ark_ec::CurveGroup;
use ark_ff::{Field, PrimeField, ToConstraintField};
use ark_spartan::{polycommitments::PolyCommitmentScheme, dense_mlpoly::EqPolynomial};

use ark_std::rc::Rc;

use crate::{
    absorb::{AbsorbNonNative, CryptographicSpongeExt},
    ccs::{self, CCSShape, CCSInstance, LCCSInstance, CCSWitness, mle::vec_to_mle},
};

use super::ml_sumcheck::{self, MLSumcheck, ListOfProductsOfPolynomials};

#[cfg(feature = "parallel")]
use rayon::iter::{ParallelIterator, IntoParallelRefIterator};

pub const SQUEEZE_ELEMENTS_BIT_SIZE: FieldElementSize = FieldElementSize::Truncated(127);

pub struct NIMFSProof<G: CurveGroup, RO> {
    pub(crate) sumcheck_proof: ml_sumcheck::Proof<G::ScalarField>,
    pub(crate) sigmas: Vec<G::ScalarField>,
    pub(crate) thetas: Vec<G::ScalarField>,
    _random_oracle: PhantomData<RO>,
}

impl<G: CurveGroup, RO> Clone for NIMFSProof<G, RO> {
    fn clone(&self) -> Self {
        Self {
            sumcheck_proof: self.sumcheck_proof.clone(),
            sigmas: self.sigmas.clone(),
            thetas: self.thetas.clone(),
            _random_oracle: self._random_oracle,
        }
    }
}

impl<G, RO> NIMFSProof<G, RO>
where
    G: CurveGroup + AbsorbNonNative<G::ScalarField>,
    G::BaseField: PrimeField + Absorb,
    G::ScalarField: Absorb,
    G::Affine: Absorb + ToConstraintField<G::BaseField>,
    RO: CryptographicSponge,
{
    pub fn prove_as_subprotocol<C: PolyCommitmentScheme<G>>(
        random_oracle: &mut RO,
        shape: &CCSShape<G>,
        (U1, W1): (&LCCSInstance<G, C>, &CCSWitness<G>),
        (U2, W2): (&CCSInstance<G, C>, &CCSWitness<G>),
    ) -> Result<(Self, (LCCSInstance<G, C>, CCSWitness<G>), G::ScalarField), ccs::Error> {
        random_oracle.absorb_non_native(&U1);
        random_oracle.absorb_non_native(&U2);

        let s: usize = ((shape.num_constraints - 1).checked_ilog2().unwrap_or(0) + 1) as usize;
        let rvec_shape = vec![SQUEEZE_ELEMENTS_BIT_SIZE; s];

        let gamma: G::ScalarField = random_oracle.squeeze_field_elements_with_sizes(&[SQUEEZE_ELEMENTS_BIT_SIZE])[0];
        let beta = random_oracle.squeeze_field_elements_with_sizes(&rvec_shape.as_slice());

        let rs = random_oracle.squeeze_field_elements_with_sizes(&rvec_shape.as_slice());

        let z1 = [U1.X.as_slice(), W1.W.as_slice()].concat();
        let z2 = [U2.X.as_slice(), W2.W.as_slice()].concat();

        let mut g = ListOfProductsOfPolynomials::new(s);

        let eq1  = EqPolynomial::new(U1.rs.clone());
        let eqrs = ark_poly::DenseMultilinearExtension::from_evaluations_vec(s, eq1.evals());

        (1..=shape.num_matrices).for_each(|j| {
            let mle = vec_to_mle(shape.Ms[j - 1].multiply_vec(&z1).as_slice());
            let mut summand_Lj = vec![ark_poly::DenseMultilinearExtension::from_evaluations_vec(s, mle.vec().clone())];

            summand_Lj.push(eqrs.clone());
            g.add_product(summand_Lj.iter().map(|s| Rc::new(s.clone())), gamma.pow(&[j as u64]));
        });

        let eq2 = EqPolynomial::new(beta);
        let eqb = ark_poly::DenseMultilinearExtension::from_evaluations_vec(s, eq2.evals());

        (0..shape.num_multisets).for_each(|i| {
            let mut summand_Q = shape.cSs[i].1.iter()
                .map(|j| vec_to_mle(shape.Ms[*j].multiply_vec(&z1).as_slice()))
                .map(|mle| ark_poly::DenseMultilinearExtension::from_evaluations_vec(s, mle.vec().clone()))
                .collect::<Vec<ark_poly::DenseMultilinearExtension<G::ScalarField>>>();

            summand_Q.push(eqb.clone());
            g.add_product(summand_Q.iter().map(|s| Rc::new(s.clone())), shape.cSs[i].0 * gamma.pow(&[(shape.num_matrices + 1) as u64]));
        });

        let (sumcheck_proof, _sumcheck_state) = MLSumcheck::prove_as_subprotocol(random_oracle, &g);

        let rho = random_oracle.squeeze_field_elements_with_sizes(&[SQUEEZE_ELEMENTS_BIT_SIZE])[0];

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
    pub fn verify_as_subprotocol<C: PolyCommitmentScheme<G>>(
        &self,
        random_oracle: &mut RO,
        U1: &LCCSInstance<G, C>,
        U2: &CCSInstance<G, C>,
    ) -> Result<LCCSInstance<G, C>, ccs::Error> {
        random_oracle.absorb_non_native(&U1);
        random_oracle.absorb_non_native(&U2);

        let s: usize = ((shape.num_constraints - 1).checked_ilog2().unwrap_or(0) + 1) as usize;
        let rvec_shape = vec![SQUEEZE_ELEMENTS_BIT_SIZE; s];

        let gamma = random_oracle.squeeze_field_elements_with_sizes(&[SQUEEZE_ELEMENTS_BIT_SIZE])[0];
        let beta  = random_oracle.squeeze_field_elements_with_sizes(&rvec_shape.as_slice());

        let rs = random_oracle.squeeze_field_elements_with_sizes(&rvec_shape.as_slice());

        let sumcheck_subclaim = MLSumcheck::verify_as_subprotocol(random_oracle, XXX, XXX, self.sumcheck_proof)?;

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

        if sumcheck_subclaim != c {
            Err();
        }

        let rho = random_oracle.squeeze_field_elements_with_sizes(&[SQUEEZE_ELEMENTS_BIT_SIZE])[0];

        let U = U.fold(U2, &rho &rs, self.sigmas, self.thetas)?;

        Ok(U)
    }
}
