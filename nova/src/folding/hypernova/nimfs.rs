#![allow(clippy::upper_case_acronyms)]

use std::marker::PhantomData;

use ark_crypto_primitives::sponge::{Absorb, CryptographicSponge, FieldElementSize};
use ark_ec::CurveGroup;
use ark_ff::{Field, PrimeField, ToConstraintField};
use ark_poly::Polynomial;
use ark_spartan::{dense_mlpoly::EqPolynomial, polycommitments::PolyCommitmentScheme};

use ark_std::{fmt::Display, rc::Rc};

use crate::{
    absorb::AbsorbNonNative,
    ccs::{self, mle::vec_to_ark_mle, CCSInstance, CCSShape, CCSWitness, LCCSInstance},
    safe_loglike,
    utils::cast_field_element,
};

use super::ml_sumcheck::{self, ListOfProductsOfPolynomials, MLSumcheck};

#[cfg(feature = "parallel")]
use rayon::iter::{IntoParallelRefIterator, ParallelIterator};

pub const SQUEEZE_ELEMENTS_BIT_SIZE: FieldElementSize = FieldElementSize::Truncated(127);

#[derive(Debug, Clone, Copy)]
pub enum Error {
    CCS(ccs::Error),
    SumCheck(ml_sumcheck::Error),
    InconsistentSubclaim,
}

impl From<ccs::Error> for Error {
    fn from(err: ccs::Error) -> Error {
        Error::CCS(err)
    }
}

impl From<ml_sumcheck::Error> for Error {
    fn from(err: ml_sumcheck::Error) -> Error {
        Error::SumCheck(err)
    }
}

impl Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::CCS(error) => write!(f, "{}", error),
            Self::SumCheck(error) => write!(f, "{}", error),
            Self::InconsistentSubclaim => write!(f, "inconsistent subclaim"),
        }
    }
}

impl ark_std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::CCS(error) => error.source(),
            Self::SumCheck(error) => error.source(),
            Self::InconsistentSubclaim => None,
        }
    }
}

pub struct NIMFSProof<G: CurveGroup, RO> {
    pub(crate) sumcheck_proof: ml_sumcheck::Proof<G::ScalarField>,
    pub(crate) poly_info: ml_sumcheck::PolynomialInfo,
    pub(crate) sigmas: Vec<G::ScalarField>,
    pub(crate) thetas: Vec<G::ScalarField>,
    pub(crate) _random_oracle: PhantomData<RO>,
}

impl<G: CurveGroup, RO> Clone for NIMFSProof<G, RO> {
    fn clone(&self) -> Self {
        Self {
            sumcheck_proof: self.sumcheck_proof.clone(),
            poly_info: self.poly_info.clone(),
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
        vk: &G::ScalarField,
        shape: &CCSShape<G>,
        (U1, W1): (&LCCSInstance<G, C>, &CCSWitness<G>),
        (U2, W2): (&CCSInstance<G, C>, &CCSWitness<G>),
    ) -> Result<(Self, (LCCSInstance<G, C>, CCSWitness<G>), G::BaseField), Error> {
        random_oracle.absorb(&vk);
        random_oracle.absorb(&U1);
        random_oracle.absorb(&U2);

        let rho: G::BaseField =
            random_oracle.squeeze_field_elements_with_sizes(&[SQUEEZE_ELEMENTS_BIT_SIZE])[0];
        let rho_scalar: G::ScalarField =
            unsafe { cast_field_element::<G::BaseField, G::ScalarField>(&rho) };

        let s: usize = safe_loglike!(shape.num_constraints) as usize;

        let gamma: G::ScalarField = random_oracle.squeeze_field_elements(1)[0];
        let beta = random_oracle.squeeze_field_elements(s);

        let z1 = [U1.X.as_slice(), W1.W.as_slice()].concat();
        let z2 = [U2.X.as_slice(), W2.W.as_slice()].concat();

        let mut g = ListOfProductsOfPolynomials::new(s);

        let eq1 = EqPolynomial::new(U1.rs.clone());
        let eqrs = vec_to_ark_mle(eq1.evals().as_slice());

        (1..=shape.num_matrices).for_each(|j| {
            let mut summand_L = vec![vec_to_ark_mle(shape.Ms[j - 1].multiply_vec(&z1).as_slice())];

            summand_L.push(eqrs.clone());
            g.add_product(
                summand_L.iter().map(|Lj| Rc::new(Lj.clone())),
                gamma.pow([j as u64]),
            );
        });

        let eq2 = EqPolynomial::new(beta);
        let eqb = vec_to_ark_mle(eq2.evals().as_slice());

        (0..shape.num_multisets).for_each(|i| {
            let mut summand_Q = shape.cSs[i]
                .1
                .iter()
                .map(|j| vec_to_ark_mle(shape.Ms[*j].multiply_vec(&z2).as_slice()))
                .collect::<Vec<ark_poly::DenseMultilinearExtension<G::ScalarField>>>();

            summand_Q.push(eqb.clone());
            g.add_product(
                summand_Q.iter().map(|Qt| Rc::new(Qt.clone())),
                shape.cSs[i].0 * gamma.pow([(shape.num_matrices + 1) as u64]),
            );
        });

        let (sumcheck_proof, sumcheck_state) = MLSumcheck::prove_as_subprotocol(random_oracle, &g);

        let rs_p = sumcheck_state.randomness;

        let sigmas: Vec<G::ScalarField> = ark_std::cfg_iter!(&shape.Ms)
            .map(|M| vec_to_ark_mle(M.multiply_vec(&z1).as_slice()).evaluate(&rs_p))
            .collect();

        let thetas: Vec<G::ScalarField> = ark_std::cfg_iter!(&shape.Ms)
            .map(|M| vec_to_ark_mle(M.multiply_vec(&z2).as_slice()).evaluate(&rs_p))
            .collect();

        let U = U1.fold(U2, &rho_scalar, &rs_p, &sigmas, &thetas)?;
        let W = W1.fold(W2, &rho_scalar)?;

        Ok((
            Self {
                sumcheck_proof,
                poly_info: g.info(),
                sigmas,
                thetas,
                _random_oracle: PhantomData,
            },
            (U, W),
            rho,
        ))
    }

    #[cfg(any(test, feature = "spartan"))]
    pub fn verify_as_subprotocol<C: PolyCommitmentScheme<G>>(
        &self,
        random_oracle: &mut RO,
        vk: &G::ScalarField,
        shape: &CCSShape<G>,
        U1: &LCCSInstance<G, C>,
        U2: &CCSInstance<G, C>,
    ) -> Result<(LCCSInstance<G, C>, G::BaseField), Error> {
        random_oracle.absorb(&vk);
        random_oracle.absorb(&U1);
        random_oracle.absorb(&U2);

        let rho: G::BaseField =
            random_oracle.squeeze_field_elements_with_sizes(&[SQUEEZE_ELEMENTS_BIT_SIZE])[0];
        let rho_scalar: G::ScalarField =
            unsafe { cast_field_element::<G::BaseField, G::ScalarField>(&rho) };

        let s: usize = safe_loglike!(shape.num_constraints) as usize;

        let gamma: G::ScalarField = random_oracle.squeeze_field_elements(1)[0];
        let beta = random_oracle.squeeze_field_elements(s);

        let gamma_powers: Vec<G::ScalarField> = (1..=shape.num_matrices)
            .map(|j| gamma.pow([j as u64]))
            .collect();

        let claimed_sum = gamma_powers
            .iter()
            .zip(U1.vs.iter())
            .map(|(a, b)| *a * b)
            .sum();

        let sumcheck_subclaim = MLSumcheck::verify_as_subprotocol(
            random_oracle,
            &self.poly_info,
            claimed_sum,
            &self.sumcheck_proof,
        )?;

        let rs_p = sumcheck_subclaim.point;

        let eq1 = EqPolynomial::new(U1.rs.clone());
        let eqrs = vec_to_ark_mle(eq1.evals().as_slice());
        let e1 = eqrs.evaluate(&rs_p);

        let eq2 = EqPolynomial::new(beta);
        let eqb = vec_to_ark_mle(eq2.evals().as_slice());
        let e2 = eqb.evaluate(&rs_p);

        let cl: G::ScalarField = gamma_powers
            .iter()
            .zip(self.sigmas.iter())
            .map(|(a, b)| *a * b)
            .sum::<G::ScalarField>()
            * e1;

        let cr: G::ScalarField = (0..shape.num_multisets)
            .map(|i| {
                shape.cSs[i]
                    .1
                    .iter()
                    .fold(shape.cSs[i].0, |acc, j| acc * self.thetas[*j])
            })
            .sum::<G::ScalarField>()
            * gamma.pow([(shape.num_matrices + 1) as u64])
            * e2;

        if sumcheck_subclaim.expected_evaluation != cl + cr {
            return Err(Error::InconsistentSubclaim);
        }

        let U = U1.fold(U2, &rho_scalar, &rs_p, &self.sigmas, &self.thetas)?;

        Ok((U, rho))
    }
}

#[cfg(test)]
pub(crate) mod tests {

    use super::*;

    use crate::poseidon_config;
    use crate::{
        ccs::{mle::vec_to_mle, CCSWitness, LCCSInstance},
        r1cs::tests::to_field_elements,
        test_utils::setup_test_ccs,
        zeromorph::Zeromorph,
    };
    use ark_crypto_primitives::sponge::poseidon::PoseidonSponge;
    use ark_ec::{
        short_weierstrass::{Projective, SWCurveConfig},
        AdditiveGroup,
    };
    use ark_std::{test_rng, UniformRand};
    use ark_test_curves::bls12_381::{g1::Config as G, Bls12_381 as E};

    type Z = Zeromorph<E>;

    #[test]
    fn prove_verify_as_subprotocol() {
        prove_verify_as_subprotocol_with_curve::<G, Z>().unwrap()
    }

    fn prove_verify_as_subprotocol_with_curve<G, C>() -> Result<(), Error>
    where
        G: SWCurveConfig,
        G::BaseField: PrimeField + Absorb,
        G::ScalarField: Absorb,
        C: PolyCommitmentScheme<Projective<G>>,
        C::PolyCommitmentKey: Clone,
    {
        let config = poseidon_config::<G::ScalarField>();

        let mut rng = test_rng();

        let (shape, U2, W2, ck) = setup_test_ccs::<G, C>(3, None, Some(&mut rng));

        let X = to_field_elements::<Projective<G>>((vec![0; shape.num_io]).as_slice());
        let W1 = CCSWitness::zero(&shape);

        let commitment_W = W1.commit::<C>(&ck);

        let s = safe_loglike!(shape.num_constraints);
        let rs: Vec<G::ScalarField> = (0..s).map(|_| G::ScalarField::rand(&mut rng)).collect();

        let z = [X.as_slice(), W1.W.as_slice()].concat();
        let vs: Vec<G::ScalarField> = ark_std::cfg_iter!(&shape.Ms)
            .map(|M| {
                vec_to_mle(M.multiply_vec(&z).as_slice()).evaluate::<Projective<G>>(rs.as_slice())
            })
            .collect();

        let U1 = LCCSInstance::<Projective<G>, C>::new(
            &shape,
            &commitment_W,
            &X,
            rs.as_slice(),
            vs.as_slice(),
        )?;

        let vk = G::ScalarField::ZERO;
        let mut random_oracle = PoseidonSponge::new(&config);

        let (proof, (folded_U, folded_W), _rho) =
            NIMFSProof::<Projective<G>, PoseidonSponge<G::ScalarField>>::prove_as_subprotocol(
                &mut random_oracle,
                &vk,
                &shape,
                (&U1, &W1),
                (&U2, &W2),
            )?;

        let mut random_oracle = PoseidonSponge::new(&config);
        let (v_folded_U, _rho) =
            proof.verify_as_subprotocol(&mut random_oracle, &vk, &shape, &U1, &U2)?;
        assert_eq!(folded_U, v_folded_U);

        shape.is_satisfied_linearized(&folded_U, &folded_W, &ck)?;

        let U1 = folded_U;
        let W1 = folded_W;

        let (_, U2, W2, _) = setup_test_ccs(5, Some(&ck), Some(&mut rng));

        let mut random_oracle = PoseidonSponge::new(&config);
        let (proof, (folded_U, folded_W), _rho) = NIMFSProof::prove_as_subprotocol(
            &mut random_oracle,
            &vk,
            &shape,
            (&U1, &W1),
            (&U2, &W2),
        )?;

        let mut random_oracle = PoseidonSponge::new(&config);
        let (v_folded_U, _rho) =
            proof.verify_as_subprotocol(&mut random_oracle, &vk, &shape, &U1, &U2)?;
        assert_eq!(folded_U, v_folded_U);

        shape.is_satisfied_linearized(&folded_U, &folded_W, &ck)?;

        Ok(())
    }
}
