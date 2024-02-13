//! Helper definitions for secondary circuit.
//!
//! Secondary circuit accepts `g1`, `g2`, `g_out`, `r` (in this exact order) as its public input, where
//! `g1`, `g2`, `g_out` are points on the curve G, `r` is an element from the scalar field, and enforces
//! `g_out = g1 + r * g2`, while having circuit satisfying witness as a trace of this computation.

use ark_ec::short_weierstrass::{Projective, SWCurveConfig};
use ark_ff::{AdditiveGroup, PrimeField};
use ark_r1cs_std::{
    alloc::AllocVar,
    eq::EqGadget,
    fields::fp::FpVar,
    groups::{curves::short_weierstrass::ProjectiveVar, CurveVar},
    ToBitsGadget,
};
use ark_relations::r1cs::{
    ConstraintSynthesizer, ConstraintSystem, ConstraintSystemRef, SynthesisError, SynthesisMode,
};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::Zero;

use crate::commitment::CommitmentScheme;

use super::nimfs::{R1CSInstance, R1CSShape, R1CSWitness};

/// Leading `Variable::One` + 3 curve points + 1 scalar.
const SECONDARY_NUM_IO: usize = 11;

/// Public input of secondary circuit.
pub struct Circuit<G1: SWCurveConfig> {
    pub(crate) g1: Projective<G1>,
    pub(crate) g2: Projective<G1>,
    pub(crate) g_out: Projective<G1>,

    /// Scalar for elliptic curve points multiplication is part of the public
    /// input and hence should fit into the base field of G1.
    ///
    /// See [`super::nimfs::SQUEEZE_ELEMENTS_BIT_SIZE`].
    pub(crate) r: G1::BaseField,
}

impl<G1: SWCurveConfig> Circuit<G1> {
    pub const NUM_IO: usize = SECONDARY_NUM_IO;
}

impl<G: SWCurveConfig> Default for Circuit<G> {
    fn default() -> Self {
        Self {
            g1: Projective::zero(),
            g2: Projective::zero(),
            g_out: Projective::zero(),
            r: G::BaseField::ZERO,
        }
    }
}

impl<G1: SWCurveConfig> ConstraintSynthesizer<G1::BaseField> for Circuit<G1>
where
    G1::BaseField: PrimeField,
{
    fn generate_constraints(
        self,
        cs: ConstraintSystemRef<G1::BaseField>,
    ) -> Result<(), SynthesisError> {
        let g1 = ProjectiveVar::<G1, FpVar<G1::BaseField>>::new_input(cs.clone(), || Ok(self.g1))?;
        let g2 = ProjectiveVar::<G1, FpVar<G1::BaseField>>::new_input(cs.clone(), || Ok(self.g2))?;
        let g_out =
            ProjectiveVar::<G1, FpVar<G1::BaseField>>::new_input(cs.clone(), || Ok(self.g_out))?;

        let r = FpVar::<G1::BaseField>::new_input(cs.clone(), || Ok(self.r))?;
        let r_bits = r.to_bits_le()?;

        let out = g1 + g2.scalar_mul_le(r_bits.iter())?;
        out.enforce_equal(&g_out)?;

        Ok(())
    }
}

/// Setup [`R1CSShape`] for a secondary circuit, defined over `G2::BaseField`.
pub fn setup_shape<G1, G2>() -> Result<R1CSShape<G2>, SynthesisError>
where
    G1: SWCurveConfig,
    G1::BaseField: PrimeField,
    G2: SWCurveConfig<BaseField = G1::ScalarField, ScalarField = G1::BaseField>,
{
    let cs = ConstraintSystem::<G1::BaseField>::new_ref();
    cs.set_mode(SynthesisMode::Setup);

    Circuit::<G1>::default().generate_constraints(cs.clone())?;

    cs.finalize();
    Ok(R1CSShape::from(cs.clone()))
}

/// Synthesize public input and a witness-trace.
pub fn synthesize<G1, G2, C2>(
    circuit: Circuit<G1>,
    pp_secondary: &C2::PP,
) -> Result<(R1CSInstance<G2, C2>, R1CSWitness<G2>), SynthesisError>
where
    G1: SWCurveConfig,
    G1::BaseField: PrimeField,
    G2: SWCurveConfig<BaseField = G1::ScalarField, ScalarField = G1::BaseField>,
    C2: CommitmentScheme<Projective<G2>>,
{
    let cs = ConstraintSystem::<G1::BaseField>::new_ref();
    cs.set_mode(SynthesisMode::Prove {
        construct_matrices: false,
    });

    circuit.generate_constraints(cs.clone())?;

    cs.finalize();
    let cs_borrow = cs.borrow().unwrap();

    let witness = cs_borrow.witness_assignment.clone();
    let pub_io = cs_borrow.instance_assignment.clone();

    let W = R1CSWitness::<G2> { W: witness };

    let commitment_W = W.commit::<C2>(pp_secondary);
    let U = R1CSInstance::<G2, C2> {
        commitment_W,
        X: pub_io,
    };

    Ok((U, W))
}

/// Folding scheme proof for a secondary circuit.
#[derive(CanonicalDeserialize, CanonicalSerialize)]
pub struct Proof<G2: SWCurveConfig, C2: CommitmentScheme<Projective<G2>>> {
    pub(crate) U: R1CSInstance<G2, C2>,
    pub(crate) commitment_T: C2::Commitment,
}

impl<G2, C2> Clone for Proof<G2, C2>
where
    G2: SWCurveConfig,
    C2: CommitmentScheme<Projective<G2>>,
{
    fn clone(&self) -> Self {
        Self {
            U: self.U.clone(),
            commitment_T: self.commitment_T,
        }
    }
}

impl<G2, C2> Default for Proof<G2, C2>
where
    G2: SWCurveConfig,
    C2: CommitmentScheme<Projective<G2>>,
{
    fn default() -> Self {
        let U = R1CSInstance {
            commitment_W: Projective::zero().into(),
            X: vec![G2::ScalarField::ZERO; SECONDARY_NUM_IO],
        };
        Self {
            U,
            commitment_T: Projective::zero().into(),
        }
    }
}
#[cfg(any(test, feature = "spartan"))]
macro_rules! parse_projective {
    ($X:expr) => {
        match &$X[..3] {
            &[x, y, z, ..] => {
                let point = ark_ec::CurveGroup::into_affine(Projective::<G1> { x, y, z });
                if !point.is_on_curve() || !point.is_in_correct_subgroup_assuming_on_curve() {
                    return None;
                }
                $X = &$X[3..];
                point.into()
            }
            _ => return None,
        }
    };
}

impl<G2, C2> R1CSInstance<G2, C2>
where
    G2: SWCurveConfig,
    C2: CommitmentScheme<Projective<G2>>,
{
    #[cfg(any(test, feature = "spartan"))]
    pub(crate) fn parse_secondary_io<G1>(&self) -> Option<Circuit<G1>>
    where
        G2::BaseField: PrimeField,
        G1: SWCurveConfig<BaseField = G2::ScalarField, ScalarField = G2::BaseField>,
    {
        let mut X = &self.X[1..];

        let g1 = parse_projective!(X);
        let g2 = parse_projective!(X);
        let g_out = parse_projective!(X);

        let r = *X.first()?;

        Some(Circuit { g1, g2, g_out, r })
    }
}

#[cfg(test)]
mod tests {
    use crate::{pedersen::PedersenCommitment, utils::cast_field_element};

    use super::*;

    use ark_ff::{Field, PrimeField};
    use ark_pallas::{Fq, Fr, PallasConfig, Projective};
    use ark_std::UniformRand;
    use ark_vesta::VestaConfig;

    #[test]
    fn parse_pub_input() {
        let mut rng = ark_std::test_rng();
        let g1 = Projective::rand(&mut rng);
        let g2 = Projective::rand(&mut rng);

        let val = u64::rand(&mut rng);
        let r = <Fq as PrimeField>::BigInt::from(val).into();
        let r_scalar = unsafe { cast_field_element::<Fq, Fr>(&r) };
        let g_out = g1 + g2 * r_scalar;

        let expected_pub_io = Circuit::<PallasConfig> { g1, g2, g_out, r };
        let X = [
            Fq::ONE,
            g1.x,
            g1.y,
            g1.z,
            g2.x,
            g2.y,
            g2.z,
            g_out.x,
            g_out.y,
            g_out.z,
            unsafe { cast_field_element(&r) },
        ];
        assert_eq!(X.len(), SECONDARY_NUM_IO);
        let r1cs = R1CSInstance::<VestaConfig, PedersenCommitment<ark_vesta::Projective>> {
            commitment_W: Default::default(),
            X: X.into(),
        };

        let pub_io = r1cs.parse_secondary_io().unwrap();
        assert_eq!(pub_io.g1, expected_pub_io.g1);
        assert_eq!(pub_io.g2, expected_pub_io.g2);
        assert_eq!(pub_io.g_out, expected_pub_io.g_out);
        assert_eq!(pub_io.r, expected_pub_io.r);

        // incorrect length
        let _X = &X[..10];
        let r1cs = R1CSInstance::<VestaConfig, PedersenCommitment<ark_vesta::Projective>> {
            commitment_W: Default::default(),
            X: _X.into(),
        };
        assert!(r1cs.parse_secondary_io::<PallasConfig>().is_none());

        // not on curve
        let mut _X = X.to_vec();
        _X[1] -= Fq::ONE;
        let r1cs = R1CSInstance::<VestaConfig, PedersenCommitment<ark_vesta::Projective>> {
            commitment_W: Default::default(),
            X: _X,
        };
        assert!(r1cs.parse_secondary_io::<PallasConfig>().is_none());
    }

    #[test]
    fn parse_synthesized() {
        let shape = setup_shape::<PallasConfig, VestaConfig>().unwrap();
        let mut rng = ark_std::test_rng();
        let g1 = Projective::rand(&mut rng);
        let g2 = Projective::rand(&mut rng);

        let val = u64::rand(&mut rng);
        let r = <Fq as PrimeField>::BigInt::from(val).into();
        let r_scalar = unsafe { cast_field_element::<Fq, Fr>(&r) };
        let g_out = g1 + g2 * r_scalar;

        let pp = PedersenCommitment::<ark_vesta::Projective>::setup(shape.num_vars, &());
        let (U, _) = synthesize::<
            PallasConfig,
            VestaConfig,
            PedersenCommitment<ark_vesta::Projective>,
        >(Circuit { g1, g2, g_out, r }, &pp)
        .unwrap();

        let pub_io = U.parse_secondary_io::<PallasConfig>().unwrap();

        assert_eq!(pub_io.g1, g1);
        assert_eq!(pub_io.g2, g2);
        assert_eq!(pub_io.g_out, g_out);
        assert_eq!(pub_io.r, r);
    }
}
