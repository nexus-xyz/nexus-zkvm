//! Helper definitions for secondary circuit.
//!
//! Relaxed secondary circuit computes `g_out = g1 + r * g2 + r.square() * g3`.

use ark_ec::short_weierstrass::{Projective, SWCurveConfig};
use ark_ff::{AdditiveGroup, PrimeField};
use ark_r1cs_std::{
    alloc::AllocVar,
    boolean::Boolean,
    eq::EqGadget,
    fields::{
        fp::FpVar,
        nonnative::{AllocatedNonNativeFieldVar, NonNativeFieldVar},
        FieldVar,
    },
    groups::{curves::short_weierstrass::ProjectiveVar, CurveVar},
    ToBitsGadget,
};
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
use ark_std::Zero;

use crate::{
    commitment::CommitmentScheme, multifold::nimfs::R1CSInstance, utils::cast_field_element,
};

pub(crate) use super::Proof;
use super::SecondaryCircuit;

/// Leading `Variable::One` + 4 curve points + 1 scalar.
pub(super) const SECONDARY_NUM_IO: usize = 14;

/// Public input of secondary circuit.
pub struct Circuit<G1: SWCurveConfig> {
    pub(crate) g1: Projective<G1>,
    pub(crate) g2: Projective<G1>,
    pub(crate) g3: Projective<G1>,
    pub(crate) g_out: Projective<G1>,

    /// Scalar for elliptic curve points multiplication is part of the public
    /// input and hence should fit into the base field of G1.
    ///
    /// See [`crate::multifold::nimfs::SQUEEZE_ELEMENTS_BIT_SIZE`].
    pub(crate) r: G1::BaseField,
}

impl<G: SWCurveConfig> Default for Circuit<G> {
    fn default() -> Self {
        Self {
            g1: Projective::zero(),
            g2: Projective::zero(),
            g3: Projective::zero(),
            g_out: Projective::zero(),
            r: G::BaseField::ZERO,
        }
    }
}

impl<G: SWCurveConfig> ConstraintSynthesizer<G::BaseField> for Circuit<G>
where
    G::BaseField: PrimeField,
{
    fn generate_constraints(
        self,
        cs: ConstraintSystemRef<G::BaseField>,
    ) -> Result<(), SynthesisError> {
        let g1 = ProjectiveVar::<G, FpVar<G::BaseField>>::new_input(cs.clone(), || Ok(self.g1))?;
        let g2 = ProjectiveVar::<G, FpVar<G::BaseField>>::new_input(cs.clone(), || Ok(self.g2))?;
        let g_out =
            ProjectiveVar::<G, FpVar<G::BaseField>>::new_input(cs.clone(), || Ok(self.g_out))?;
        let r = FpVar::<G::BaseField>::new_input(cs.clone(), || Ok(self.r))?;

        let g3 = ProjectiveVar::<G, FpVar<G::BaseField>>::new_input(cs.clone(), || Ok(self.g3))?;

        let r_bits = r.to_bits_le()?;

        // squaring must be computed in the target field with a modulus different from constraint field,
        // hence allocate non native witness.
        let (r_scalar, r_scalar_bits) = AllocatedNonNativeFieldVar::new_witness_with_le_bits(
            ark_relations::ns!(cs, "r_scalar"),
            || {
                let r_scalar =
                    unsafe { cast_field_element::<G::BaseField, G::ScalarField>(&self.r) };
                Ok(r_scalar)
            },
        )?;

        assert!(r_scalar_bits.len() >= r_bits.len());
        for (r_bit, r_scalar_bit) in r_bits.iter().zip(&r_scalar_bits) {
            r_bit.enforce_equal(r_scalar_bit)?;
        }
        for r_scalar_bit in r_scalar_bits.iter().skip(r_bits.len()) {
            r_scalar_bit.enforce_equal(&Boolean::FALSE)?;
        }

        // TODO: computing bits is redundant as it's already done during limbs reduction, requires a patch.
        let r_square_bits = NonNativeFieldVar::Var(r_scalar).square()?.to_bits_le()?;

        let out = g1 + g2.scalar_mul_le(r_bits.iter())? + g3.scalar_mul_le(r_square_bits.iter())?;
        out.enforce_equal(&g_out)?;

        Ok(())
    }
}

impl<G1> SecondaryCircuit<G1> for Circuit<G1>
where
    G1: SWCurveConfig,
    G1::BaseField: PrimeField,
{
    const NUM_IO: usize = SECONDARY_NUM_IO;
}

impl<G2, C2> R1CSInstance<G2, C2>
where
    G2: SWCurveConfig,
    C2: CommitmentScheme<Projective<G2>, Commitment = Projective<G2>>,
{
    #[cfg(test)]
    pub(crate) fn parse_relaxed_secondary_io<G1>(&self) -> Option<Circuit<G1>>
    where
        G2::BaseField: PrimeField,
        G1: SWCurveConfig<BaseField = G2::ScalarField, ScalarField = G2::BaseField>,
    {
        let mut X = &self.X[1..];

        let g1 = parse_projective!(X);
        let g2 = parse_projective!(X);
        let g_out = parse_projective!(X);

        let r = *X.get(0)?;
        let mut X = &X[1..];
        let g3 = parse_projective!(X);
        let _ = X;

        Some(Circuit {
            g1,
            g2,
            g3,
            g_out,
            r,
        })
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
    fn parse_synthesized() {
        let shape = Circuit::<PallasConfig>::setup_shape::<VestaConfig>().unwrap();
        let mut rng = ark_std::test_rng();
        let g1 = Projective::rand(&mut rng);
        let g2 = Projective::rand(&mut rng);
        let g3 = Projective::rand(&mut rng);

        let val = u64::rand(&mut rng);
        let r = <Fq as PrimeField>::BigInt::from(val).into();
        let r_scalar = unsafe { cast_field_element::<Fq, Fr>(&r) };
        let g_out = g1 + g2 * r_scalar + g3 * r_scalar.square();

        let pp = PedersenCommitment::<ark_vesta::Projective>::setup(shape.num_vars);
        let (U, _) = Circuit::<PallasConfig>::synthesize::<
            VestaConfig,
            PedersenCommitment<ark_vesta::Projective>,
        >(
            Circuit {
                g1,
                g2,
                g3,
                g_out,
                r,
            },
            &pp,
        )
        .unwrap();

        let pub_io = U.parse_relaxed_secondary_io::<PallasConfig>().unwrap();

        assert_eq!(pub_io.g1, g1);
        assert_eq!(pub_io.g2, g2);
        assert_eq!(pub_io.g3, g3);
        assert_eq!(pub_io.g_out, g_out);
        assert_eq!(pub_io.r, r);
    }
}
