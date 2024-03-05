//! An extension for arkworks interface for cryptographic sponge.
//!
//! Poseidon cryptographic sponge from arkworks is defined over some specified field, and current implementation may
//! either silently discard non-native field element absorbed into the sponge, or panic. Thus, care must be taken
//! when choosing between [`Absorb`] and [`AbsorbNonNative`], because both would compile.
//!
//! Let G1, G2 denote a cycle of elliptic curves: G1 = E(F2) with scalar field F1, G2 = E(F1) with scalar field F2.
//! If r1cs input consists of elements from F1, then its commitment is a point on the curve G1 -- elements from F2.
//! Usually, F1 is chosen as a field the sponge operates with, hence commitments from G1 should be absorbed with
//! non-native implementation, whereas commitments from G2 should be absorbed natively.
//!
//! The algorithm for conversion between F1 and F2 should be a unique mapping, e.g. BigNat representation.

#![deny(unsafe_code)]

use ark_crypto_primitives::sponge::{self as ark_sponge, Absorb};
use ark_ec::{
    short_weierstrass::{Projective, SWCurveConfig},
    CurveGroup,
};
use ark_ff::PrimeField;
use ark_spartan::polycommitments::{PolyCommitmentScheme, PolyCommitmentTrait};

use super::{
    commitment::{Commitment, CommitmentScheme},
    utils::cast_field_element_unique,
};
use crate::ccs::{CCSInstance, LCCSInstance};
use crate::r1cs::{R1CSInstance, RelaxedR1CSInstance};

/// An interface to objects that can be absorbed by [`ark_sponge::CryptographicSponge`] defined
/// over F1, but cannot be natively represented as an array of elements of F1.
pub trait AbsorbNonNative<F1: PrimeField + Absorb> {
    /// Converts self into an array of elements from non-native field F1 and appends
    /// it to `dest`.
    fn to_non_native_field_elements(&self, dest: &mut Vec<F1>);

    /// Converts self into an array of elements from non-native field F1 and appends
    /// it into an array of elements from F2 using [`Absorb`].
    fn to_sponge_field_elements<F2: PrimeField>(&self, dest: &mut Vec<F2>) {
        let mut _dest = Vec::new();
        self.to_non_native_field_elements(&mut _dest);

        Absorb::to_sponge_field_elements(&_dest, dest);
    }
}

/// Extension of [`ark_sponge::CryptographicSponge`] for non-native objects.
pub trait CryptographicSpongeExt: ark_sponge::CryptographicSponge {
    /// Absorb an input using non-native implementation.
    fn absorb_non_native<F>(&mut self, input: &impl AbsorbNonNative<F>)
    where
        F: PrimeField + Absorb;
}

impl<S> CryptographicSpongeExt for S
where
    S: ark_sponge::CryptographicSponge,
{
    fn absorb_non_native<F>(&mut self, input: &impl AbsorbNonNative<F>)
    where
        F: PrimeField + Absorb,
    {
        let mut dest = Vec::new();
        input.to_non_native_field_elements(&mut dest);

        self.absorb(&dest);
    }
}

/// Unique affine coordinates are non-native elements, boolean `infinity` is converted to `ZERO` or `ONE`.
///
/// The conversion to affine point must be consistent with in-circuit implementation.
impl<P: SWCurveConfig> AbsorbNonNative<P::ScalarField> for Projective<P>
where
    P::BaseField: PrimeField,
    P::ScalarField: Absorb,
{
    fn to_non_native_field_elements(&self, dest: &mut Vec<P::ScalarField>) {
        let affine = <Self as CurveGroup>::into_affine(*self);

        let x = cast_field_element_unique::<P::BaseField, P::ScalarField>(&affine.x);
        let y = cast_field_element_unique::<P::BaseField, P::ScalarField>(&affine.y);
        let infinity = P::ScalarField::from(affine.infinity);
        Absorb::to_sponge_field_elements(&[&x[..], &y[..], &[infinity]].concat(), dest);
    }
}

/// Since r1cs instance contains both elements from F1 and F2, it's a matter of notion what to call
/// native absorb implementation: either it has to cast commitments coordinates or the input `X`.
///
/// Assume that native implementation is the one that doesn't have to cast public input.
impl<G, C> AbsorbNonNative<G::BaseField> for R1CSInstance<G, C>
where
    G: CurveGroup,
    G::BaseField: PrimeField + Absorb,
    G::Affine: Absorb,
    C: CommitmentScheme<G>,
{
    fn to_non_native_field_elements(&self, dest: &mut Vec<G::BaseField>) {
        Absorb::to_sponge_field_elements(&self.commitment_W.into_affine(), dest);

        for x in &self.X[1..] {
            let x_base = cast_field_element_unique::<G::ScalarField, G::BaseField>(x);
            Absorb::to_sponge_field_elements(&x_base, dest);
        }
    }
}

/// See the above comment for [`R1CSInstance`] non-native absorb implementation.
impl<G, C> AbsorbNonNative<G::BaseField> for RelaxedR1CSInstance<G, C>
where
    G: CurveGroup,
    G::BaseField: PrimeField + Absorb,
    G::Affine: Absorb,
    C: CommitmentScheme<G>,
{
    fn to_non_native_field_elements(&self, dest: &mut Vec<G::BaseField>) {
        Absorb::to_sponge_field_elements(&self.commitment_W.into_affine(), dest);
        Absorb::to_sponge_field_elements(&self.commitment_E.into_affine(), dest);

        for x in &self.X {
            let x_base = cast_field_element_unique::<G::ScalarField, G::BaseField>(x);
            Absorb::to_sponge_field_elements(&x_base, dest);
        }
    }
}

/// See the above comment for [`R1CSInstance`] non-native absorb implementation.
impl<G, C> AbsorbNonNative<G::BaseField> for CCSInstance<G, C>
where
    G: CurveGroup,
    G::BaseField: PrimeField + Absorb,
    G::Affine: Absorb,
    C: PolyCommitmentScheme<G>,
{
    fn to_non_native_field_elements(&self, dest: &mut Vec<G::BaseField>) {
        self.commitment_W
            .clone()
            .into_affine()
            .iter()
            .for_each(|c| Absorb::to_sponge_field_elements(c, dest));

        for x in &self.X[1..] {
            let x_base = cast_field_element_unique::<G::ScalarField, G::BaseField>(x);
            Absorb::to_sponge_field_elements(&x_base, dest);
        }
    }
}

/// See the above comment for [`R1CSInstance`] non-native absorb implementation.
impl<G, C> AbsorbNonNative<G::BaseField> for LCCSInstance<G, C>
where
    G: CurveGroup,
    G::BaseField: PrimeField + Absorb,
    G::Affine: Absorb,
    C: PolyCommitmentScheme<G>,
{
    fn to_non_native_field_elements(&self, dest: &mut Vec<G::BaseField>) {
        self.commitment_W
            .clone()
            .into_affine()
            .iter()
            .for_each(|c| Absorb::to_sponge_field_elements(c, dest));

        for x in &self.X {
            let x_base = cast_field_element_unique::<G::ScalarField, G::BaseField>(x);
            Absorb::to_sponge_field_elements(&x_base, dest);
        }

        for r in &self.rs {
            let r_base = cast_field_element_unique::<G::ScalarField, G::BaseField>(r);
            Absorb::to_sponge_field_elements(&r_base, dest);
        }

        for v in &self.vs {
            let v_base = cast_field_element_unique::<G::ScalarField, G::BaseField>(v);
            Absorb::to_sponge_field_elements(&v_base, dest);
        }
    }
}

impl<F: PrimeField + Absorb, A: AbsorbNonNative<F>> AbsorbNonNative<F> for &A {
    fn to_non_native_field_elements(&self, dest: &mut Vec<F>) {
        (*self).to_non_native_field_elements(dest)
    }
}
