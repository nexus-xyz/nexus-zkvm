use std::marker::PhantomData;

use ark_ec::pairing::Pairing;
use ark_poly_commit::error::Error;
use ark_spartan::dense_mlpoly::DensePolynomial;
use ark_spartan::polycommitments::zeromorph::Zeromorph as SpartanZM;
use ark_spartan::polycommitments::{error, PCSKeys, PolyCommitmentScheme};
use ark_std::rand::RngCore;

use merlin::Transcript;

use crate::LOG_TARGET;

pub struct Zeromorph<E>(PhantomData<E>);

impl<E> PolyCommitmentScheme<E::G1> for Zeromorph<E>
where
    E: Pairing,
{
    type PolyCommitmentKey = <ark_spartan::polycommitments::zeromorph::Zeromorph<E> as PolyCommitmentScheme<E::G1>>::PolyCommitmentKey;

    type EvalVerifierKey = <ark_spartan::polycommitments::zeromorph::Zeromorph<E> as PolyCommitmentScheme<E::G1>>::EvalVerifierKey;

    type Commitment = <ark_spartan::polycommitments::zeromorph::Zeromorph<E> as PolyCommitmentScheme<E::G1>>::Commitment;

    type SRS =
        <ark_spartan::polycommitments::zeromorph::Zeromorph<E> as PolyCommitmentScheme<E::G1>>::SRS;

    type PolyCommitmentProof = <ark_spartan::polycommitments::zeromorph::Zeromorph<E> as PolyCommitmentScheme<E::G1>>::PolyCommitmentProof;

    fn commit(
        poly: &DensePolynomial<E::ScalarField>,
        ck: &Self::PolyCommitmentKey,
    ) -> Self::Commitment {
        let _span = tracing::debug_span!(
            target: LOG_TARGET,
            "zeromorph::commit",
            poly_size = poly.len(),
        )
        .entered();

        SpartanZM::commit(poly, ck)
    }

    fn prove(
        C: Option<&Self::Commitment>,
        poly: &DensePolynomial<E::ScalarField>,
        r: &[E::ScalarField],
        eval: &E::ScalarField,
        ck: &Self::PolyCommitmentKey,
        transcript: &mut Transcript,
    ) -> Self::PolyCommitmentProof {
        let _span = tracing::debug_span!(
            target: LOG_TARGET,
            "zeromorph::prove",
            poly_size = poly.len(),
        )
        .entered();

        SpartanZM::prove(C, poly, r, eval, ck, transcript)
    }

    fn verify(
        commitment: &Self::Commitment,
        proof: &Self::PolyCommitmentProof,
        ck: &Self::EvalVerifierKey,
        transcript: &mut Transcript,
        r: &[E::ScalarField],
        eval: &E::ScalarField,
    ) -> Result<(), error::PCSError> {
        let _span = tracing::debug_span!(
            target: LOG_TARGET,
            "zeromorph::verify",
        )
        .entered();

        SpartanZM::verify(commitment, proof, ck, transcript, r, eval)
    }

    // Generate a SRS using the provided RNG; this is just for testing purposes, since in reality
    // we need to perform a trusted setup ceremony and then read the SRS from a file.
    fn setup(
        max_poly_vars: usize,
        label: &'static [u8],
        rng: &mut impl RngCore,
    ) -> Result<Self::SRS, Error> {
        let _span = tracing::debug_span!(
            target: LOG_TARGET,
            "zeromorph::setup",
            ?max_poly_vars,
        )
        .entered();

        SpartanZM::setup(max_poly_vars, label, rng)
    }

    fn trim(srs: &Self::SRS, supported_num_vars: usize) -> PCSKeys<E::G1, Self> {
        let _span = tracing::debug_span!(
            target: LOG_TARGET,
            "zeromorph::trim",
            ?supported_num_vars,
        )
        .entered();

        let PCSKeys { ck, vk } = SpartanZM::trim(srs, supported_num_vars);
        PCSKeys { ck, vk }
    }
}
