use std::marker::PhantomData;

use ark_crypto_primitives::sponge::{CryptographicSponge, FieldElementSize};
use ark_ec::short_weierstrass::{Projective, SWCurveConfig};
use ark_ff::{AdditiveGroup, BigInteger, PrimeField};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, CanonicalSerializeHashExt};

use super::{Error, StepCircuit};
use crate::{
    commitment::CommitmentScheme,
    folding::nova::cyclefold::nimfs::{R1CSShape, SQUEEZE_ELEMENTS_BIT_SIZE},
    pedersen::{PedersenCommitment, SVDWMap},
    utils,
};

#[derive(CanonicalSerialize, CanonicalDeserialize)]
pub struct PublicParams<G1, G2, C1, C2, RO, SC, SP>
where
    G1: SWCurveConfig,
    G2: SWCurveConfig,
    C1: CommitmentScheme<Projective<G1>>,
    C2: CommitmentScheme<Projective<G2>>,
    RO: CryptographicSponge + Sync,
    RO::Config: CanonicalSerialize + CanonicalDeserialize + Sync,
    SC: StepCircuit<G1::ScalarField>,
    SP: Send + Sync,
{
    pub ro_config: RO::Config,
    pub shape: R1CSShape<G1>,
    pub shape_secondary: R1CSShape<G2>,
    pub pp: C1::PP,
    pub pp_secondary: C2::PP,
    pub digest: G1::ScalarField,

    pub _step_circuit: PhantomData<SC>,
    pub _setup_params: PhantomData<SP>,
}

impl<G1, G2, C1, C2, RO, SC, SP> PublicParams<G1, G2, C1, C2, RO, SC, SP>
where
    G1: SWCurveConfig,
    G2: SWCurveConfig,
    C1: CommitmentScheme<Projective<G1>>,
    C2: CommitmentScheme<Projective<G2>>,
    RO: CryptographicSponge + Sync,
    RO::Config: CanonicalSerialize + CanonicalDeserialize + Sync,
    SC: StepCircuit<G1::ScalarField>,
    SP: SetupParams<G1, G2, C1, C2, RO, SC>,
{
    pub fn setup(
        ro_config: RO::Config,
        step_circuit: &SC,
        aux1: impl CKSetupFn<G1, C1>,
        aux2: impl CKSetupFn<G2, C2>,
    ) -> Result<Self, Error> {
        SP::setup(ro_config, step_circuit, aux1, aux2)
    }

    /// Returns first [`SQUEEZE_ELEMENTS_BIT_SIZE`] bits of public parameters sha3 hash reinterpreted
    /// as scalar field element in little-endian order.
    pub(super) fn hash(&self) -> G1::ScalarField {
        assert_eq!(self.digest, G1::ScalarField::ZERO);

        let num_bits = FieldElementSize::sum::<G1::ScalarField>(&[SQUEEZE_ELEMENTS_BIT_SIZE]);
        assert!(num_bits < G1::ScalarField::MODULUS_BIT_SIZE as usize);

        let hash = <Self as CanonicalSerializeHashExt>::hash::<sha3::Sha3_256>(self);
        let bits: Vec<bool> = utils::iter_bits_le(&hash).take(num_bits).collect();

        let digest = <G1::ScalarField as PrimeField>::BigInt::from_bits_le(&bits);
        G1::ScalarField::from(digest)
    }
}

pub trait SetupParams<G1, G2, C1, C2, RO, SC>: Send + Sync + Sized
where
    G1: SWCurveConfig,
    G2: SWCurveConfig,
    C1: CommitmentScheme<Projective<G1>>,
    C2: CommitmentScheme<Projective<G2>>,
    RO: CryptographicSponge + Sync,
    RO::Config: CanonicalSerialize + CanonicalDeserialize + Sync,
    SC: StepCircuit<G1::ScalarField>,
{
    fn setup(
        ro_config: RO::Config,
        step_circuit: &SC,
        aux1: impl CKSetupFn<G1, C1>,
        aux2: impl CKSetupFn<G2, C2>,
    ) -> Result<PublicParams<G1, G2, C1, C2, RO, SC, Self>, Error>;
}

/// Fn object used to compute auxiliary params for the commitment scheme from R1CS matrices.
pub trait CKSetupFn<G: SWCurveConfig, C: CommitmentScheme<Projective<G>>>:
    FnOnce(&R1CSShape<G>) -> Box<C::SetupAux>
{
}

impl<T, G: SWCurveConfig, C: CommitmentScheme<Projective<G>>> CKSetupFn<G, C> for T where
    T: FnOnce(&R1CSShape<G>) -> Box<C::SetupAux>
{
}

/// Serialize R1CS matrices and use it as input for xof hasher.
pub fn pedersen_setup<G>(
    shape: &R1CSShape<G>,
) -> Box<<PedersenCommitment<G> as CommitmentScheme<Projective<G>>>::SetupAux>
where
    G: SWCurveConfig + SVDWMap,
    G::BaseField: PrimeField,
{
    let mut buf = vec![];
    shape
        .serialize_compressed(&mut buf)
        .expect("serialize failed");

    buf.into_boxed_slice()
}

/// Explicitly provide ck params by value.
pub fn setup_by_value_fn<G, C, T>(aux: T) -> impl CKSetupFn<G, C>
where
    G: SWCurveConfig,
    C: CommitmentScheme<Projective<G>, SetupAux = T>,
{
    move |_shape: &R1CSShape<G>| Box::new(aux)
}
