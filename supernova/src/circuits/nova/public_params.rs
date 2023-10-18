use std::marker::PhantomData;

use ark_crypto_primitives::sponge::{CryptographicSponge, FieldElementSize};
use ark_ec::short_weierstrass::{Projective, SWCurveConfig};
use ark_ff::{AdditiveGroup, BigInteger, PrimeField};
use ark_serialize::{
    CanonicalDeserialize, CanonicalSerialize, CanonicalSerializeHashExt, SerializationError,
};

use super::Error;
use crate::{
    commitment::CommitmentScheme,
    multifold::nimfs::{R1CSShape, SQUEEZE_ELEMENTS_BIT_SIZE},
    utils,
};

pub struct PublicParams<G1, G2, C1, C2, RO, SC, SP>
where
    G1: SWCurveConfig,
    G2: SWCurveConfig,
    C1: CommitmentScheme<Projective<G1>>,
    C2: CommitmentScheme<Projective<G2>>,
    RO: CryptographicSponge,
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

impl<G1, G2, C1, C2, RO, SC, SP> CanonicalSerialize for PublicParams<G1, G2, C1, C2, RO, SC, SP>
where
    G1: SWCurveConfig,
    G2: SWCurveConfig,
    C1: CommitmentScheme<Projective<G1>>,
    C2: CommitmentScheme<Projective<G2>>,
    RO: CryptographicSponge,
    RO::Config: CanonicalSerialize,
{
    fn serialize_with_mode<W: ark_serialize::Write>(
        &self,
        mut writer: W,
        compress: ark_serialize::Compress,
    ) -> Result<(), ark_serialize::SerializationError> {
        self.ro_config.serialize_with_mode(&mut writer, compress)?;
        self.shape.serialize_with_mode(&mut writer, compress)?;
        self.shape_secondary
            .serialize_with_mode(&mut writer, compress)?;
        self.pp.serialize_with_mode(&mut writer, compress)?;
        self.pp_secondary
            .serialize_with_mode(&mut writer, compress)?;
        self.digest.serialize_with_mode(&mut writer, compress)?;

        Ok(())
    }

    fn serialized_size(&self, compress: ark_serialize::Compress) -> usize {
        self.ro_config.serialized_size(compress)
            + self.shape.serialized_size(compress)
            + self.shape_secondary.serialized_size(compress)
            + self.pp.serialized_size(compress)
            + self.pp_secondary.serialized_size(compress)
            + self.digest.serialized_size(compress)
    }
}

impl<G1, G2, C1, C2, RO, SC, SP> CanonicalDeserialize for PublicParams<G1, G2, C1, C2, RO, SC, SP>
where
    G1: SWCurveConfig,
    G2: SWCurveConfig,
    C1: CommitmentScheme<Projective<G1>>,
    C2: CommitmentScheme<Projective<G2>>,
    RO: CryptographicSponge,
    RO::Config: CanonicalDeserialize,
    SC: Sync,
    SP: Sync,
{
    fn deserialize_with_mode<R: ark_serialize::Read>(
        mut reader: R,
        compress: ark_serialize::Compress,
        validate: ark_serialize::Validate,
    ) -> Result<Self, SerializationError> {
        let ro_config = RO::Config::deserialize_with_mode(&mut reader, compress, validate)?;
        let shape = R1CSShape::deserialize_with_mode(&mut reader, compress, validate)?;
        let shape_secondary = R1CSShape::deserialize_with_mode(&mut reader, compress, validate)?;
        let pp = C1::PP::deserialize_with_mode(&mut reader, compress, validate)?;
        let pp_secondary = C2::PP::deserialize_with_mode(&mut reader, compress, validate)?;
        let digest = G1::ScalarField::deserialize_with_mode(&mut reader, compress, validate)?;

        Ok(Self {
            ro_config,
            shape,
            shape_secondary,
            pp,
            pp_secondary,
            digest,
            _step_circuit: PhantomData,
            _setup_params: PhantomData,
        })
    }
}

impl<G1, G2, C1, C2, RO, SC, SP> ark_serialize::Valid for PublicParams<G1, G2, C1, C2, RO, SC, SP>
where
    G1: SWCurveConfig,
    G2: SWCurveConfig,
    C1: CommitmentScheme<Projective<G1>>,
    C2: CommitmentScheme<Projective<G2>>,
    RO: CryptographicSponge,
    RO::Config: CanonicalDeserialize,
    SC: Sync,
    SP: Sync,
{
    fn check(&self) -> Result<(), SerializationError> {
        self.ro_config.check()?;
        self.shape.check()?;
        self.shape_secondary.check()?;
        self.pp.check()?;
        self.pp_secondary.check()?;
        self.digest.check()?;

        Ok(())
    }
}

impl<G1, G2, C1, C2, RO, SC, SP> PublicParams<G1, G2, C1, C2, RO, SC, SP>
where
    G1: SWCurveConfig,
    G2: SWCurveConfig,
    C1: CommitmentScheme<Projective<G1>>,
    C2: CommitmentScheme<Projective<G2>>,
    RO: CryptographicSponge,
    RO::Config: CanonicalSerialize,
    SP: SetupParams<G1, G2, C1, C2, RO, SC>,
{
    pub fn setup(ro_config: RO::Config, step_circuit: &SC) -> Result<Self, Error> {
        SP::setup(ro_config, step_circuit)
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

pub trait SetupParams<G1, G2, C1, C2, RO, SC>: Sized
where
    G1: SWCurveConfig,
    G2: SWCurveConfig,
    C1: CommitmentScheme<Projective<G1>>,
    C2: CommitmentScheme<Projective<G2>>,
    RO: CryptographicSponge,
{
    fn setup(
        ro_config: RO::Config,
        step_circuit: &SC,
    ) -> Result<PublicParams<G1, G2, C1, C2, RO, SC, Self>, Error>;
}
