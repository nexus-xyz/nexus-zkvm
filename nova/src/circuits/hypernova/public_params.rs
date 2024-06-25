use std::marker::PhantomData;

use ark_crypto_primitives::sponge::{CryptographicSponge, FieldElementSize};
use ark_ec::short_weierstrass::{Projective, SWCurveConfig};
use ark_ff::{AdditiveGroup, BigInteger, PrimeField};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, CanonicalSerializeHashExt};
use ark_spartan::polycommitments::PolyCommitmentScheme;

use super::{Error, StepCircuit};
use crate::{
    commitment::CommitmentScheme,
    folding::hypernova::cyclefold::nimfs::{
        CCSShape,
        R1CSShape,
        SQUEEZE_ELEMENTS_BIT_SIZE,
    },
    utils,
};

#[derive(CanonicalSerialize, CanonicalDeserialize)]
pub struct PublicParams<G1, G2, C1, C2, RO, SC, SP>
where
    G1: SWCurveConfig,
    G2: SWCurveConfig,
    C1: PolyCommitmentScheme<Projective<G1>>,
    C2: CommitmentScheme<Projective<G2>>,
    RO: CryptographicSponge + Sync,
    RO::Config: CanonicalSerialize + CanonicalDeserialize + Sync,
    SC: StepCircuit<G1::ScalarField>,
    SP: Send + Sync,
{
    pub ro_config: RO::Config,
    pub shape: CCSShape<G1>,
    pub shape_secondary: R1CSShape<G2>,
    pub ck: C1::PolyCommitmentKey,
    pub pp_secondary: C2::PP,
    pub digest: G1::ScalarField,

    pub _step_circuit: PhantomData<SC>,
    pub _setup_params: PhantomData<SP>,
}

impl<G1, G2, C1, C2, RO, SC, SP> PublicParams<G1, G2, C1, C2, RO, SC, SP>
where
    G1: SWCurveConfig,
    G2: SWCurveConfig,
    C1: PolyCommitmentScheme<Projective<G1>>,
    C2: CommitmentScheme<Projective<G2>>,
    RO: CryptographicSponge + Sync,
    RO::Config: CanonicalSerialize + CanonicalDeserialize + Sync,
    SC: StepCircuit<G1::ScalarField>,
    SP: SetupParams<G1, G2, C1, C2, RO, SC>,
{
    pub fn setup(
        ro_config: RO::Config,
        step_circuit: &SC,
        srs: &C1::SRS,
        aux: &C2::SetupAux,
    ) -> Result<Self, Error> {
        SP::setup(ro_config, step_circuit, srs, aux)
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
    C1: PolyCommitmentScheme<Projective<G1>>,
    C2: CommitmentScheme<Projective<G2>>,
    RO: CryptographicSponge + Sync,
    RO::Config: CanonicalSerialize + CanonicalDeserialize + Sync,
    SC: StepCircuit<G1::ScalarField>,
{
    fn setup(
        ro_config: RO::Config,
        step_circuit: &SC,
        srs: &C1::SRS,
        aux: &C2::SetupAux,
    ) -> Result<PublicParams<G1, G2, C1, C2, RO, SC, Self>, Error>;
}

#[cfg(test)]
mod test {
    use ark_std::test_rng;
    use ark_crypto_primitives::sponge::Absorb;
    use ark_crypto_primitives::sponge::constraints::{CryptographicSpongeVar, SpongeWithGadget};
    use crate::{
        circuits::hypernova::sequential::augmented::{
            HyperNovaAugmentedCircuit,
            HyperNovaConstraintSynthesizer,
        },
        folding::hypernova::cyclefold,
        safe_loglike,
    };

    impl<G1, G2, C1, C2, RO, SC, SP> PublicParams<G1, G2, C1, C2, RO, SC, SP>
    where
        G1: SWCurveConfig,
        G2: SWCurveConfig<BaseField = G1::ScalarField, ScalarField = G1::BaseField>,
        G1::BaseField: PrimeField + Absorb,
        G2::BaseField: PrimeField + Absorb,
        C1: PolyCommitmentScheme<Projective<G1>>,
        C2: CommitmentScheme<Projective<G2>, SetupAux = ()>,
        RO: SpongeWithGadget<G1::ScalarField> + Send + Sync,
        RO::Var: CryptographicSpongeVar<G1::ScalarField, RO, Parameters = RO::Config>,
        RO::Config: CanonicalSerialize + CanonicalDeserialize + Sync,
        SC: StepCircuit<G1::ScalarField>,
        SP: SetupParams<G1, G2, C1, C2, RO, SC>,
    {
        pub fn test_setup(ro_config: RO::Config, step_circuit: &SC) -> Result<Self, Error> {
            let (_, projected_augmented_circuit_size_upper_bound) =
                HyperNovaAugmentedCircuit::<
                        G1,
                    G2,
                    C1,
                    C2,
                    RO,
                    SC,
                    >::project_augmented_circuit_size_upper_bound(step_circuit)?;

            let mut rng = test_rng();
            let max_poly_vars: usize =
                safe_loglike!(projected_augmented_circuit_size_upper_bound) as usize;

            let srs = C1::setup(max_poly_vars, b"test_hypernova_seq_primary_curve", &mut rng)
                .map_err(|_| cyclefold::Error::PolyCommitmentSetup)?;

            SP::setup(ro_config, step_circuit, &srs, &())
        }
    }
}
