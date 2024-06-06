use std::fs::File;
use zstd::stream::{Decoder, Encoder};

use ark_ff::PrimeField;
use ark_ec::short_weierstrass::{Projective, SWCurveConfig};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_crypto_primitives::sponge::{Absorb, CryptographicSponge};
use nexus_nova::StepCircuit;
use nexus_nova::commitment::CommitmentScheme;
use nexus_nova::nova::pcd::{compression::{SNARK, PolyVectorCommitment, SNARKKey as SpartanKey}, PublicParams as ComPP};
use spartan::polycommitments::PolyCommitmentScheme;

use crate::prover::nova::error::*;
use crate::prover::nova::pp::load_pp;
use crate::prover::nova::srs::load_srs;
use crate::prover::nova::LOG_TARGET;

pub fn gen_key<G1, G2, C1, C2, RO, SC>(
    pp: &ComPP<G1, G2, PolyVectorCommitment<Projective<G1>, C1>, C2, RO, SC>,
    srs: &C1::SRS,
) -> Result<SpartanKey<Projective<G1>, C1>, ProofError>
where
    G1: SWCurveConfig,
    G2: SWCurveConfig<BaseField = G1::ScalarField, ScalarField = G1::BaseField>,
    G1::BaseField: PrimeField + Absorb,
    G2::BaseField: PrimeField + Absorb,
    C1: PolyCommitmentScheme<Projective<G1>>,
    C1::Commitment: Copy + From<Projective<G1>> + Into<Projective<G1>>,
    C2: CommitmentScheme<Projective<G2>>,
    RO: CryptographicSponge + Sync + Send,
    RO::Config: CanonicalSerialize + CanonicalDeserialize + Sync,
    SC: StepCircuit<G1::ScalarField>,
{
    let key = SNARK::setup(pp, srs)?;
    Ok(key)
}

pub fn save_key<G1, C1>(
    key: SpartanKey<Projective<G1>, C1>,
    file: &str
) -> Result<(), ProofError>
where
    G1: SWCurveConfig,
    C1: PolyCommitmentScheme<Projective<G1>>,
{
    let f = File::create(file)?;
    let mut enc = Encoder::new(&f, 0)?;
    key.serialize_compressed(&mut enc)?;
    enc.finish()?;
    f.sync_all()?;
    Ok(())
}

pub fn load_key<G1, C1>(
    file: &str
) -> Result<SpartanKey<Projective<G1>, C1>, ProofError>
where
    G1: SWCurveConfig,
    C1: PolyCommitmentScheme<Projective<G1>>,
{
    let f = File::open(file)?;
    let mut dec = Decoder::new(&f)?;
    let key = SpartanKey::deserialize_compressed_unchecked(&mut dec)?;
    Ok(key)
}

pub fn gen_key_to_file<G1, G2, C1, C2, RO, SC>(
    pp: &ComPP<G1, G2, PolyVectorCommitment<Projective<G1>, C1>, C2, RO, SC>,
    srs: &C1::SRS,
    key_file: &str,
) -> Result<SpartanKey<Projective<G1>, C1>, ProofError>
where
    G1: SWCurveConfig,
    G2: SWCurveConfig<BaseField = G1::ScalarField, ScalarField = G1::BaseField>,
    G1::BaseField: PrimeField + Absorb,
    G2::BaseField: PrimeField + Absorb,
    C1: PolyCommitmentScheme<Projective<G1>>,
    C1::Commitment: Copy + From<Projective<G1>> + Into<Projective<G1>>,
    C2: CommitmentScheme<Projective<G2>>,
    RO: CryptographicSponge + Sync + Send,
    RO::Config: CanonicalSerialize + CanonicalDeserialize + Sync,
    SC: StepCircuit<G1::ScalarField>,
{
    let key: SpartanKey<Projective<G1>, C1> = gen_key(&pp, &srs)?;
    save_key(key, key_file)
}
