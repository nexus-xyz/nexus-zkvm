use std::fs::File;
use zstd::stream::{Decoder, Encoder};

pub use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use nexus_nova::nova::pcd::compression::SNARK;

use super::error::*;
use super::types::*;
use super::LOG_TARGET;

pub fn gen_key(pp: &ComPP, srs: &SRS) -> Result<SpartanKey, ProofError> {
    tracing::info!(
        target: LOG_TARGET,
        "Generating Spartan key parameters",
    );

    let key = SNARK::setup(pp, srs)?;
    Ok(key)
}

pub fn save_key(key: SpartanKey, file: &str) -> Result<(), ProofError> {
    tracing::info!(
        target: LOG_TARGET,
        pp_file =?file,
        "Saving Spartan key parameters",
    );

    let f = File::create(file)?;
    let mut enc = Encoder::new(&f, 0)?;
    key.serialize_compressed(&mut enc)?;
    enc.finish()?;
    f.sync_all()?;
    Ok(())
}

pub fn load_key(file: &str) -> Result<SpartanKey, ProofError> {
    tracing::info!(
        target: LOG_TARGET,
        pp_file =?file,
        "Loading Spartan key parameters",
    );

    let f = File::open(file)?;
    let mut dec = Decoder::new(&f)?;
    let key = SpartanKey::deserialize_compressed_unchecked(&mut dec)?;
    Ok(key)
}

pub fn gen_key_to_file(pp: &ComPP, srs: &SRS, key_file: &str) -> Result<(), ProofError> {
    let key: SpartanKey = gen_key(pp, srs)?;
    save_key(key, key_file)
}
