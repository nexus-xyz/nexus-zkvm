use std::fs::File;
use zstd::stream::{Encoder, Decoder};

pub use ark_serialize::{CanonicalSerialize, CanonicalDeserialize};
use supernova::nova::pcd::compression::SNARK;

use crate::types::*;
use crate::error::*;

pub fn gen_key(pp: &ComPP, srs: &SRS) -> Result<SpartanKey, ProofError> {
    //todo: handle error better
    Ok(SNARK::setup(pp, srs).unwrap())
}

pub fn save_key(key: SpartanKey, file: &str) -> Result<(), ProofError> {
    let f = File::create(file)?;
    let mut enc = Encoder::new(&f, 0)?;
    key.serialize_compressed(&mut enc)?;
    enc.finish()?;
    f.sync_all()?;
    Ok(())
}

pub fn load_key(file: &str) -> Result<SpartanKey, ProofError> {
    let f = File::open(file)?;
    let mut dec = Decoder::new(&f)?;
    let key = SpartanKey::deserialize_compressed_unchecked(&mut dec)?;
    Ok(key)
}

pub fn gen_key_to_file(pp: &ComPP, srs: &SRS, key_file: &str) -> Result<(), ProofError> {
    println!("Generating Spartan key to {key_file}...");
    let key: SpartanKey = gen_key(pp, srs)?;
    save_key(key, key_file)
}

pub fn gen_or_load_key(
    gen: bool,
    key_file: &str,
    pp: &ComPP,
    srs: &SRS,
) -> Result<SpartanKey, ProofError> {
    let t = std::time::Instant::now();
    let key: SpartanKey = if gen {
        println!("Generating Spartan key...");
        gen_key(pp, srs)?
    } else {
        println!("Loading Spartan key from {key_file}...");
        load_key(key_file)?
    };
    println!("Got Spartan key in {:?}", t.elapsed());
    Ok(key)
}
