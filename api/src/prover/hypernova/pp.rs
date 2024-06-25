use std::fs::File;
use zstd::stream::{Decoder, Encoder};

pub use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};

use crate::prover::nova::circuit::nop_circuit;
use super::error::*;
use super::types::*;
use super::LOG_TARGET;

#[cfg(test)]
pub(crate) fn gen_test_pp(circuit: &SC) -> Result<PP, ProofError> {
    tracing::info!(
        target: LOG_TARGET,
        "Generating public parameters",
    );

    let params = nexus_nova::hypernova::public_params::PublicParams::<G1, G2, C1, C2, RO, SC>::test_setup(ro_config(), circuit)?;

    Ok(params)
}

pub fn gen_pp(circuit: &SC, srs: &C1::SRS, aux: &C2::SetupAux) -> Result<PP, ProofError> {
    tracing::info!(
        target: LOG_TARGET,
        "Generating public parameters",
    );

    Ok(PP::setup(ro_config(), circuit, srs, aux)?)
}

pub fn save_pp(pp: &PP, file: &str) -> Result<(), ProofError> {
    tracing::info!(
        target: LOG_TARGET,
        path = ?file,
        "Saving public parameters",
    );

    let f = File::create(file)?;
    let mut enc = Encoder::new(&f, 0)?;
    pp.serialize_compressed(&mut enc)?;
    enc.finish()?;
    f.sync_all()?;
    Ok(())
}

pub fn load_pp(file: &str) -> Result<PP, ProofError> {
    tracing::info!(
        target: LOG_TARGET,
        path = ?file,
        "Loading public parameters",
    );

    let f = File::open(file)?;
    let mut dec = Decoder::new(&f)?;
    let pp = PP::deserialize_compressed(&mut dec)?;
    Ok(pp)
}

pub fn gen_vm_pp(k: usize, srs: &C1::SRS, aux: &C2::SetupAux) -> Result<PP, ProofError> {
    let tr = nop_circuit(k)?;
    gen_pp(&tr, srs, aux)
}

pub fn show_pp(pp: &PP) {
    tracing::debug!(
        target: LOG_TARGET,
        "Primary circuit {}",
        pp.shape,
    );
    tracing::debug!(
        target: LOG_TARGET,
        "Secondary circuit {}",
        pp.shape_secondary,
    );
}
