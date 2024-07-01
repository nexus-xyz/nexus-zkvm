use std::fs::File;
use zstd::stream::{Decoder, Encoder};

pub use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};

use super::error::*;
use super::types::*;
use super::LOG_TARGET;
use crate::prover::nova::circuit::nop_circuit;

pub fn gen_pp(circuit: &SC, srs: &SRS, aux: &SetupAux) -> Result<PP, ProofError> {
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

pub fn gen_vm_pp(k: usize, srs: &SRS, aux: &SetupAux) -> Result<PP, ProofError> {
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

pub mod test_pp {
    use super::*;

    pub fn gen_test_pp(circuit: &SC) -> Result<PP, ProofError> {
        let params =
            nexus_nova::hypernova::sequential::PublicParams::<G1, G2, C1, C2, RO, SC>::test_setup(
                nexus_nova::poseidon_config(),
                circuit,
            )?;

        Ok(params)
    }

    pub fn gen_vm_test_pp(k: usize) -> Result<PP, ProofError> {
        let tr = nop_circuit(k)?;
        gen_test_pp(&tr)
    }
}
