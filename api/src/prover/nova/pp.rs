use std::fs::File;
use zstd::stream::{Decoder, Encoder};

pub use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};

use super::circuit::nop_circuit;
use super::error::*;
use super::srs::load_srs;
use super::types::*;
use super::LOG_TARGET;

pub fn gen_pp<C, SP>(circuit: &SC, aux: &C::SetupAux) -> Result<PP<C, SP>, ProofError>
where
    C: CommitmentScheme<P1>,
    SP: SetupParams<G1, G2, C, C2, RO, SC>,
{
    tracing::info!(
        target: LOG_TARGET,
        "Generating public parameters",
    );

    Ok(SP::setup(ro_config(), circuit, aux, &())?)
}

pub fn save_pp<C, SP>(pp: PP<C, SP>, file: &str) -> Result<(), ProofError>
where
    C: CommitmentScheme<P1>,
    SC: StepCircuit<F1>,
    SP: SetupParams<G1, G2, C, C2, RO, SC>,
{
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

pub fn load_pp<C, SP>(file: &str) -> Result<PP<C, SP>, ProofError>
where
    C: CommitmentScheme<P1>,
    SC: StepCircuit<F1> + Sync,
    SP: SetupParams<G1, G2, C, C2, RO, SC> + Sync,
{
    tracing::info!(
        target: LOG_TARGET,
        path = ?file,
        "Loading public parameters",
    );

    let f = File::open(file)?;
    let mut dec = Decoder::new(&f)?;
    let pp = PP::<C, SP>::deserialize_compressed(&mut dec)?;
    Ok(pp)
}

pub fn gen_vm_pp<C, SP>(k: usize, aux: &C::SetupAux) -> Result<PP<C, SP>, ProofError>
where
    SP: SetupParams<G1, G2, C, C2, RO, SC>,
    C: CommitmentScheme<P1>,
{
    let tr = nop_circuit(k)?;
    gen_pp(&tr, aux)
}

fn show_pp<C, SP>(pp: &PP<C, SP>)
where
    SP: SetupParams<G1, G2, C, C2, RO, SC>,
    C: CommitmentScheme<P1>,
{
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
