use std::fs::File;
use zstd::stream::{Decoder, Encoder};

pub use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};

use super::srs::load_srs;
use crate::circuit::{nop_circuit, Tr};
use crate::error::*;
use crate::types::*;
use crate::{LOG_TARGET, TERMINAL_MODE};

pub fn gen_pp<C, SP>(circuit: &SC, aux: &C::SetupAux) -> Result<PP<C, SP>, ProofError>
where
    C: CommitmentScheme<P1>,
    SP: SetupParams<G1, G2, C, C2, RO, SC>,
{
    Ok(SP::setup(ro_config(), circuit, aux, &())?)
}

pub fn save_pp<C, SP>(pp: &PP<C, SP>, file: &str) -> Result<(), ProofError>
where
    C: CommitmentScheme<P1>,
    SC: StepCircuit<F1>,
    SP: SetupParams<G1, G2, C, C2, RO, SC>,
{
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
    let f = File::open(file)?;
    let mut dec = Decoder::new(&f)?;
    let pp = PP::<C, SP>::deserialize_compressed(&mut dec)?;
    Ok(pp)
}

pub fn gen_vm_pp<C, SP>(k: usize, aux: &C::SetupAux) -> Result<PP<C, SP>, ProofError>
where
    SP: SetupParams<G1, G2, C, C2, RO, Tr>,
    C: CommitmentScheme<P1>,
{
    let tr = nop_circuit(k)?;
    gen_pp(&tr, aux)
}

fn show_pp<C, SP>(pp: &PP<C, SP>)
where
    SP: SetupParams<G1, G2, C, C2, RO, Tr>,
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

pub fn gen_to_file(
    k: usize,
    par: bool,
    pp_file: &str,
    srs_file_opt: Option<&str>,
) -> Result<(), ProofError> {
    tracing::info!(
        target: LOG_TARGET,
        path = ?pp_file,
        "Generating public parameters",
    );
    let mut term = nexus_tui::TerminalHandle::new(TERMINAL_MODE);

    if par {
        match srs_file_opt {
            Some(srs_file) => {
                tracing::info!(
                target: LOG_TARGET,
                path =?srs_file,
                "Reading the SRS",
                );
                let srs: SRS = {
                    let mut term_ctx = term.context("Loading").on_step(|_step| "SRS".into());
                    let _guard = term_ctx.display_step();
                    load_srs(srs_file)?
                };
                tracing::info!(
                    target: LOG_TARGET,
                    path =?srs_file,
                    "SRS found for a maximum of {} variables",
                    srs.max_num_vars
                );
                let pp: ComPP = {
                    tracing::info!(
                        target: LOG_TARGET,
                        "Generating compressible PCD public parameters",
                    );
                    let mut term_ctx = term
                        .context("Setting up")
                        .on_step(|_step| "public parameters for PCD (compression enabled)".into());
                    let _guard = term_ctx.display_step();
                    gen_vm_pp(k, &srs)?
                };

                show_pp(&pp);
                save_pp(&pp, pp_file)
            }
            None => {
                tracing::info!(
                    target: LOG_TARGET,
                    "Generating non-compressible PCD public parameters",
                );
                let pp: ParPP = {
                    let mut term_ctx = term
                        .context("Setting up")
                        .on_step(|_step| "public parameters for PCD (compression disabled)".into());
                    let _guard = term_ctx.display_step();

                    gen_vm_pp(k, &())?
                };
                show_pp(&pp);
                save_pp(&pp, pp_file)
            }
        }
    } else {
        tracing::info!(
            target: LOG_TARGET,
            "Generating IVC public parameters",
        );

        let pp: SeqPP = {
            let mut term_ctx = term
                .context("Setting up")
                .on_step(|_step| "public parameters for IVC".into());
            let _guard = term_ctx.display_step();
            gen_vm_pp(k, &())?
        };
        show_pp(&pp);
        save_pp(&pp, pp_file)
    }
}

pub fn gen_or_load<C, SP>(
    gen: bool,
    k: usize,
    pp_file: &str,
    aux_opt: Option<&C::SetupAux>,
) -> Result<PP<C, SP>, ProofError>
where
    SP: SetupParams<G1, G2, C, C2, RO, Tr> + Sync,
    C: CommitmentScheme<P1>,
{
    let mut term = nexus_tui::TerminalHandle::new(TERMINAL_MODE);

    let pp: PP<C, SP> = if gen {
        tracing::info!(
            target: LOG_TARGET,
            "Generating public parameters",
        );

        let aux = if let Some(aux) = aux_opt {
            aux
        } else {
            tracing::error!(
                target: LOG_TARGET,
                "Auxiliary setup parameters are not provided",
            );
            return Err(ProofError::MissingSRS);
        };
        let mut term_ctx = term
            .context("Setting up")
            .on_step(|_step| "public parameters".into());
        let _guard = term_ctx.display_step();
        gen_vm_pp(k, aux)?
    } else {
        tracing::info!(
            target: LOG_TARGET,
            path = ?pp_file,
            "Loading public parameters",
        );
        let mut term_ctx = term
            .context("Loading")
            .on_step(|_step| "public parameters".into());
        let _guard = term_ctx.display_step();

        load_pp(pp_file)?
    };

    show_pp(&pp);
    Ok(pp)
}
