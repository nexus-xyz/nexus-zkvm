use std::fs::File;
use zstd::stream::{Decoder, Encoder};

pub use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};

use crate::circuit::{nop_circuit, Tr};
use crate::error::*;
use crate::types::*;
use crate::LOG_TARGET;

pub fn gen_pp<SP>(circuit: &SC) -> Result<PP<SP>, ProofError>
where
    SP: SetupParams<G1, G2, C1, C2, RO, SC>,
{
    Ok(SP::setup(ro_config(), circuit, &(), &())?)
}

pub fn save_pp<SP>(pp: PP<SP>, file: &str) -> Result<(), ProofError>
where
    SC: StepCircuit<F1>,
    SP: SetupParams<G1, G2, C1, C2, RO, SC>,
{
    let f = File::create(file)?;
    let mut enc = Encoder::new(&f, 0)?;
    pp.serialize_compressed(&mut enc)?;
    enc.finish()?;
    f.sync_all()?;
    Ok(())
}

pub fn load_pp<SP>(file: &str) -> Result<PP<SP>, ProofError>
where
    SC: StepCircuit<F1> + Sync,
    SP: SetupParams<G1, G2, C1, C2, RO, SC> + Sync,
{
    let f = File::open(file)?;
    let mut dec = Decoder::new(&f)?;
    let pp = PP::<SP>::deserialize_compressed(&mut dec)?;
    Ok(pp)
}

pub fn gen_vm_pp<SP>(k: usize) -> Result<PP<SP>, ProofError>
where
    SP: SetupParams<G1, G2, C1, C2, RO, Tr>,
{
    let tr = nop_circuit(k)?;
    gen_pp(&tr)
}

fn show_pp<SP>(pp: &PP<SP>)
where
    SP: SetupParams<G1, G2, C1, C2, RO, Tr>,
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

pub fn gen_to_file(k: usize, par: bool, pp_file: &str) -> Result<(), ProofError> {
    tracing::info!(
        target: LOG_TARGET,
        path = ?pp_file,
        "Generating public parameters",
    );
    let mut term = nexus_tui::TerminalHandle::new();
    let mut term_ctx = term
        .context("Setting up")
        .on_step(|_step| format!("public parameters"));
    let _guard = term_ctx.display_step();

    if par {
        let pp: ParPP = gen_vm_pp(k)?;
        show_pp(&pp);
        save_pp(pp, pp_file)
    } else {
        let pp: SeqPP = gen_vm_pp(k)?;
        show_pp(&pp);
        save_pp(pp, pp_file)
    }
}

pub fn gen_or_load<SP>(gen: bool, k: usize, pp_file: &str) -> Result<PP<SP>, ProofError>
where
    SP: SetupParams<G1, G2, C1, C2, RO, Tr> + Sync,
{
    let mut term = nexus_tui::TerminalHandle::new();

    let pp: PP<SP> = if gen {
        tracing::info!(
            target: LOG_TARGET,
            "Generating public parameters",
        );
        let mut term_ctx = term
            .context("Setting up")
            .on_step(|_step| "public parameters".into());
        let _guard = term_ctx.display_step();

        gen_vm_pp(k)?
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
    drop(term);

    show_pp(&pp);
    Ok(pp)
}
