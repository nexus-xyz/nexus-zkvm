use std::fs::File;
use zstd::stream::{Decoder, Encoder};

pub use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use nexus_nova::nova::pcd::compression::SNARK;

use crate::error::*;
use crate::pp::load_pp;
use crate::srs::load_srs;
use crate::types::*;
use crate::{LOG_TARGET, TERMINAL_MODE};

pub fn gen_key(pp: &ComPP, srs: &SRS) -> Result<SpartanKey, ProofError> {
    let key = SNARK::setup(pp, srs)?;
    Ok(key)
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

pub fn gen_key_to_file(pp_file: &str, srs_file: &str, key_file: &str) -> Result<(), ProofError> {
    tracing::info!(
        target: LOG_TARGET,
        path =?srs_file,
        "Reading the SRS",
    );
    let mut term = nexus_tui::TerminalHandle::new(TERMINAL_MODE);
    let srs = {
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

    tracing::info!(
        target: LOG_TARGET,
        pp_file =?pp_file,
        "Reading the Nova public parameters",
    );

    let pp: ComPP = {
        let mut term_ctx = term
            .context("Loading")
            .on_step(|_step| "Nova public parameters".into());
        let _guard = term_ctx.display_step();

        load_pp(pp_file)?
    };

    tracing::info!(
        target: LOG_TARGET,
        key_file =?key_file,
        "Generating Spartan key parameters",
    );

    let mut term_ctx = term
        .context("Generating")
        .on_step(|_step| "Spartan key".into());
    let _guard = term_ctx.display_step();

    let key: SpartanKey = gen_key(&pp, &srs)?;
    save_key(key, key_file)
}

pub fn gen_or_load_key(
    gen: bool,
    key_file: &str,
    pp_file: Option<&str>,
    srs_file: Option<&str>,
) -> Result<SpartanKey, ProofError> {
    let mut term = nexus_tui::TerminalHandle::new(TERMINAL_MODE);
    let key: SpartanKey = if gen {
        tracing::info!(
            target: LOG_TARGET,
            key_file =?key_file,
            "Generating Spartan key parameters",
        );

        let srs_file = srs_file.ok_or(ProofError::MissingSRS)?;
        tracing::info!(
            target: LOG_TARGET,
            path =?srs_file,
            "Reading the SRS",
        );
        let srs = {
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

        let pp_file = pp_file.ok_or(ProofError::InvalidPP)?;
        tracing::info!(
            target: LOG_TARGET,
            path =?srs_file,
            "Reading the Nova public parameters",
        );

        let mut term_ctx = term
            .context("Setting up")
            .on_step(|_step| "Spartan key".into());
        let _guard = term_ctx.display_step();

        let pp: ComPP = load_pp(pp_file)?;

        gen_key(&pp, &srs)?
    } else {
        tracing::info!(
            target: LOG_TARGET,
            path = ?pp_file,
            "Loading Spartan key",
        );
        let mut term_ctx = term
            .context("Loading")
            .on_step(|_step| "Spartan key".into());
        let _guard = term_ctx.display_step();

        load_key(key_file)?
    };
    Ok(key)
}
