//! Jolt prove/verify routine implementation.

use std::{fs::File, io::BufReader, path::Path};

use nexus_core::nvm::memory::MerkleTrie;
use nexus_core::prover::jolt::{
    parse_elf, trace,
    types::{JoltCommitments, JoltProof},
    VM,
};
use nexus_progress_bar::TerminalHandle;

use anyhow::Context;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};

use super::prove::CommonProveArgs;
use crate::{utils::path_to_artifact, LOG_TARGET};

type Proof = (JoltProof, JoltCommitments);

pub fn prove(path: &Path) -> anyhow::Result<()> {
    let bytes = std::fs::read(path)?;
    let vm: VM<MerkleTrie> = parse_elf(&bytes)?;

    let mut term = TerminalHandle::new_enabled();

    // preprocess bytecode
    let bytecode_size = vm.bytecode_size();
    let mut ctx = term
        .context("Preprocessing")
        .on_step(|_step| "bytecode".into())
        .completion_stats(move |elapsed| format!("in {elapsed}; bytecode size: {bytecode_size}"));
    let preprocessing = {
        let _guard = ctx.display_step();
        nexus_core::prover::jolt::preprocess(&vm)
    };
    drop(term);

    // trace
    println!("Executing program...");

    let start = std::time::Instant::now();
    let trace = trace(vm)?;
    println!(
        "Executed {} instructions in {:?}",
        trace.len(),
        start.elapsed(),
    );

    let mut term = TerminalHandle::new_enabled();
    // prove
    let mut ctx = term
        .context("Proving")
        .on_step(|_step| "program execution".into());
    let (proof, commitments) = {
        let _guard = ctx.display_step();
        nexus_core::prover::jolt::prove(trace, &preprocessing)?
    };

    let proof = (proof, commitments);

    // save
    let current_dir = std::env::current_dir()?;
    let proof_path = current_dir.join("nexus-proof");

    let mut context = term.context("Saving").on_step(|_step| "proof".into());
    {
        let _guard = context.display_step();

        let mut buf = Vec::new();

        CanonicalSerialize::serialize_compressed(&proof, &mut buf)?;
        std::fs::write(proof_path, buf)?;
    }

    Ok(())
}

pub fn verify(proof_path: &Path, prove_args: CommonProveArgs) -> anyhow::Result<()> {
    let CommonProveArgs { bin, profile } = prove_args;
    let path = path_to_artifact(bin, &profile)?;

    // load proof
    let file = File::open(proof_path)?;
    let reader = BufReader::new(file);

    let (proof, commitments): Proof = CanonicalDeserialize::deserialize_compressed(reader)
        .context("proof is not in Jolt format")?;

    let bytes = std::fs::read(path)?;
    let vm: VM<MerkleTrie> = parse_elf(&bytes)?;

    let mut term = TerminalHandle::new_enabled();

    // preprocess bytecode
    let bytecode_size = vm.bytecode_size();
    let mut ctx = term
        .context("Preprocessing")
        .on_step(|_step| "bytecode".into())
        .completion_stats(move |elapsed| format!("in {elapsed}; bytecode size: {bytecode_size}"));
    let preprocessing = {
        let _guard = ctx.display_step();
        nexus_core::prover::jolt::preprocess(&vm)
    };

    // verify
    let mut ctx = term
        .context("Verifying")
        .on_step(move |_step| "proof".into());
    let mut _guard = ctx.display_step();

    let result = nexus_core::prover::jolt::verify(preprocessing, proof, commitments);

    match result {
        Ok(_) => {
            drop(_guard);

            tracing::info!(
                target: LOG_TARGET,
                "Proof is valid",
            );
            Ok(())
        }
        Err(err) => {
            _guard.abort();

            tracing::error!(
                target: LOG_TARGET,
                err = ?err,
                "Proof is invalid",
            );
            std::process::exit(1);
        }
    }
}
