use std::{
    fs::File,
    io::BufReader,
    path::{Path, PathBuf},
};

use anyhow::Context;
use ark_serialize::CanonicalDeserialize;
use clap::Args;

use nexus_config::{
    vm::{NovaImpl, ProverImpl, VmConfig},
    Config,
};
use nexus_api::prover::nova::types::{ComPCDNode, ComProof, IVCProof, PCDNode};
use super::{
    jolt,
    prove::{CommonProveArgs, LocalProveArgs},
    public_params::format_params_file,
    spartan_key::format_key_file,
};
use crate::{command::cache_path, LOG_TARGET};

#[derive(Debug, Args)]
pub struct VerifyArgs {
    /// File containing completed proof
    #[arg(default_value = "nexus-proof")]
    pub file: PathBuf,

    /// whether the proof has been compressed
    #[arg(long, short, default_value = "false")]
    pub compressed: bool,

    #[clap(flatten)]
    pub prover_args: LocalProveArgs,

    #[clap(flatten)]
    pub common_args: CommonProveArgs,

    /// File containing the Spartan key; only needed when 'compressed' is true
    #[arg(long = "key-file", short = 'k')]
    pub key_file: Option<PathBuf>,
}

pub fn handle_command(args: VerifyArgs) -> anyhow::Result<()> {
    let VerifyArgs {
        file,
        compressed,
        prover_args: LocalProveArgs { k, pp_file, prover_impl: nova_impl, .. },
        key_file,
        common_args,
    } = args;

    let vm_config = VmConfig::from_env()?;
    if compressed {
        verify_proof_compressed(&file, k.unwrap_or(vm_config.k), pp_file, key_file)
    } else {
        verify_proof(
            &file,
            k.unwrap_or(vm_config.k),
            nova_impl.unwrap_or(vm_config.prover),
            common_args,
            pp_file,
        )
    }
}

fn verify_proof_compressed(
    path: &Path,
    k: usize,
    pp_file: Option<PathBuf>,
    key_file: Option<PathBuf>,
) -> anyhow::Result<()> {
    let file = File::open(path)?;
    let reader = BufReader::new(file);

    let pp_path = match pp_file {
        Some(path) => path,
        None => {
            let pp_file_name = format_params_file(NovaImpl::ParallelCompressible, k);
            let cache_path = cache_path()?;

            cache_path.join(pp_file_name)
        }
    }
    .to_str()
    .context("path is not utf-8")?
    .to_owned();

    let key_path = match key_file {
        Some(path) => path,
        None => {
            let key_file_name = format_key_file(k);
            let cache_path = cache_path()?;

            cache_path.join(key_file_name)
        }
    }
    .to_str()
    .context("path is not utf-8")?
    .to_owned();

    let mut term = nexus_tui::TerminalHandle::new_enabled();
    let mut ctx = term
        .context("Verifying compressed")
        .on_step(move |_step| "proof".into());
    let mut _guard = Default::default();

    let result = {
        let proof = ComProof::deserialize_compressed(reader)?;
        let params = {
            let mut term_ctx = term
                .context("Loading")
                .on_step(|_step| "public parameters".into());
            let _guard = term_ctx.display_step();

            nexus_api::prover::nova::pp::load_pp(&pp_path)?
        };
        let key = nexus_api::prover::nova::key::load_key(&key_path)?;

        _guard = ctx.display_step();
        nexus_api::prover::nova::verify_compressed(&key, &params, &proof)
            .map_err(anyhow::Error::from)
    };

    match result {
        Ok(_) => {
            drop(_guard);

            tracing::info!(
                target: LOG_TARGET,
                "Compressed proof is valid",
            );
        }
        Err(err) => {
            _guard.abort();

            tracing::error!(
                target: LOG_TARGET,
                err = ?err,
                ?k,
                "Compressed proof is invalid",
            );
            std::process::exit(1);
        }
    }

    Ok(())
}

fn verify_proof(
    path: &Path,
    k: usize,
    prover: ProverImpl,
    prove_args: CommonProveArgs,
    pp_file: Option<PathBuf>,
) -> anyhow::Result<()> {
    // handle jolt separately
    let nova_impl = match prover {
        ProverImpl::Jolt => return jolt::verify(path, prove_args),
        ProverImpl::Nova(nova_impl) => nova_impl,
    };

    let file = File::open(path)?;
    let reader = BufReader::new(file);

    let path = match pp_file {
        Some(path) => path,
        None => {
            let pp_file_name = format_params_file(nova_impl, k);
            let cache_path = cache_path()?;

            cache_path.join(pp_file_name)
        }
    }
    .to_str()
    .context("path is not utf8")?
    .to_owned();

    let mut term = nexus_tui::TerminalHandle::new_enabled();
    let mut ctx = term.context("Verifying").on_step(move |_step| {
        match nova_impl {
            NovaImpl::Parallel => "root",
            NovaImpl::ParallelCompressible => "root",
            NovaImpl::Sequential => "proof",
        }
        .into()
    });
    let mut _guard = Default::default();

    let params = {
        let mut term_ctx = term
            .context("Loading")
            .on_step(|_step| "public parameters".into());
        let _guard = term_ctx.display_step();

        nexus_api::prover::nova::pp::load_pp(&path)?
    };

    let result = match nova_impl {
        NovaImpl::Parallel => {
            let root = PCDNode::deserialize_compressed(reader)?;

            _guard = ctx.display_step();
            root.verify(&params).map_err(anyhow::Error::from)
        }
        NovaImpl::ParallelCompressible => {
            let root = ComPCDNode::deserialize_compressed(reader)?;

            _guard = ctx.display_step();
            root.verify(&params).map_err(anyhow::Error::from)
        }
        NovaImpl::Sequential => {
            let proof = IVCProof::deserialize_compressed(reader)?;

            _guard = ctx.display_step();
            proof
                .verify(&params, proof.step_num() as usize)
                .map_err(anyhow::Error::from)
        }
    };

    match result {
        Ok(_) => {
            drop(_guard);

            tracing::info!(
                target: LOG_TARGET,
                "Proof is valid",
            );
        }
        Err(err) => {
            _guard.abort();

            tracing::error!(
                target: LOG_TARGET,
                err = ?err,
                ?k,
                %nova_impl,
                "Proof is invalid",
            );
            std::process::exit(1);
        }
    }
    Ok(())
}
