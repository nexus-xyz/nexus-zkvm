use std::{
    fs::File,
    io::BufReader,
    path::{Path, PathBuf},
};

use anyhow::Context;
use ark_serialize::CanonicalDeserialize;
use nexus_config::{
    vm::{NovaImpl, VmConfig},
    Config,
};
use nexus_prover::types::{IVCProof, PCDNode, ParPP, SeqPP};
use nexus_tools_dev::command::common::{
    prove::LocalProveArgs, public_params::format_params_file, VerifyArgs,
};

use crate::{command::cache_path, LOG_TARGET};

pub fn handle_command(args: VerifyArgs) -> anyhow::Result<()> {
    let VerifyArgs {
        file,
        prover_args: LocalProveArgs { k, pp_file, nova_impl },
    } = args;

    let vm_config = VmConfig::from_env()?;

    verify_proof(
        &file,
        k.unwrap_or(vm_config.k),
        nova_impl.unwrap_or(vm_config.nova_impl),
        pp_file,
    )
}

fn verify_proof(
    path: &Path,
    k: usize,
    nova_impl: NovaImpl,
    pp_file: Option<PathBuf>,
) -> anyhow::Result<()> {
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

    let mut term = nexus_tui::TerminalHandle::new();
    let mut ctx = term.context("Verifying").on_step(move |_step| {
        match nova_impl {
            NovaImpl::Parallel => "root",
            NovaImpl::Sequential => "proof",
        }
        .into()
    });
    let mut _guard = Default::default();

    let result = match nova_impl {
        NovaImpl::Parallel => {
            let root = PCDNode::deserialize_compressed(reader)?;
            let params: ParPP = nexus_prover::pp::gen_or_load(false, k, &path, &())?;

            _guard = ctx.display_step();
            root.verify(&params).map_err(anyhow::Error::from)
        }
        NovaImpl::Sequential => {
            let proof = IVCProof::deserialize_compressed(reader)?;
            let params: SeqPP = nexus_prover::pp::gen_or_load(false, k, &path, &())?;

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
