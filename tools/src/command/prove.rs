use std::{
    io,
    path::{Path, PathBuf},
};

use anyhow::Context;
use clap::Args;

use nexus_api::config::{vm as vm_config, Config};

use crate::{
    command::{
        jolt,
        public_params::{setup_params, SetupArgs},
    },
    utils::{cargo, path_to_artifact},
    LOG_TARGET,
};

#[derive(Debug, Args)]
pub struct ProveArgs {
    #[command(flatten)]
    pub common_args: CommonProveArgs,

    /// Send prove request to the network.
    #[arg(long, conflicts_with_all = ["k", "pp_file", "impl"])]
    pub network: bool,

    /// Node address for accessing API.
    #[arg(long, conflicts_with_all = ["k", "pp_file", "impl"])]
    pub url: Option<String>,

    #[command(flatten)]
    pub local_args: LocalProveArgs,
}

#[derive(Debug, Args)]
pub struct LocalProveArgs {
    #[arg(short, name = "k")]
    pub k: Option<usize>,

    /// Path to public parameters file.
    #[arg(short = 'p', long = "public-params")]
    pub pp_file: Option<PathBuf>,

    #[arg(long("impl"))]
    pub prover_impl: Option<vm_config::ProverImpl>,

    /// Path to the SRS file: only needed when pp_file is None and nova_impl is ParallelCompressible.
    #[arg(long("srs-file"))]
    pub srs_file: Option<PathBuf>,
}

#[derive(Debug, Args)]
pub struct CommonProveArgs {
    /// Build artifacts with the specified profile. "release-unoptimized" is default.
    #[arg(long, default_value = "release-unoptimized")]
    pub profile: String,

    /// Name of the bin target to run.
    #[arg(long)]
    pub bin: Option<String>,
}

pub fn handle_command(args: ProveArgs) -> anyhow::Result<()> {
    let ProveArgs {
        common_args: CommonProveArgs { profile, bin },
        network,
        url,
        local_args,
    } = args;

    let path = path_to_artifact(bin, &profile)?;
    let vm_config = vm_config::VmConfig::from_env()?;

    if &profile == "dev" {
        tracing::warn!(
            target: LOG_TARGET,
            "proving debug build",
        )
    }

    if network {
        let url = url.context("url must be specified")?;
        request_prove(&path, &url)
    } else {
        let LocalProveArgs { k, pp_file, prover_impl, srs_file } = local_args;

        // workaround to enforce runtime to rebuild -- set env (cli args take priority)
        if let Some(prover) = prover_impl {
            std::env::set_var("NEXUS_VM_PROVER", prover.to_string());
        }

        // build artifact if needed
        cargo(
            None,
            [
                "build",
                "--target=riscv32i-unknown-none-elf",
                "--profile",
                &profile,
            ],
        )?;

        let k = k.unwrap_or(vm_config.k);
        let prover_impl = prover_impl.unwrap_or(vm_config.prover);
        local_prove(&path, k, prover_impl, pp_file, srs_file)
    }
}

fn request_prove(_path: &Path, _url: &str) -> anyhow::Result<()> {
    // TODO: network errors cannot be converted to anyhow.

    // let client = Client::new(url).map_err(|err| anyhow::anyhow!("url is invalid: {err}"))?;
    // let proof = client
    //     .submit_proof("account".to_string(), path)
    //     .map_err(|err| anyhow::anyhow!("failed to send request: {err}"))?;

    // tracing::info!(
    //     target: LOG_TARGET,
    //     hash = %proof.hash,
    //     "Prove request submitted",
    // );
    tracing::warn!(
        target: LOG_TARGET,
        "Networking commands are disabled",
    );

    Ok(())
}

fn local_prove(
    path: &Path,
    k: usize,
    prover: vm_config::ProverImpl,
    pp_file: Option<PathBuf>,
    srs_file: Option<PathBuf>,
) -> anyhow::Result<()> {
    // handle jolt separately
    let nova_impl = match prover {
        vm_config::ProverImpl::Jolt => return jolt::prove(path),
        vm_config::ProverImpl::Nova(nova_impl) => nova_impl,
    };

    // setup if necessary
    let pp_file = if let Some(path) = pp_file {
        // return early if the path was explicitly specified and doesn't exist
        if !path.try_exists()? {
            tracing::error!(
                target: LOG_TARGET,
                "path {} was not found",
                path.display(),
            );
            return Err(io::Error::from(io::ErrorKind::NotFound).into());
        }
        path
    } else {
        setup_params(SetupArgs {
            k: Some(k),
            nova_impl: Some(nova_impl),
            path: None,
            force: false,
            srs_file,
        })?
    };
    let path_str = pp_file.to_str().context("path is not valid utf8")?;

    let opts = nexus_api::nvm::VMOpts {
        k,
        machine: None,
        file: Some(path.into()),
    };
    let trace = nexus_api::prover::nova::run(&opts, true)?;
    let k = trace.k;

    let current_dir = std::env::current_dir()?;
    let proof_path = current_dir.join("nexus-proof");

    let mut term = nexus_tui::TerminalHandle::new_enabled();

    let tr = nexus_api::prover::nova::init_circuit_trace(trace)?;
    let num_steps = tr.steps();

    let on_step = move |iter: usize| match nova_impl {
        vm_config::NovaImpl::Parallel | vm_config::NovaImpl::ParallelCompressible => {
            let b = (num_steps + 1).ilog2();
            let a = b - 1 - (num_steps - iter).ilog2();

            let step = 2usize.pow(a + 1) * iter - (2usize.pow(a) - 1) * (2usize.pow(b + 1) - 1);
            let step_type = if iter <= num_steps / 2 {
                "leaf"
            } else if iter == num_steps - 1 {
                "root"
            } else {
                "node"
            };
            format!("{step_type} {step}")
        }
        _ => format!("step {iter}"),
    };

    let icount = {
        match nova_impl {
            vm_config::NovaImpl::Parallel | vm_config::NovaImpl::ParallelCompressible => {
                k * num_steps
            }
            _ => tr.instructions(),
        }
    };

    let mut term_ctx = term
        .context("Computing")
        .on_step(on_step)
        .num_steps(num_steps)
        .with_loading_bar("Proving")
        .completion_header("Proved")
        .completion_stats(move |elapsed| {
            format!(
                "{num_steps} step(s) in {elapsed}; {:.2} instructions / second",
                icount as f32 / elapsed.as_secs_f32()
            )
        });

    match nova_impl {
        vm_config::NovaImpl::Parallel => {
            assert!((num_steps + 1).is_power_of_two());

            let state = {
                let mut iterm = nexus_tui::TerminalHandle::new_enabled();
                let mut term_ctx = iterm
                    .context("Loading")
                    .on_step(|_step| "public parameters".into());
                let _guard = term_ctx.display_step();

                nexus_api::prover::nova::pp::load_pp(path_str)?
            };

            let mut vs = (0..num_steps)
                .step_by(2)
                .map(|i| {
                    let _guard = term_ctx.display_step();

                    let v = nexus_api::prover::nova::prove_par_leaf_step(&state, &tr, i)?;
                    Ok(v)
                })
                .collect::<anyhow::Result<Vec<_>>>()?;

            let root = {
                loop {
                    if vs.len() == 1 {
                        break;
                    }

                    vs = vs
                        .chunks(2)
                        .map(|ab| {
                            let _guard = term_ctx.display_step();
                            let c = nexus_api::prover::nova::prove_par_parent_step(
                                &state, &tr, &ab[0], &ab[1],
                            )?;
                            Ok(c)
                        })
                        .collect::<anyhow::Result<Vec<_>>>()?;
                }

                vs.into_iter().next().unwrap()
            };

            let mut context = term.context("Saving").on_step(|_step| "proof".into());
            let _guard = context.display_step();

            nexus_api::prover::nova::save_proof(root, &proof_path)?;
        }
        vm_config::NovaImpl::ParallelCompressible => {
            assert!((num_steps + 1).is_power_of_two());

            let mut iterm = nexus_tui::TerminalHandle::new_enabled();
            let state = {
                let mut term_ctx = iterm
                    .context("Loading")
                    .on_step(|_step| "public parameters".into());
                let _guard = term_ctx.display_step();

                nexus_api::prover::nova::pp::load_pp(path_str)?
            };

            let mut vs = (0..num_steps)
                .step_by(2)
                .map(|i| {
                    let _guard = term_ctx.display_step();

                    let v = nexus_api::prover::nova::prove_par_com_leaf_step(&state, &tr, i)?;
                    Ok(v)
                })
                .collect::<anyhow::Result<Vec<_>>>()?;

            let root = {
                loop {
                    if vs.len() == 1 {
                        break;
                    }

                    vs = vs
                        .chunks(2)
                        .map(|ab| {
                            let _guard = term_ctx.display_step();
                            let c = nexus_api::prover::nova::prove_par_com_parent_step(
                                &state, &tr, &ab[0], &ab[1],
                            )?;
                            Ok(c)
                        })
                        .collect::<anyhow::Result<Vec<_>>>()?;
                }

                vs.into_iter().next().unwrap()
            };

            let mut context = term.context("Saving").on_step(|_step| "proof".into());
            let _guard = context.display_step();

            nexus_api::prover::nova::save_proof(root, &proof_path)?;
        }
        vm_config::NovaImpl::Sequential => {
            let mut iterm = nexus_tui::TerminalHandle::new_enabled();
            let state = {
                let mut term_ctx = iterm
                    .context("Loading")
                    .on_step(|_step| "public parameters".into());
                let _guard = term_ctx.display_step();

                nexus_api::prover::nova::pp::load_pp(path_str)?
            };

            let mut proof = nexus_api::prover::nova::prove_seq_step(None, &state, &tr)?;

            for _ in 1..num_steps {
                let _guard = term_ctx.display_step();
                proof = nexus_api::prover::nova::prove_seq_step(Some(proof), &state, &tr)?;
            }

            let mut context = term.context("Saving").on_step(|_step| "proof".into());
            let _guard = context.display_step();

            nexus_api::prover::nova::save_proof(proof, &proof_path)?;
        }
    }

    Ok(())
}
