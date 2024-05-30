use std::path::Path;

use anyhow::Context;
use clap::Args;
use nexus_api::config::{Config, NetworkConfig};

use crate::{
    command::{
        common::public_params::SetupArgs,
        dev::{common_impl::public_params::setup_params_from_env, compile_env_configs},
    },
    utils::cargo,
};

// TODO: switch to enum
#[derive(Debug, Args)]
pub struct NodeArgs {
    /// Run coordinator node.
    #[arg(group = "type", short, default_value = "false")]
    well_known: bool,

    /// Run pcd-prover node.
    #[arg(group = "type", short, default_value = "false")]
    pcd: bool,

    /// Run msm-prover node.
    #[arg(group = "type", short, default_value = "false")]
    msm: bool,
}

pub fn handle_command(args: NodeArgs) -> anyhow::Result<()> {
    // make sure configs are compiled
    compile_env_configs(false)?;

    let network_config = NetworkConfig::from_env()?;

    // setup if necessary
    let pp_file = setup_params_from_env(SetupArgs::default())?;

    launch_node(args, network_config, &pp_file)
}

fn launch_node(args: NodeArgs, config: NetworkConfig, pp_file: &Path) -> anyhow::Result<()> {
    let NodeArgs { mut well_known, pcd, msm } = args;
    if !(well_known || pcd || msm) {
        well_known = true;
    }
    let listen_addr = config.api.bind_addr;

    let connect_addr = config.client.to_string();

    // -w|-p|-m [-l=<addr>] [-c=<addr>] [--public-params=<path>]
    let mut network_opts = Vec::new();
    let role = if well_known {
        "-w"
    } else if pcd {
        "-p"
    } else {
        assert!(msm);
        "-m"
    }
    .to_string();
    network_opts.push(role);

    let path = pp_file.to_str().context("path is not valid utf8")?;
    network_opts.extend([
        format!("-l={listen_addr}"),
        format!("-c={connect_addr}"),
        format!("--public-params={path}"),
    ]);

    let mut cargo_opts: Vec<String> = ["run", "--release", "-p", "nexus-network", "--"]
        .into_iter()
        .map(From::from)
        .collect();
    cargo_opts.append(&mut network_opts);

    // run from workspace
    cargo(cargo_manifest_dir_path!().into(), cargo_opts)
}
