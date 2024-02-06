use std::{net::SocketAddr, path::Path};

use anyhow::Context;
use clap::Args;
use nexus_config::{Config, NetworkConfig};

use crate::{
    command::dev::{
        compile_env_configs,
        public_params::{setup_params_from_env, SetupArgs},
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
    let bind_addr = network_config.api.bind_addr();

    // setup if necessary
    let pp_file = setup_params_from_env(SetupArgs::default())?;

    launch_node(args, bind_addr, &pp_file)
}

fn launch_node(args: NodeArgs, bind_addr: SocketAddr, pp_file: &Path) -> anyhow::Result<()> {
    let NodeArgs {
        mut well_known,
        pcd,
        msm,
    } = args;
    if !(well_known || pcd || msm) {
        well_known = true;
    }
    let connect_addr = bind_addr;
    let mut listen_addr = bind_addr;

    // -w|-p|-m [-l=<addr>] [-c=<addr>] [--public-params=<path>]
    let mut network_opts = Vec::new();
    if well_known {
        network_opts.push("-w".to_string());
    } else if pcd {
        // TODO: should be configurable.
        listen_addr.set_port(0);
        network_opts.push("-p".into());
    } else if msm {
        // TODO: should be configurable.
        listen_addr.set_port(0);
        network_opts.push("-m".into());
    }
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
