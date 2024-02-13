use anyhow::Context;

use nexus_config::{Config, NetworkConfig};

use crate::{command::common::RequestArgs, utils::cargo};

pub fn handle_command(args: RequestArgs) -> anyhow::Result<()> {
    let hash = args.hash;

    let url = if let Some(url) = args.url {
        url
    } else {
        let network_config = NetworkConfig::from_env()?;
        network_config.client.to_string()
    };

    request_proof(hash, &url)
}

fn request_proof(hash: String, url: &str) -> anyhow::Result<()> {
    let current_dir = std::env::current_dir()?;
    let path = current_dir.join("nexus-proof.json");
    let path_str = path.to_str().context("path is not valid utf8")?;
    // query <hash> [-p=<path_to_save>]
    let mut client_opts = vec![format!("--url={url}")];
    client_opts.extend(["query".to_owned(), hash, format!("-p={path_str}")]);

    let mut cargo_opts: Vec<String> = ["run", "-p", "nexus-network", "--bin", "client", "--"]
        .into_iter()
        .map(From::from)
        .collect();
    cargo_opts.append(&mut client_opts);

    // run from workspace
    cargo(cargo_manifest_dir_path!().into(), cargo_opts)
}
