use anyhow::Context;

use crate::{command::common::RequestArgs, utils::cargo};

pub fn handle_command(args: RequestArgs) -> anyhow::Result<()> {
    let hash = args.hash;

    request_proof(hash)
}

fn request_proof(hash: String) -> anyhow::Result<()> {
    let current_dir = std::env::current_dir()?;
    let path = current_dir.join("nexus-proof.json");
    let path_str = path.to_str().context("path is not valid utf8")?;
    // query <hash> [-p=<path_to_save>]
    let mut client_opts = vec!["query".to_owned(), hash, format!("-p={path_str}")];

    let mut cargo_opts: Vec<String> = ["run", "-p", "nexus-network", "--bin", "client", "--"]
        .into_iter()
        .map(From::from)
        .collect();
    cargo_opts.append(&mut client_opts);

    // run from workspace
    cargo(cargo_manifest_dir_path!().into(), cargo_opts)
}
