use anyhow::Context;
use clap::Args;

use crate::LOG_TARGET;

#[derive(Debug, Args)]
pub struct RequestArgs {
    /// Program hash.
    pub hash: String,

    #[arg(long)]
    pub url: Option<String>,
}

pub fn handle_command(args: RequestArgs) -> anyhow::Result<()> {
    let hash = args.hash;
    let url = args.url.context("url must be specified")?;

    request_proof(hash, &url)
}

fn request_proof(_hash: String, _url: &str) -> anyhow::Result<()> {
    // let current_dir = std::env::current_dir()?;
    // let path = current_dir.join("nexus-proof.json");
    // let path_str = path.to_str().context("path is not valid utf8")?;

    // // TODO: network errors cannot be converted to anyhow.
    // let client = Client::new(url).map_err(|err| anyhow::anyhow!("url is invalid: {err}"))?;
    // let proof = client
    //     .fetch_proof(&hash)
    //     .map_err(|err| anyhow::anyhow!("failed to send request: {err}"))?;

    // if proof.total_nodes > proof.complete_nodes {
    //     tracing::info!(
    //         target: LOG_TARGET,
    //         "Proof is not complete: {}/{}",
    //         proof.complete_nodes,
    //         proof.total_nodes,
    //     );
    // } else {
    //     tracing::info!(
    //         target: LOG_TARGET,
    //         "Storing proof to {path_str}",
    //     );
    //     let serialized = serde_json::to_vec(&proof)?;
    //     std::fs::write(path_str, serialized)?;
    // }
    tracing::warn!(
        target: LOG_TARGET,
        "Networking commands are disabled",
    );

    Ok(())
}
