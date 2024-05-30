use std::path::PathBuf;

use clap::Args;
use nexus_api::config::vm as vm_config;

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
