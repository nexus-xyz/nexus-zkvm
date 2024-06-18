use std::path::PathBuf;

use clap::{Args, Subcommand};
use nexus_api::config::vm as vm_config;

#[derive(Debug, Args)]
pub struct PublicParamsArgs {
    #[command(subcommand)]
    pub command: Option<PublicParamsAction>,
}

#[derive(Debug, Subcommand)]
pub enum PublicParamsAction {
    /// Generate public parameters to file.
    Setup(SetupArgs),
    /// Sample SRS for testing to file: NOT SECURE, and memory-heavy operation.
    SampleTestSRS(SRSSetupArgs),
}

#[derive(Debug, Default, Args)]
pub struct SRSSetupArgs {
    /// Number of vm instructions per fold; defaults to reading value from vm config.
    #[arg(short, name = "k")]
    pub k: Option<usize>,

    /// Number of variables: defaults to minimum needed for compression for the given `k`.
    #[arg(short = 'n', long = "num-vars")]
    pub num_vars: Option<usize>,

    /// File to save test SRS
    #[arg(short, long)]
    pub file: Option<PathBuf>,

    /// Overwrite the file if it already exists.
    #[arg(long)]
    pub force: bool,
}

#[derive(Debug, Default, Args)]
pub struct SetupArgs {
    /// Number of vm instructions per fold.
    #[arg(short, name = "k")]
    pub k: Option<usize>,

    #[arg(long("impl"))]
    pub nova_impl: Option<vm_config::NovaImpl>,

    /// Where to save the file.
    #[arg(short, long)]
    pub path: Option<PathBuf>,

    /// Overwrite the file if it already exists.
    #[arg(long)]
    pub force: bool,

    /// Path to the SRS file (only required for compressible PCD proofs).
    #[arg(long("srs_file"))]
    pub srs_file: Option<PathBuf>,
}
