use std::path::PathBuf;

use clap::{Args, Subcommand};

#[derive(Debug, Args)]
pub struct SpartanSetupArgs {
    #[command(subcommand)]
    pub command: Option<SpartanSetupAction>,
}

#[derive(Debug, Subcommand)]
pub enum SpartanSetupAction {
    /// Generate Spartan key to file.
    Setup(SetupArgs),
}

#[derive(Debug, Default, Args)]
pub struct SetupArgs {
    /// Where to save the file.
    #[arg(short, long)]
    pub path: Option<PathBuf>,

    /// Overwrite the file if it already exists
    #[arg(long)]
    pub force: bool,

    /// Number of vm instructions per fold.
    #[arg(short, name = "k")]
    pub k: Option<usize>,

    /// Path to Nova public parameters file.
    #[arg(short = 'p', long = "public_params")]
    pub pp_file: Option<PathBuf>,

    /// Path to the Zeromorph structured reference string.
    #[arg(short = 's', long = "srs")]
    pub srs_file: Option<PathBuf>,
}

pub fn format_key_file(k: usize) -> String {
    format!("nexus-spartan-key-{k}.zst")
}
