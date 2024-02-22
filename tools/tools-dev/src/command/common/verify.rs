use std::path::PathBuf;

use clap::Args;

#[derive(Debug, Args)]
pub struct VerifyArgs {
    /// Path to public parameters file.
    #[arg(short = 'p', long = "public-params")]
    pub pp_file: Option<PathBuf>,

    /// File containing completed proof
    #[arg(default_value = "nexus-proof")]
    pub file: PathBuf,

    #[arg(short)]
    pub k: Option<usize>,
}
