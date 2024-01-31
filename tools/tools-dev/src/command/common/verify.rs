use std::path::PathBuf;

use clap::Args;

#[derive(Debug, Args)]
pub struct VerifyArgs {
    #[arg(short = 'p', long = "public-params")]
    pub pp_file: Option<PathBuf>,

    /// File containing completed proof
    #[arg(default_value = "nexus-proof.json")]
    pub file: PathBuf,
}
