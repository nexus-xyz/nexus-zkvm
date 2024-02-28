use std::path::PathBuf;

use clap::Args;

use super::prove::LocalProveArgs;

#[derive(Debug, Args)]
pub struct VerifyArgs {
    /// File containing completed proof
    #[arg(default_value = "nexus-proof")]
    pub file: PathBuf,

    /// whether the proof has been compressed
    #[arg(long, short, default_value = "false")]
    pub compressed: bool,

    #[clap(flatten)]
    pub prover_args: LocalProveArgs,

    /// File containing the Spartan key; only needed when 'compressed' is true
    #[arg(long = "key-file", short = 'k')]
    pub key_file: Option<PathBuf>,
}
