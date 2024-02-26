use std::path::PathBuf;

use clap::Args;

use super::prove::LocalProveArgs;

#[derive(Debug, Args)]
pub struct VerifyArgs {
    /// File containing completed proof
    #[arg(default_value = "nexus-proof")]
    pub file: PathBuf,

    #[clap(flatten)]
    pub prover_args: LocalProveArgs,
}
