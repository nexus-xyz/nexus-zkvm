use std::path::PathBuf;

use clap::{Args, Subcommand};

#[derive(Debug, Args)]
pub struct ProveArgs {
    #[command(subcommand)]
    pub action: Option<ProveAction>,

    #[command(flatten)]
    pub common_args: CommonProveArgs,
}

#[derive(Debug, Subcommand)]
pub enum ProveAction {
    Request,
    Local {
        #[arg(short, name = "k")]
        k: Option<usize>,

        #[arg(short = 'p', long = "public-params")]
        pp_file: Option<PathBuf>,
    },
}

#[derive(Debug, Args)]
pub struct CommonProveArgs {
    /// Use release mode artifacts
    #[arg(short, long)]
    pub release: bool,

    /// Name of the bin target to run
    #[arg(long)]
    pub bin: Option<String>,
}
