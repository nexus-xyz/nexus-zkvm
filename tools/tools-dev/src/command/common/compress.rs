use clap::Args;
use std::path::PathBuf;

#[derive(Debug, Args)]
pub struct CompressArgs {
    /// Number of vm instructions per fold
    #[arg(short, name = "k")]
    pub k: Option<usize>,

    /// Spartan key file
    #[arg(long = "key")]
    pub key_file: Option<PathBuf>,

    /// public parameters file; only needed if generating a new Spartan key
    #[arg(short = 'p', long = "public-params")]
    pub pp_file: Option<PathBuf>,

    /// srs file; only needed if generating a new Spartan key
    #[arg(short = 's', long = "structured-reference-string")]
    pub srs_file: Option<PathBuf>,

    /// File containing uncompressed proof
    #[arg(short = 'f', long = "proof-file")]
    pub proof_file: PathBuf,
}
