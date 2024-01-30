use clap::{Args, Parser, Subcommand, ValueEnum};

#[derive(Debug, Parser)]
#[command(name = "cargo")]
#[command(bin_name = "cargo")]
enum Cargo {
    Nexus(Opts),
}

#[derive(Debug, Args)]
#[command(author, version, about, long_about = None)]
pub struct Opts {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Create a new Nexus project
    New {
        /// Path to new project directory
        #[arg(name = "path")]
        path: std::path::PathBuf,
    },

    /// Run a Nexus binary
    Run {
        /// Print instruction trace
        #[arg(short)]
        verbose: bool,

        /// Use release mode artifacts
        #[arg(short, long)]
        release: bool,

        /// Name of the bin target to run
        #[arg(long)]
        bin: Option<String>,
    },

    /// Send program to Nexus prover network
    Prove {
        /// Use release mode artifacts
        #[arg(short, long)]
        release: bool,

        /// Name of the bin target to run
        #[arg(long)]
        bin: Option<String>,
    },

    /// Query status of a proof
    Query {
        /// Proof identifier
        #[arg(long)]
        hash: String,

        /// File to save completed proof
        #[arg(short, long, default_value = "nexus-proof.json")]
        file: std::path::PathBuf,
    },

    /// Verify a Nexus proof
    Verify {
        /// public parameters file
        #[arg(
            short = 'p',
            long = "public-params",
            default_value = "nexus-public.zst"
        )]
        pp_file: String,

        /// File containing completed proof
        #[arg(short, long, default_value = "nexus-proof.json")]
        file: std::path::PathBuf,
    },

    /// Run a Nexus proof locally
    LocalProve {
        /// instructions per step
        #[arg(short, name = "k", default_value = "1")]
        k: usize,

        /// public parameters file
        #[arg(
            short = 'p',
            long = "public-params",
            default_value = "nexus-public.zst"
        )]
        pp_file: String,

        /// Use release mode artifacts
        #[arg(short, long)]
        release: bool,

        /// Name of the bin target to run
        #[arg(long)]
        bin: Option<String>,
    },

    /// Export proof artifacts
    Export {
        #[arg(name = "artifact", value_enum)]
        artifact: Artifact,
    },

    /// Sample test SRS
    SampleTestSRS {
        /// Number of variables
        #[arg(short = 'n', long = "num-vars", default_value = "19")]
        num_vars: usize,

        /// File to save test SRS
        #[arg(long = "srs", default_value = "test_srs.zst")]
        file: String,
    },
}
pub use Command::*;

#[derive(Copy, Clone, Debug, ValueEnum)]
pub enum Artifact {
    EthVerifier,
    EthCallData,
}
pub use Artifact::*;

use std::sync::OnceLock;

static OPTS: OnceLock<Opts> = OnceLock::new();

pub fn options() -> &'static Opts {
    OPTS.get_or_init(|| {
        let Cargo::Nexus(opts) = Cargo::parse();
        opts
    })
}
