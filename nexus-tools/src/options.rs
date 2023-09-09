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
        /// Name of the binary to run
        #[arg(long)]
        bin: Option<String>,
    },

    /// Create a Nexus package
    Package {},

    /// Display information about a Nexus package file
    Info {
        /// Display more information (max:3)
        #[arg(short, long, action = clap::ArgAction::Count)]
        verbose: u8,

        /// Input file
        #[arg(name = "Package File")]
        file: std::path::PathBuf,
    },

    /// Send Nexus package to prover network
    Prove {},

    /// Verify a Nexus proof
    Verify {},

    /// Export proof artifacts
    Export {
        #[arg(name = "artifact", value_enum)]
        artifact: Artifact,
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
