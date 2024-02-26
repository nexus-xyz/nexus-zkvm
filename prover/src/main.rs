#[cfg(feature = "snmalloc")]
#[global_allocator]
static ALLOC: snmalloc_rs::SnMalloc = snmalloc_rs::SnMalloc;

use clap::{Parser, Subcommand};
use tracing_subscriber::EnvFilter;

use nexus_prover::{
    error::ProofError,
    pp::{gen_or_load, gen_to_file},
    prove_par, prove_seq, run,
};
use nexus_vm::riscv::VMOpts;

#[derive(Debug, Parser)]
#[command(author, version, about, long_about = None)]
struct Opts {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Generate public parameters file
    Gen {
        /// instructions per step
        #[arg(short, name = "k", default_value = "1")]
        k: usize,

        /// use parallel Nova
        #[arg(short = 'P', default_value = "false")]
        par: bool,

        /// public parameters file
        #[arg(
            short = 'p',
            long = "public-params",
            default_value = "nexus-public.zst"
        )]
        pp_file: String,

        /// whether public parameters are compatible with proof compression
        #[arg(short = 'c', long = "compressible", default_value = "false")]
        com: bool,

        /// SRS file: required with `--compressible`, otherwise ignored
        #[arg(short = 's', long = "srs")]
        srs_file: Option<String>,
    },

    /// Prove execution of program
    Prove {
        /// generate public parameters (ignore files)
        #[arg(short)]
        gen: bool,

        /// use parallel Nova
        #[arg(short = 'P', default_value = "false")]
        par: bool,

        /// public parameters file
        #[arg(
            short = 'p',
            long = "public-params",
            default_value = "nexus-public.zst"
        )]
        pp_file: String,

        #[command(flatten)]
        vm: VMOpts,
    },
}
use Command::*;

fn main() -> Result<(), ProofError> {
    let filter = EnvFilter::from_default_env();
    tracing_subscriber::fmt()
        .with_span_events(tracing_subscriber::fmt::format::FmtSpan::CLOSE)
        .with_env_filter(filter)
        .init();

    let opts = Opts::parse();

    match opts.command {
        Gen { k, par, pp_file, com, srs_file } => {
            gen_to_file(k, par, com, &pp_file, srs_file.as_deref())
        }

        Prove { gen, par, pp_file, vm } => {
            let trace = run(&vm, par)?;
            if par {
                prove_par(gen_or_load(gen, vm.k, &pp_file, &())?, trace)?;
            } else {
                prove_seq(&gen_or_load(gen, vm.k, &pp_file, &())?, trace)?;
            }
            Ok(())
        }
    }
}
