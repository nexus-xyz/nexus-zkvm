#[cfg(feature = "snmalloc")]
#[global_allocator]
static ALLOC: snmalloc_rs::SnMalloc = snmalloc_rs::SnMalloc;

use clap::{Parser, Subcommand};

use nexus_riscv::VMOpts;
use nexus_prover::*;
use nexus_prover::error::*;
use nexus_prover::pp::{gen_to_file, gen_or_load};

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
    },

    /// Prove execution of program
    Prove {
        /// generate public parameters (ignore files)
        #[arg(short)]
        gen: bool,

        /// use parallel Nova
        #[arg(short = 'P', default_value = "false")]
        par: bool,

        /// private parameters file
        #[arg(
            short = 'p',
            long = "private-params",
            default_value = "nexus-public.zst"
        )]
        pp_file: String,

        #[command(flatten)]
        vm: VMOpts,
    },
}
use Command::*;

fn main() -> Result<(), ProofError> {
    let opts = Opts::parse();

    match opts.command {
        Gen { k, par, pp_file } => gen_to_file(k, par, &pp_file),

        Prove { gen, par, pp_file, vm } => {
            let trace = run(&vm, par)?;
            if par {
                prove_par(gen_or_load(gen, vm.k, &pp_file)?, trace)
            } else {
                prove_seq(gen_or_load(gen, vm.k, &pp_file)?, trace)
            }
        }
    }
}
