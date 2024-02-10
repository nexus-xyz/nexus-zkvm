#[cfg(feature = "snmalloc")]
#[global_allocator]
static ALLOC: snmalloc_rs::SnMalloc = snmalloc_rs::SnMalloc;

use clap::{Parser, Subcommand};

use nexus_prover::srs::load_srs;
use nexus_prover::types::ComPP;
use nexus_riscv::VMOpts;
use nexus_prover::*;
use nexus_prover::error::*;
use nexus_prover::pp::{gen_or_load, gen_to_file, load_pp};

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

        /// SRS file: if supplied, compressible proof is generated
        #[arg(short = 's', long = "srs")]
        srs_file: Option<String>,
    },

    /// Compress a Nexus proof via supernova
    Compress {
        /// public parameters file
        #[arg(
            short = 'p',
            long = "public-params",
            default_value = "nexus-public.zst"
        )]
        pp_file: String,

        /// srs file
        #[arg(
            short = 's',
            long = "structured-reference-string",
            default_value = "nexus-srs.zst"
        )]
        srs_file: String,

        /// File containing uncompressed proof
        #[arg(short, long, default_value = "nexus-proof.json")]
        file: String,

        /// Specifies whether we are compressing a local proof
        #[arg(short, long, default_value = "false")]
        local: bool,
    },
}
use Command::*;

fn main() -> Result<(), ProofError> {
    let opts = Opts::parse();

    match opts.command {
        Gen { k, par, pp_file, com, srs_file } => {
            gen_to_file(k, par, com, &pp_file, srs_file.as_deref())
        }

        Prove { gen, par, pp_file, vm, srs_file } => {
            let trace = run(&vm, par)?;

            match if par {
                match srs_file {
                    Some(srs_file) => {
                        let srs = load_srs(&srs_file)?;
                        prove_par_com(gen_or_load(gen, vm.k, &pp_file, &(srs))?, trace)
                    }

                    None => prove_par(gen_or_load(gen, vm.k, &pp_file, &())?, trace),
                }
            } else {
                prove_seq(gen_or_load(gen, vm.k, &pp_file, &())?, trace)
            } {
                Ok(_proof) => Ok(()),
                Err(e) => Err(e),
            }
        }

        Compress { pp_file, srs_file, file, local } => {
            println!("Reading srs file");
            let srs = load_srs(&srs_file)?;

            println!("Reading pp file");
            let pp: ComPP = load_pp(&pp_file)?;

            let proof = load_proof(&file)?;

            let result = compress(pp, srs, proof, local);

            match result {
                Ok(_) => Ok(()),
                Err(e) => Err(e),
            }
        }
    }
}
