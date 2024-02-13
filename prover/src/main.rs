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
use nexus_prover::key::{gen_key_to_file, gen_or_load_key};

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
    /// Generate public parameters file
    SpartanKeyGen {
        /// whether to generate Nova public parameters
        #[arg(short = 'g', long = "gen-pp", default_value = "true")]
        gen_pp: bool,

        /// instructions per step: only required if 'gen_pp' is true
        #[arg(short, name = "k", default_value = "1")]
        k: Option<usize>,

        /// public parameters file
        #[arg(
            short = 'p',
            long = "public-params",
            default_value = "nexus-public.zst"
        )]
        pp_file: String,

        /// SRS file
        #[arg(short = 's', long = "srs")]
        srs_file: String,

        /// Spartan key file
        #[arg(
            short = 'k',
            long = "spartan-key",
            default_value = "nexus-spartan-key.zst"
        )]
        key_file: String,
    },

    /// Compress a Nexus proof via supernova
    Compress {
        /// generate Spartan key (ignore files)
        #[arg(short)]
        gen: bool,

        /// Spartan key file
        #[arg(
            short = 'k',
            long = "spartan-key",
            default_value = "nexus-spartan-key.zst"
        )]
        key_file: String,

        /// public parameters file; only needed if `gen` is `false`
        #[arg(
            short = 'p',
            long = "public-params",
            default_value = "nexus-public.zst"
        )]
        pp_file: String,

        /// srs file; only needed if `gen` is `false`
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

        SpartanKeyGen { gen_pp, k, pp_file, srs_file, key_file } => {
            let k = match gen_pp {
                //todo: error handling
                true => k.unwrap(),
                false => 1,
            };
            let srs = load_srs(&srs_file)?;
            let pp: ComPP = gen_or_load(gen_pp, k, &pp_file, &srs)?;
            gen_key_to_file(&pp, &srs, &key_file)
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

        Compress {
            gen,
            key_file,
            pp_file,
            srs_file,
            file,
            local,
        } => {
            println!("Reading srs file");
            let srs = load_srs(&srs_file)?;

            println!("Reading pp file");
            let pp: ComPP = load_pp(&pp_file)?;

            let key = gen_or_load_key(gen, &key_file, &pp, &srs)?;

            let proof = load_proof(&file)?;

            let result = compress(&pp, &key, proof, local);

            match result {
                Ok(_) => Ok(()),
                Err(e) => Err(e),
            }
        }
    }
}
