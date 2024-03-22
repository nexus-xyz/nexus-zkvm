#[cfg(feature = "snmalloc")]
#[global_allocator]
static ALLOC: snmalloc_rs::SnMalloc = snmalloc_rs::SnMalloc;

use ark_std::path::Path;
use clap::{Parser, Subcommand};
use tracing_subscriber::EnvFilter;

use nexus_prover::{
    compress,
    key::{gen_key_to_file, gen_or_load_key},
    load_proof,
    pp::{gen_or_load, gen_to_file, load_pp},
    prove_par, prove_par_com, prove_seq, run, save_proof,
    srs::load_srs,
    types::{ComPCDNode, ComPP},
    LOG_TARGET,
};
use nexus_riscv::VMOpts;

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

        /// SRS file: if not provided, proofs will not be compressible.
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

        /// File to save the proof
        #[arg(short = 'f', long = "proof_file")]
        proof_file: String,
    },
    /// Generate public parameters file
    SpartanKeyGen {
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

        /// public parameters file
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
        srs_file: Option<String>,

        /// File containing uncompressed proof
        #[arg(short = 'f', long = "proof-file", default_value = "nexus-proof.json")]
        proof_file: String,

        /// File to save compressed proof
        #[arg(
            short = 'c',
            long = "compressed-proof-file",
            default_value = "nexus-proof-compressed.json"
        )]
        compressed_proof_file: String,
    },
}
use Command::*;

fn main() -> anyhow::Result<()> {
    let filter = EnvFilter::from_default_env();
    tracing_subscriber::fmt()
        .with_span_events(tracing_subscriber::fmt::format::FmtSpan::CLOSE)
        .with_env_filter(filter)
        .init();

    let opts = Opts::parse();

    match opts.command {
        Gen { k, par, pp_file, srs_file } => {
            gen_to_file(k, par, &pp_file, srs_file.as_deref())?;
            Ok(())
        }

        SpartanKeyGen { pp_file, srs_file, key_file } => {
            gen_key_to_file(&pp_file, &srs_file, &key_file)?;
            Ok(())
        }

        Prove {
            gen,
            par,
            pp_file,
            vm,
            srs_file,
            proof_file,
        } => {
            let trace = run(&vm, par)?;
            let path = Path::new(&proof_file);
            if par {
                if srs_file.is_some() {
                    let srs = load_srs(&srs_file.unwrap())?;
                    let proof =
                        prove_par_com(gen_or_load(gen, vm.k, &pp_file, Some(&(srs)))?, trace)?;
                    save_proof(proof, path)
                } else {
                    let proof = prove_par(gen_or_load(gen, vm.k, &pp_file, Some(&()))?, trace)?;
                    save_proof(proof, path)
                }
            } else {
                let proof = prove_seq(&gen_or_load(gen, vm.k, &pp_file, Some(&()))?, trace)?;
                save_proof(proof, path)
            }
        }

        Compress {
            gen,
            key_file,
            pp_file,
            srs_file,
            proof_file,
            compressed_proof_file,
        } => {
            let key = gen_or_load_key(gen, &key_file, Some(&pp_file), srs_file.as_deref())?;

            tracing::info!(
                target: LOG_TARGET,
                path =?pp_file,
                "Reading the Nova public parameters",
            );

            let pp: ComPP = load_pp(&pp_file)?;

            tracing::info!(
                target: LOG_TARGET,
                proof_file = %proof_file,
                "Reading the proof",
            );
            let proof_path = Path::new(&proof_file);
            let node: ComPCDNode = load_proof(proof_path)?;

            let compressed_proof = compress(&pp, &key, node)?;
            let compressed_proof_path = Path::new(&compressed_proof_file);
            save_proof(compressed_proof, compressed_proof_path)
        }
    }
}
