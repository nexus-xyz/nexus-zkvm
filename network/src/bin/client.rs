use std::path::PathBuf;
use clap::{Parser, Subcommand};
use nexus_network::client::*;

#[derive(Debug, Parser)]
struct Opts {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    Submit {
        path_to_elf: PathBuf,
    },
    Query {
        hash: String,

        #[arg(short)]
        path_to_save: Option<PathBuf>,
    },
}

fn main() {
    let opts = Opts::parse();

    let proof = match opts.command {
        Command::Submit { path_to_elf } => {
            submit_proof("account".to_string(), &path_to_elf).unwrap()
        }
        Command::Query { hash, path_to_save } => {
            let proof = fetch_proof(&hash).unwrap();
            let path = path_to_save.unwrap_or_else(|| PathBuf::from("nexus-proof.json"));

            if proof.proof.is_some() {
                println!("Saving proof...");
                let serialized = serde_json::to_vec(&proof).unwrap();
                std::fs::write(path, &serialized).unwrap();
            }

            proof
        }
    };

    println!("{}", proof);
}
