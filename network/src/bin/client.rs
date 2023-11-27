use std::path::PathBuf;
use clap::Parser;
use nexus_network::client::*;

#[derive(Debug, Parser)]
struct Opts {
    #[arg(group = "g", short)]
    program: Option<PathBuf>,

    #[arg(group = "g", short)]
    query: Option<String>,
}

fn main() {
    let opts = Opts::parse();

    let proof = if opts.program.is_some() {
        submit_proof("account".to_string(), &opts.program.unwrap()).unwrap()
    } else if opts.query.is_some() {
        fetch_proof(&opts.query.unwrap()).unwrap()
    } else {
        panic!()
    };

    println!("{}", proof);
}
