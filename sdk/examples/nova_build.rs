use nexus_sdk::{
    compile::CompileOpts,
    nova::seq::{Nova, Proof, PP},
    Local, Parameters, Prover,
};

const PACKAGE: &str = "example";
const EXAMPLE: &str = "example"; // `main.rs` of `example` package compiles to binary `example`

fn main() {
    let mut opts = CompileOpts::new(PACKAGE, EXAMPLE);
    opts.set_memlimit(8); // use an 8mb memory

    println!("Compiling guest program...");
    let path = Nova::compile(&opts).expect("failed to compile guest program");

    println!("Setting up Nova public parameters...");
    let pp: PP = PP::generate().expect("failed to generate parameters");

    // defaults to local proving
    let prover: Nova<Local> = Nova::new_from_file(&path).expect("failed to load program");

    // input and output types are both `()`
    println!("Proving execution of vm...");
    let (proof, _): (Proof, ()) = prover
        .prove::<(), ()>(&pp, None)
        .expect("failed to prove program");

    print!("Verifying execution...");
    proof.verify(&pp).expect("failed to verify proof");

    println!("  Succeeded!");
}
