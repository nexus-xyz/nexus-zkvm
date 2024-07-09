use nexus_sdk::{
    compile::CompileOpts,
    nova::seq::{Nova, PP},
    Local, Parameters, Prover, Verifiable,
};

const PACKAGE: &str = "example";
const EXAMPLE: &str = "example"; // `main.rs` of `example` package compiles to binary `example`

fn main() {
    println!("Setting up Nova public parameters...");
    let pp: PP = PP::generate().expect("failed to generate parameters");

    let mut opts = CompileOpts::new(PACKAGE, EXAMPLE);
    opts.set_memlimit(8); // use an 8mb memory

    println!("Compiling guest program...");
    let prover: Nova<Local> = Nova::compile(&opts).expect("failed to compile guest program");

    // input and output types are both `()`
    println!("Proving execution of vm...");
    let proof = prover
        .prove::<(), ()>(&pp, None)
        .expect("failed to prove program");

    println!(">>>>> Logging\n{}<<<<<", proof.logs());

    print!("Verifying execution...");
    proof.verify(&pp).expect("failed to verify proof");

    println!("  Succeeded!");
}
