use nexus_sdk::{
    legacy::{compile::CompileOpts, jolt::Jolt},
    Local,
};

const PACKAGE: &str = "example_legacy";
const EXAMPLE: &str = "legacy_noecall";

fn main() {
    let opts = CompileOpts::new_with_custom_binary(PACKAGE, EXAMPLE);

    // defaults to local proving
    let prover: Jolt<Local> = Jolt::compile(&opts).expect("failed to load program");

    println!("Proving execution of vm...");
    let proof = prover.prove().expect("failed to prove program");

    // Normally the prover communicates the seralized proof to the verifier who deserializes it.

    print!("Verifying execution...");
    proof.verify().expect("failed to verify proof");

    println!("  Succeeded!");
}
