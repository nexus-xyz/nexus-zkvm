use nexus_sdk::{compile::CompileOpts, jolt::Jolt, Local};

const PACKAGE: &str = "example";
const EXAMPLE: &str = "noecall";

fn main() {
    let opts = CompileOpts::new_with_custom_binary(PACKAGE, EXAMPLE);

    // defaults to local proving
    let prover: Jolt<Local> = Jolt::compile_with_input::<u32>(&opts, &5_u32).expect("failed to load program");

    println!("Proving execution of vm...");
    let proof = prover.prove().expect("failed to prove program");

    print!("Verifying execution...");
    proof.verify().expect("failed to verify proof");

    println!("  Succeeded!");
}
