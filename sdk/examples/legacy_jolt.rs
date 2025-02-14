#[cfg(feature = "legacy-jolt")]
mod legacy_jolt {
    use nexus_sdk::{
        legacy::{compile::CompileOpts, jolt::Jolt},
        Local,
    };

    const PACKAGE: &str = "example_legacy";
    const EXAMPLE: &str = "legacy_noecall";

    pub fn run() {
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
}

#[cfg(feature = "legacy-jolt")]
fn main() {
    legacy_jolt::run();
}

#[cfg(not(feature = "legacy-jolt"))]
fn main() {
    println!("This example requires the 'legacy' feature to be enabled.");
    println!("Please rebuild with '--features legacy-jolt'");
}
