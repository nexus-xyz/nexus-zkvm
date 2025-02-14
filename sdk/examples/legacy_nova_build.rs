#[cfg(feature = "legacy-nova")]
mod legacy_nova_build {
    use nexus_sdk::{
        legacy::{
            compile::CompileOpts,
            nova::seq::{Nova, PP},
            LegacyProver, LegacyVerifiable,
        },
        Local, Parameters, Setup,
    };

    const PACKAGE: &str = "example_legacy";

    pub fn run() {
        let mut opts = CompileOpts::new(PACKAGE);
        opts.set_memlimit(8); // use an 8mb memory

        println!("Compiling guest program...");
        let mut prover: Nova<Local> =
            Nova::compile(&opts).expect("failed to compile guest program");

        println!("Setting up Nova public parameters...");
        let pp: PP = PP::generate(&()).expect("failed to generate parameters");

        println!("Loading parameters for proving...");
        prover
            .setup_parameters(&pp)
            .expect("failed to fix parameters");

        println!("Proving execution of vm...");
        let mut proof = prover.prove().expect("failed to prove program");

        println!(">>>>> Logging\n{}<<<<<", proof.logs().join(""));

        // Normally the prover communicates the seralized proof to the verifier who deserializes it.
        //
        // For minimality serialization scrubs the public parameters, so the verifier must load them.
        // We can simulate this by detatching.
        LegacyVerifiable::detach(&mut proof);

        println!("Loading parameters for verification...");
        proof
            .setup_parameters(&pp)
            .expect("failed to fix parameters");

        print!("Verifying execution...");
        proof.verify().expect("failed to verify proof");

        println!("  Succeeded!");
    }
}

#[cfg(feature = "legacy-nova")]
fn main() {
    legacy_nova_build::run();
}

#[cfg(not(feature = "legacy-nova"))]
fn main() {
    println!("This example requires the 'legacy-nova' feature to be enabled.");
    println!("Please rebuild with '--features legacy-nova'");
}
