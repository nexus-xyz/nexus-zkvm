#[cfg(feature = "legacy-nova")]
mod legacy_nova_io {
    use nexus_sdk::{
        legacy::{
            nova::seq::{Nova, PP},
            LegacyProver, LegacyVerifiable,
        },
        Local, Parameters, Setup,
    };

    type Input = (u32, u32);
    type Output = i32;

    const EXAMPLE_NAME: &str = "legacy_input_output";

    const TARGET_PATH: &str = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../target/riscv32im-unknown-none-elf/release"
    );

    pub fn run() {
        let path = std::path::Path::new(TARGET_PATH).join(EXAMPLE_NAME);
        if path.try_exists().is_err() {
            panic!(
                "{}{} was not found, make sure to compile the program \
                 with `cd examples && cargo build --release --bin {}`",
                "target/riscv32im-unknown-none-elf/release/", EXAMPLE_NAME, EXAMPLE_NAME,
            );
        }

        // defaults to local proving
        let mut prover: Nova<Local> = Nova::new_from_file(&path).expect("failed to load program");

        println!("Setting up Nova public parameters...");
        let pp: PP = PP::generate(&()).expect("failed to generate parameters");

        println!("Loading parameters for proving...");
        prover
            .setup_parameters(&pp)
            .expect("failed to fix parameters");

        let input: Input = (3, 5);

        print!("Proving execution of vm...");
        let mut proof = prover
            .prove_with_input::<Input>(&input)
            .expect("failed to prove program");

        println!(
            " output is {}!",
            proof
                .output::<Output>()
                .expect("failed to deserialize output")
        );

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
    legacy_nova_io::run();
}

#[cfg(not(feature = "legacy-nova"))]
fn main() {
    println!("This example requires the 'legacy-nova' feature to be enabled.");
    println!("Please rebuild with '--features legacy-nova'");
}
