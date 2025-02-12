use nexus_sdk::{
    legacy::{
        hypernova::seq::{HyperNova, PP, SRS},
        LegacyProver, LegacyVerifiable,
    },
    Local, Parameters, Reference, Setup,
};

const EXAMPLE_NAME: &str = "example_legacy";

const TARGET_PATH: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../target/riscv32i-unknown-none-elf/release"
);

fn main() {
    let path = std::path::Path::new(TARGET_PATH).join(EXAMPLE_NAME);
    if path.try_exists().is_err() {
        panic!(
            "{}{} was not found, make sure to compile the program \
             with `cd examples && cargo build --release --bin {}`",
            "target/riscv32i-unknown-none-elf/release/", EXAMPLE_NAME, EXAMPLE_NAME,
        );
    }

    // defaults to local proving
    let mut prover: HyperNova<Local> =
        HyperNova::new_from_file(&path).expect("failed to load program");

    println!("Setting up HyperNova reference string...");
    let srs: SRS = SRS::generate().expect("failed to generate reference string");

    println!("Setting up HyperNova public parameters...");
    let pp: PP = PP::generate(&srs).expect("failed to generate parameters");

    println!("Loading reference and parameters for proving...");
    prover
        .setup_reference(&srs)
        .expect("failed to fix reference");
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

    println!("Loading reference and parameters for verification...");
    proof
        .setup_reference(&srs)
        .expect("failed to fix reference");
    proof
        .setup_parameters(&pp)
        .expect("failed to fix parameters");

    print!("Verifying execution...");
    proof.verify().expect("failed to verify proof");

    println!("  Succeeded!");
}
