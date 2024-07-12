use nexus_sdk::{
    hypernova::seq::{HyperNova, PP},
    Local, Parameters, Prover, Verifiable,
};

const EXAMPLE_NAME: &str = "example";

const TARGET_PATH: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../target/riscv32i-unknown-none-elf/release-unoptimized"
);

fn main() {
    let path = std::path::Path::new(TARGET_PATH).join(EXAMPLE_NAME);
    if path.try_exists().is_err() {
        panic!(
            "{}{} was not found, make sure to compile the program \
             with `cd examples && cargo build --release-unoptimized --bin {}`",
            "target/riscv32i-unknown-none-elf/release-unoptimized/", EXAMPLE_NAME, EXAMPLE_NAME,
        );
    }

    // HyperNova relies on an structured reference string (SRS).
    // So we use a testing setup call that generates one for us.
    println!("Setting up testing HyperNova public parameters...");
    let pp: PP = PP::generate_for_testing().expect("failed to generate parameters");

    // defaults to local proving
    let prover: HyperNova<Local> = HyperNova::new_from_file(&path).expect("failed to load program");

    // input and output types are both `()`
    println!("Proving execution of vm...");
    let proof = prover.prove(&pp).expect("failed to prove program");

    println!(">>>>> Logging\n{}<<<<<", proof.logs().join(""));

    print!("Verifying execution...");
    proof.verify(&pp).expect("failed to verify proof");

    println!("  Succeeded!");
}
