use nexus_sdk::{nova::seq::{Nova, Proof, PP}, Parameters, Prover, Local};

const EXAMPLE_NAME: &str = "private_input";

const TARGET_PATH: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../target/riscv32i-unknown-none-elf/release"
);

fn main() {

    let path = std::path::Path::new(TARGET_PATH).join(EXAMPLE_NAME);
    if !path.try_exists().is_ok() {
        panic!(
            "{}{} was not found, make sure to compile the program \
             with `cd examples && cargo build --release --bin {}`",
            "target/riscv32i-unknown-none-elf/release/", EXAMPLE_NAME, EXAMPLE_NAME,
        );
    }

    println!("Setting up Nova public parameters...");
    let pp: PP = PP::generate()
        .expect("failed to generate parameters");

    // defaults to local proving
    let prover: Nova<Local> = Nova::new_from_file(&path)
        .expect("failed to load program");

    let input: u8 = 0x06;

    println!("Proving execution of vm...");
    let proof: Proof = prover.prove::<u8>(&pp, Some(input))
        .expect("failed to prove program");

    print!("Verifying execution...");
    proof.verify(&pp)
        .expect("failed to verify proof");

    println!("  Succeeded!");
}
