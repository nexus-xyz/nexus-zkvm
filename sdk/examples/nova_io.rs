use nexus_sdk::{
    nova::seq::{Nova, Proof, PP},
    Local, Parameters, Prover,
};

const EXAMPLE_NAME: &str = "input_output";

const TARGET_PATH: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../target/riscv32i-unknown-none-elf/release-unoptimized"
);

fn main() {
    let path = std::path::Path::new(TARGET_PATH).join(EXAMPLE_NAME);
    if path.try_exists().is_err() {
        panic!(
            "{}{} was not found, make sure to compile the program \
             with `cd examples && cargo build --bin {}`",
            "target/riscv32i-unknown-none-elf/release-unoptimized/", EXAMPLE_NAME, EXAMPLE_NAME,
        );
    }

    println!("Setting up Nova public parameters...");
    let pp: PP = PP::generate().expect("failed to generate parameters");

    // defaults to local proving
    let prover: Nova<Local> = Nova::new_from_file(&path).expect("failed to load program");

    // input type is (u32, u32), output type is i32
    let input = (3 as u32, 5 as u32);

    print!("Proving execution of vm...");
    let (proof, output): (Proof, i32) = prover
        .prove::<(u32, u32), i32>(&pp, Some(input))
        .expect("failed to prove program");

    println!(" output is {}!", output);

    print!("Verifying execution...");
    proof.verify(&pp).expect("failed to verify proof");

    println!("  Succeeded!");
}
