use nexus_sdk::{
    nova::seq::{Generate, Nova, PP},
    Local, Prover, Verifiable,
};

type Input = (u32, u32);
type Output = i32;

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
             with `cd examples && cargo build --release-unoptimized --bin {}`",
            "target/riscv32i-unknown-none-elf/release-unoptimized/", EXAMPLE_NAME, EXAMPLE_NAME,
        );
    }

    println!("Setting up Nova public parameters...");
    let pp: PP = PP::generate().expect("failed to generate parameters");

    // defaults to local proving
    let prover: Nova<Local> = Nova::new_from_file(&path).expect("failed to load program");

    let input: Input = (3, 5);

    print!("Proving execution of vm...");
    let proof = prover
        .prove_with_input::<Input>(&pp, &input)
        .expect("failed to prove program");

    println!(
        " output is {}!",
        proof
            .output::<Output>()
            .expect("failed to deserialize output")
    );

    println!(">>>>> Logging\n{}<<<<<", proof.logs().join(""));

    print!("Verifying execution...");
    proof.verify(&pp).expect("failed to verify proof");

    println!("  Succeeded!");
}
