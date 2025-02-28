use nexus_sdk::{stwo::seq::Stwo, Local, Prover, Verifiable, Viewable};

const EXAMPLE_NAME: &str = "input_output";

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

    let prover: Stwo<Local> = Stwo::new_from_file(&path).expect("failed to load program");

    let elf = prover.elf.clone(); // save elf for use with verification

    print!("Proving execution of vm... ");
    let (view, proof) = prover
        .prove_with_input::<u32, u32>(&3, &5)
        .expect("failed to prove program"); // x = 5, y = 3

    assert_eq!(
        view.exit_code().expect("failed to retrieve exit code"),
        nexus_sdk::KnownExitCodes::ExitSuccess as u32
    );

    let output: u32 = view
        .public_output::<u32>()
        .expect("failed to retrieve public output");
    assert_eq!(output, 15); // z = 15

    println!("output is {}!", output);
    println!(
        ">>>>> Logging\n{}<<<<<",
        view.logs().expect("failed to retrieve debug logs").join("")
    );

    // Normally the prover communicates the seralized proof to the verifier who deserializes it.
    //
    // The verifier must also possess the program binary and the public i/o. Usually, either
    // the verifier will rebuild the elf in a reproducible way (e.g., within a container) or
    // the prover will communicate it to the verifier who will then check that it is a valid
    // compilation of the claimed guest program. Here we simulate the latter.
    //
    // If we instead wanted to simulate the former, it might look something like:
    //
    // println!("Verifier recompiling guest program...");
    // let mut verifier_compiler = Compiler::<CargoPackager>::new(PACKAGE);
    // let path = verifier_compiler.build().expect("failed to (re)compile guest program");
    //
    // print!("Verifying execution...");
    // proof.verify_expected_from_program_path::<&str, u32, u32>(
    //    &5,    // x = 5
    //    nexus_sdk::KnownExitCodes::ExitSuccess as u32,
    //    &15,   // z = 15
    //    &path, // path to expected program binary
    //    &[]    // no associated data,
    // ).expect("failed to verify proof");

    print!("Verifying execution...");

    #[rustfmt::skip]
    proof
        .verify_expected::<u32, u32>(
            &5,   // x = 5
            nexus_sdk::KnownExitCodes::ExitSuccess as u32,
            &15,  // z = 15
            &elf, // expected elf (program binary)
            &[],  // no associated data,
        )
        .expect("failed to verify proof");

    println!("  Succeeded!");
}
