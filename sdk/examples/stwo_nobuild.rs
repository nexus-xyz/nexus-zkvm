use nexus_sdk::{stwo::seq::Stwo, Local, Prover, Verifiable, Viewable};

const EXAMPLE_NAME: &str = "example";

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

    println!("Proving execution of vm...");
    let (view, proof) = prover.prove().expect("failed to prove program");

    println!(
        ">>>>> Logging\n{}<<<<<",
        view.logs().expect("failed to retrieve debug logs").join("")
    );
    assert_eq!(
        view.exit_code().expect("failed to retrieve exit code"),
        nexus_sdk::KnownErrorCodes::ExitSuccess as u32
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
    // proof.verify_expected_from_program_path::<&str, (), ()>(
    //    &(),   // no public input
    //    nexus_sdk::KnownErrorCodes::ExitSuccess as u32,
    //    &(),   // no public output
    //    &path, // path to expected program binary
    //    &[]    // no associated data,
    // ).expect("failed to verify proof");

    print!("Verifying execution...");

    #[rustfmt::skip]
    proof
        .verify_expected::<(), ()>(
            &(),  // no public input
            nexus_sdk::KnownErrorCodes::ExitSuccess as u32,
            &(),  // no public output
            &elf, // expected elf (program binary)
            &[],  // no associated data,
        )
        .expect("failed to verify proof");

    println!("  Succeeded!");
}
