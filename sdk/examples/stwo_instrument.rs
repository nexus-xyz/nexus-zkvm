use nexus_sdk::{
    compile::{cargo::CargoPackager, Compile, Compiler},
    stwo::seq::Stwo,
    ByGuestCompilation, Local, Prover, Verifiable, Viewable,
};
use std::time::Instant;

const PACKAGE: &str = "guest";

fn main() {
    println!("=== Nexus zkVM Host Program Execution ===");

    let start_time = Instant::now();

    print!("1. Compiling guest program...");
    let compile_start = Instant::now();
    let mut prover_compiler = Compiler::<CargoPackager>::new(PACKAGE);
    let prover: Stwo<Local> =
        Stwo::compile(&mut prover_compiler).expect("failed to compile guest program");
    let compile_duration = compile_start.elapsed();
    println!(" {} ms", compile_duration.as_millis());

    let elf = prover.elf.clone(); // save elf for use with verification

    print!("\n2. Proving execution of VM...");
    let prove_start = Instant::now();
    let (view, proof) = prover.prove().expect("failed to prove program");
    let prove_duration = prove_start.elapsed();
    println!(" {} ms", prove_duration.as_millis());

    println!("\n3. Execution Logs:");
    println!("-------------------");
    match view.logs() {
        Ok(logs) => println!("{}", logs.join("")),
        Err(e) => eprintln!("Error: Failed to retrieve debug logs - {}", e),
    }
    println!("-------------------");

    match view.exit_code() {
        Ok(code) => {
            if code == nexus_sdk::KnownExitCodes::ExitSuccess as u32 {
                println!(
                    "\n4. Execution completed successfully (Exit code: {})",
                    code
                );
            } else {
                eprintln!("\n4. Execution failed (Exit code: {})", code);
                return;
            }
        }
        Err(e) => {
            eprintln!("\nError: Failed to retrieve exit code - {}", e);
            return;
        }
    }

    print!("\n5. Verifying execution... ");
    let verify_start = Instant::now();
    proof
        .verify_expected::<(), ()>(
            &(), // no public input
            nexus_sdk::KnownExitCodes::ExitSuccess as u32,
            &(),  // no public output
            &elf, // expected elf (program binary)
            &[],  // no associated data,
        )
        .expect("failed to verify proof");
    let verify_duration = verify_start.elapsed();

    println!("Succeeded!");
    println!("   Verification time: {} ms", verify_duration.as_millis());
    println!("   Proofsize: {} bytes", proof.size_estimate());

    let total_duration = start_time.elapsed();
    println!("\n=== Execution and Verification Complete ===");
    println!("Total execution time: {} ms", total_duration.as_millis());
}
