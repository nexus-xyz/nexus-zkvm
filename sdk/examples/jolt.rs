use nexus_sdk::{compile::CompileOpts, jolt::Jolt, Local};

type Input = (u32, u32);
type Output = i32;

const PACKAGE: &str = "example";
const EXAMPLE: &str = "public_io";

fn main() {
    let opts = CompileOpts::new_with_custom_binary(PACKAGE, EXAMPLE);

    // defaults to local proving
    let prover: Jolt<Local> = Jolt::compile(&opts).expect("failed to load program");

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
    proof.verify().expect("failed to verify proof");

    println!("  Succeeded!");
}
