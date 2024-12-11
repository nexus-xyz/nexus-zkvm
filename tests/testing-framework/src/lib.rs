#[cfg(test)]
mod test {
    use nexus_common::cpu::InstructionResult;

    use nexus_vm::elf::ElfFile;
    use nexus_vm::emulator::MemoryTranscript;
    use nexus_vm::emulator::{Emulator, HarvardEmulator, LinearEmulator, LinearMemoryLayout};
    use postcard::{from_bytes, to_allocvec};
    use serde::{de::DeserializeOwned, Serialize};
    use serial_test::serial;
    use std::{path::PathBuf, process::Command};
    use tempfile::{tempdir, TempDir};

    #[derive(Clone)]
    enum EmulatorType {
        Harvard,
        Linear(u32, u32, u32), // heap size, stack size, program size
        TwoPass,
    }

    impl EmulatorType {
        fn default_linear() -> Self {
            Self::Linear(0x800000, 0x100000, 0x80000)
        }
    }

    trait Input: Serialize + std::fmt::Debug + Clone {}
    impl<T> Input for T where T: Serialize + std::fmt::Debug + Clone {}
    trait Output: Serialize + DeserializeOwned + std::fmt::Debug + PartialEq + Clone {}
    impl<T> Output for T where T: Serialize + DeserializeOwned + std::fmt::Debug + PartialEq + Clone {}

    struct IOArgs<T: Input, U: Input, V: Output> {
        pub public_input: Option<T>,
        pub private_input: Option<U>,
        pub expected_output: Option<V>,
        pub expected_result:
            Result<(Vec<InstructionResult>, MemoryTranscript), nexus_vm::error::VMError>,
    }

    impl<T: Input, U: Input, V: Output> Default for IOArgs<T, U, V> {
        fn default() -> Self {
            Self {
                public_input: None,
                private_input: None,
                expected_output: None,
                expected_result: Err(nexus_vm::error::VMError::VMExited(0)),
            }
        }
    }

    impl<T: Input, U: Input, V: Output> IOArgs<T, U, V> {
        fn default_list() -> Vec<Self> {
            vec![Self::default()]
        }

        fn new(input: Option<T>, private_input: Option<U>, expected_output: Option<V>) -> Self {
            Self {
                public_input: input,
                private_input,
                expected_output,
                expected_result: Err(nexus_vm::error::VMError::VMExited(0)),
            }
        }

        fn simple_panic() -> Self {
            Self {
                public_input: None,
                private_input: None,
                expected_output: None,
                expected_result: Err(nexus_vm::error::VMError::VMExited(1)),
            }
        }
    }

    /// Create a temporary directory with a new Cargo project that has nexus_rt as a local dependency.
    fn create_tmp_dir() -> TempDir {
        // Create a temporary directory.
        let tmp_dir = tempdir().expect("Failed to create temporary directory");
        let tmp_dir_path = tmp_dir.path().join("integration");
        let tmp_dir_str = tmp_dir_path.to_str().unwrap();

        // Create a new Cargo project.
        let mut output = Command::new("cargo")
            .arg("new")
            .arg(tmp_dir_str)
            .output()
            .expect("Failed to create new Cargo project");

        assert!(output.status.success());

        // Get the current directory.
        let runtime_dir = std::env::current_dir().unwrap().join("../../runtime");

        // Add the nexus_rt dependency to the `Cargo.toml` file.
        output = Command::new("cargo")
            .current_dir(tmp_dir_str)
            .arg("add")
            .arg("nexus-rt")
            .arg("--path")
            .arg(runtime_dir)
            .output()
            .expect("Failed to add nexus_rt dependency");

        assert!(output.status.success());

        tmp_dir
    }

    /// Compile the test file.
    fn compile_to_elf(tmp_project_path: PathBuf, test_path: &str, compile_flags: &str) -> Vec<u8> {
        // Overwrite the main.rs file with the test file.
        let main_file = format!("{}/src/main.rs", tmp_project_path.clone().to_str().unwrap());
        let target = "riscv32i-unknown-none-elf";

        let mut output = Command::new("cp")
            .arg(test_path)
            .arg(main_file)
            .output()
            .expect("Failed to copy test file");

        assert!(output.status.success());

        let linker_script = std::env::current_dir()
            .unwrap()
            .join("../../runtime/linker-scripts/default.x");

        // Compile the test file for riscv target.
        output = Command::new("cargo")
            .current_dir(tmp_project_path.clone())
            .arg("build")
            .arg("--target")
            .arg(target)
            .env(
                "RUSTFLAGS",
                &format!(
                    "{compile_flags} -C relocation-model=pic -C panic=abort -C link-arg=-T{}",
                    linker_script.display()
                ),
            ) // Disable optimizations.
            .output()
            .expect("Failed to run test");

        if !output.status.success() {
            eprintln!("Error: {}", String::from_utf8_lossy(&output.stderr));
            panic!("cargo build failed for RISC-V target");
        }
        assert!(output.status.success());

        // Read the elf file to bytes.
        let elf_file = format!(
            "{}/target/{target}/debug/integration",
            tmp_project_path.clone().to_str().unwrap()
        );

        std::fs::read(elf_file).expect("Failed to read elf file")
    }

    fn compile_multi(test_name: &str, compile_flags: &[&str]) -> Vec<ElfFile> {
        let mut elfs = Vec::<ElfFile>::new();
        // Set up the temporary directories for intermediate project setup.
        let tmp_dir = &create_tmp_dir();
        let tmp_project_path = tmp_dir.path().join("integration");

        for flag_set in compile_flags {
            // Check that the tests compile and execute correctly.
            // Compile the test file.
            let test_dir_path = "../integration-tests";
            let test_path = format!("{test_dir_path}/{test_name}.rs");
            let elf_contents = compile_to_elf(tmp_project_path.clone(), &test_path, flag_set);

            // Save the elf file for debugging purposes.
            let elf_path = format!("{test_dir_path}/{test_name}.elf");
            std::fs::write(&elf_path, &elf_contents).expect("Failed to write file");

            // Parse the elf file.
            let elf = ElfFile::from_bytes(&elf_contents).expect("Unable to load ELF from bytes");
            elfs.push(elf);
        }
        elfs
    }

    /// Helper function to run emulator and check that the inputs and outputs are correct.
    fn emulate<T: Input, U: Input, V: Output>(
        elfs: Vec<ElfFile>,
        io_args: &IOArgs<T, U, V>,
        emulator_type: EmulatorType,
    ) {
        // Serialize the input.
        let mut input_bytes = Vec::<u8>::new();
        if let Some(input) = &io_args.public_input {
            input_bytes = to_allocvec(input).expect("Serialization failed");
        }

        let mut private_input_bytes = Vec::<u8>::new();
        if let Some(private_input) = &io_args.private_input {
            private_input_bytes = to_allocvec(private_input).expect("Serialization failed");
        }

        let mut deserialized_output: Option<V> = None;
        let ad = vec![0u8; 0xbeef as usize]; // placeholder ad until we have use for it

        for elf in elfs {
            match emulator_type {
                EmulatorType::Harvard | EmulatorType::TwoPass => {
                    // Use elf file to build the harvard emulator.
                    let mut emulator =
                        HarvardEmulator::from_elf(elf.clone(), &input_bytes, &private_input_bytes);

                    // Check that the program exits correctly.
                    assert_eq!(&emulator.execute(), &io_args.expected_result);

                    // Deserialize the output.
                    if io_args.expected_output.is_some() {
                        let output_bytes = emulator.get_output().unwrap();
                        deserialized_output =
                            Some(from_bytes(&output_bytes).expect("Deserialization failed"));
                    }

                    // Run a second pass with a linear emulator constructed from the harvard emulator.
                    if matches!(emulator_type, EmulatorType::TwoPass) {
                        // Check that the intermediate output is correct.
                        assert_eq!(deserialized_output, io_args.expected_output);

                        // Use the data obtained from the harvard emulator to construct the linear emulator.
                        let mut linear_emulator =
                            LinearEmulator::from_harvard(emulator, elf, &ad, &private_input_bytes)
                                .unwrap();

                        // Check that the program exits correctly.
                        assert_eq!(&linear_emulator.execute(), &io_args.expected_result);

                        // Deserialize the output.
                        if io_args.expected_output.is_some() {
                            let output_bytes = linear_emulator.get_output().unwrap();
                            deserialized_output =
                                Some(from_bytes(&output_bytes).expect("Deserialization failed"));
                        }
                    }
                }
                EmulatorType::Linear(heap_size, stack_size, program_size) => {
                    // Calculate the output length.
                    let mut output_len = 0;
                    if let Some(expected_output) = io_args.expected_output.clone() {
                        output_len = to_allocvec(&expected_output)
                            .expect("Serialization failed")
                            .len();
                    }
                    // Construct the memory layout.
                    let memory_layout = LinearMemoryLayout::new(
                        heap_size,
                        stack_size,
                        input_bytes.len() as u32,
                        output_len as u32,
                        program_size,
                        ad.len() as u32,
                    )
                    .expect("Invalid memory layout");

                    // Construct the linear emulator.
                    let mut emulator = LinearEmulator::from_elf(
                        memory_layout,
                        &ad,
                        elf,
                        &input_bytes,
                        &private_input_bytes,
                    );

                    // Check that the program exits correctly.
                    assert_eq!(&emulator.execute(), &io_args.expected_result);

                    // Deserialize the output.
                    if io_args.expected_output.is_some() {
                        let output_bytes = emulator.get_output().unwrap();
                        deserialized_output =
                            Some(from_bytes(&output_bytes).expect("Deserialization failed"));
                    }
                }
            };
        }

        // Check that the program exits correctly.
        assert_eq!(deserialized_output, io_args.expected_output);
    }

    /// Helper function to run test accross multiple emulators, multiple opt levels, and multiple inputs.
    fn test_example_multi<T: Input, U: Input, V: Output>(
        emulators: Vec<EmulatorType>,
        compile_flags: Vec<&str>,
        name: &str,
        io_args: Vec<IOArgs<T, U, V>>,
    ) {
        let elfs = compile_multi(name, &compile_flags);

        for emulator in &emulators {
            for io_arg in &io_args {
                emulate::<T, U, V>(elfs.clone(), io_arg, emulator.clone());
            }
        }
    }

    #[test]
    #[serial]
    fn test_fact_example() {
        test_example_multi(
            vec![
                EmulatorType::Harvard,
                EmulatorType::default_linear(),
                EmulatorType::TwoPass,
            ],
            vec!["-C opt-level=3"],
            "../../examples/src/fact",
            IOArgs::<(), (), ()>::default_list(),
        );
    }

    #[test]
    #[serial]
    fn test_fib_example() {
        test_example_multi(
            vec![
                EmulatorType::Harvard,
                EmulatorType::default_linear(),
                EmulatorType::TwoPass,
            ],
            vec!["-C opt-level=3"],
            "../../examples/src/fib",
            IOArgs::<(), (), ()>::default_list(),
        );
    }

    #[test]
    #[serial]
    fn test_fib1000_example() {
        test_example_multi(
            vec![
                EmulatorType::Harvard,
                EmulatorType::default_linear(),
                EmulatorType::TwoPass,
            ],
            vec!["-C opt-level=3"],
            "../../examples/src/fib1000",
            IOArgs::<(), (), ()>::default_list(),
        );
    }

    #[test]
    #[serial]
    fn test_main_example() {
        test_example_multi(
            vec![
                EmulatorType::Harvard,
                EmulatorType::default_linear(),
                EmulatorType::TwoPass,
            ],
            vec!["-C opt-level=3"],
            "../../examples/src/main",
            IOArgs::<(), (), ()>::default_list(),
        );
    }

    #[test]
    #[serial]
    fn test_palindromes_example() {
        test_example_multi(
            vec![
                EmulatorType::Harvard,
                EmulatorType::default_linear(),
                EmulatorType::TwoPass,
            ],
            vec!["-C opt-level=3"],
            "../../examples/src/palindromes",
            IOArgs::<(), (), ()>::default_list(),
        );
    }

    #[test]
    #[serial]
    fn test_galeshapley_example() {
        test_example_multi(
            vec![
                EmulatorType::Harvard,
                EmulatorType::default_linear(),
                EmulatorType::TwoPass,
            ],
            vec!["-C opt-level=3"],
            "../../examples/src/galeshapley",
            IOArgs::<(), (), ()>::default_list(),
        );
    }

    #[test]
    #[serial]
    fn test_lambda_calculus_example() {
        test_example_multi(
            vec![
                EmulatorType::Harvard,
                EmulatorType::default_linear(),
                EmulatorType::TwoPass,
            ],
            vec!["-C opt-level=3"],
            "../../examples/src/lambda_calculus",
            IOArgs::<(), (), ()>::default_list(),
        );
    }

    #[test]
    #[serial]
    fn test_fail_example() {
        test_example_multi(
            vec![
                EmulatorType::Harvard,
                EmulatorType::default_linear(),
                EmulatorType::TwoPass,
            ],
            vec!["-C opt-level=3"],
            "../../examples/src/fail",
            vec![IOArgs::<(), (), ()>::simple_panic()],
        );
    }

    #[test]
    #[serial]
    fn test_input_output_example() {
        test_example_multi(
            vec![
                EmulatorType::Harvard,
                EmulatorType::default_linear(),
                EmulatorType::TwoPass,
            ],
            vec!["-C opt-level=3"],
            "../../examples/src/input_output",
            vec![
                IOArgs::<u32, u32, u32>::new(Some(3u32), Some(4u32), Some(12u32)),
                IOArgs::<u32, u32, u32>::new(Some(4u32), Some(0u32), Some(0u32)),
                IOArgs::<u32, u32, u32>::new(Some(1_048_576u32), Some(4u32), Some(4_194_304u32)),
            ],
        );
    }

    #[test]
    #[serial]
    fn test_keccak_example() {
        test_example_multi(
            vec![
                EmulatorType::Harvard,
                EmulatorType::default_linear(),
                EmulatorType::TwoPass,
            ],
            vec!["-C opt-level=3"],
            "../../examples/src/keccak",
            IOArgs::<(), (), ()>::default_list(),
        );
    }

    #[test]
    #[ignore]
    fn test_examples_all_opt_levels() {
        let emulators = vec![
            EmulatorType::Harvard,
            EmulatorType::default_linear(),
            EmulatorType::TwoPass,
        ];
        let compile_flags = vec![
            "-C opt-level=0",
            "-C opt-level=1",
            "-C opt-level=2",
            "-C opt-level=3",
        ];
        let examples = vec![
            "fact",
            "fib",
            "fib1000",
            "main",
            "palindromes",
            "galeshapley",
            "lambda_calculus",
            "keccak",
        ];

        // Test simple examples.
        for example in examples {
            let example_path = format!("../../examples/src/{}", example);
            let elfs = compile_multi(&example_path, &compile_flags);

            for emulator in &emulators {
                emulate::<(), (), ()>(
                    elfs.clone(),
                    &IOArgs::<(), (), ()>::default(),
                    emulator.clone(),
                );
            }
        }

        // Test fail example.
        let fail_path = "../../examples/src/fail";
        let fail_elfs = compile_multi(fail_path, &compile_flags);

        for emulator in &emulators {
            emulate::<(), (), ()>(
                fail_elfs.clone(),
                &IOArgs::<(), (), ()>::simple_panic(),
                emulator.clone(),
            );
        }
    }

    #[test]
    #[serial]
    fn test_emulate() {
        let emulators = vec![
            EmulatorType::Harvard,
            EmulatorType::default_linear(),
            EmulatorType::TwoPass,
        ];
        let compile_flags = vec!["-C opt-level=3"];
        let io_u32_elfs = compile_multi("io_u32", &compile_flags);
        let io_u64_elfs = compile_multi("io_u64", &compile_flags);
        let io_u128_elfs = compile_multi("io_u128", &compile_flags);

        for emulator in emulators {
            emulate::<u32, (), u32>(
                io_u32_elfs.clone(),
                &IOArgs::<u32, (), u32>::new(Some(123u32), None, Some(123u32)),
                emulator.clone(),
            );
            emulate::<u64, (), u64>(
                io_u64_elfs.clone(),
                &IOArgs::<u64, (), u64>::new(Some(1u64 << 32), None, Some(1u64 << 32)),
                emulator.clone(),
            );
            emulate::<u128, (), u128>(
                io_u128_elfs.clone(),
                &IOArgs::<u128, (), u128>::new(
                    Some(332306998946228968225970211937533483u128),
                    None,
                    Some(332306998946228968225970211937533483u128),
                ),
                emulator.clone(),
            );
        }
    }

    #[test]
    #[serial]
    fn test_fib() {
        let inputs = vec![1u32, 10u32, 20u32];
        let outputs = vec![1u32, 34u32, 4181u32];
        let emulators = vec![
            EmulatorType::Harvard,
            EmulatorType::default_linear(),
            EmulatorType::TwoPass,
        ];
        let elfs = compile_multi("fib", &["-C opt-level=3"]);

        for (input, output) in inputs.iter().zip(outputs.iter()) {
            for emulator in emulators.clone() {
                emulate::<u32, (), u32>(
                    elfs.clone(),
                    &IOArgs::<u32, (), u32>::new(Some(input.clone()), None, Some(output.clone())),
                    emulator.clone(),
                );
            }
        }
    }
}
