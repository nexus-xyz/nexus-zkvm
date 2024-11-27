#[cfg(test)]
mod test {
    use nexus_common::cpu::InstructionResult;

    use nexus_vm::elf::ElfFile;
    use nexus_vm::emulator::MemoryTranscript;
    use nexus_vm::emulator::{Emulator, HarvardEmulator, LinearEmulator, LinearMemoryLayout};
    use postcard::{from_bytes, to_allocvec};
    use serde::{de::DeserializeOwned, Serialize};
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
    fn emulate<
        T: Serialize,
        U: Serialize + DeserializeOwned + std::fmt::Debug + PartialEq + Clone,
    >(
        elfs: Vec<ElfFile>,
        input: Option<T>,
        expected_output: Option<U>,
        expected_result: Result<
            (Vec<InstructionResult>, MemoryTranscript),
            nexus_vm::error::VMError,
        >,
        emulator_type: EmulatorType,
    ) {
        // Serialize the input.
        let mut input_bytes = Vec::<u8>::new();
        if let Some(input) = &input {
            input_bytes = to_allocvec(input).expect("Serialization failed");
        }

        let mut deserialized_output: Option<U> = None;
        let ad = vec![0u8; 0xbeef as usize]; // placeholder ad until we have use for it

        for elf in elfs {
            match emulator_type {
                EmulatorType::Harvard | EmulatorType::TwoPass => {
                    // Use elf file to build the harvard emulator.
                    let mut emulator = HarvardEmulator::from_elf(elf.clone(), &input_bytes, &[]);

                    // Check that the program exits correctly.
                    assert_eq!(emulator.execute(), expected_result);

                    // Deserialize the output.
                    if expected_output.is_some() {
                        let output_bytes = emulator.get_output().unwrap();
                        deserialized_output =
                            Some(from_bytes(&output_bytes).expect("Deserialization failed"));
                    }

                    // Run a second pass with a linear emulator constructed from the harvard emulator.
                    if matches!(emulator_type, EmulatorType::TwoPass) {
                        // Check that the intermediate output is correct.
                        assert_eq!(deserialized_output, expected_output);

                        // Use the data obtained from the harvard emulator to construct the linear emulator.
                        let mut linear_emulator =
                            LinearEmulator::from_harvard(emulator, elf, &ad, &[]).unwrap();

                        // Check that the program exits correctly.
                        assert_eq!(linear_emulator.execute(), expected_result);

                        // Deserialize the output.
                        if expected_output.is_some() {
                            let output_bytes = linear_emulator.get_output().unwrap();
                            deserialized_output =
                                Some(from_bytes(&output_bytes).expect("Deserialization failed"));
                        }
                    }
                }
                EmulatorType::Linear(heap_size, stack_size, program_size) => {
                    // Calculate the output length.
                    let mut output_len = 0;
                    if let Some(expected_output) = expected_output.clone() {
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
                    let mut emulator =
                        LinearEmulator::from_elf(memory_layout, &ad, elf, &input_bytes, &[]);

                    // Check that the program exits correctly.
                    assert_eq!(emulator.execute(), expected_result);

                    // Deserialize the output.
                    if expected_output.is_some() {
                        let output_bytes = emulator.get_output().unwrap();
                        deserialized_output =
                            Some(from_bytes(&output_bytes).expect("Deserialization failed"));
                    }
                }
            };
        }

        // Check that the program exits correctly.
        assert_eq!(deserialized_output, expected_output);
    }

    #[test]
    fn test_emulate() {
        let emulators = vec![
            EmulatorType::Harvard,
            EmulatorType::default_linear(),
            EmulatorType::TwoPass,
        ];
        let io_u32_elfs = compile_multi("io_u32", &["-C opt-level=0", ""]);
        let io_u64_elfs = compile_multi("io_u64", &["-C opt-level=0", ""]);
        let io_u128_elfs = compile_multi("io_u128", &["-C opt-level=0", ""]);

        for emulator in emulators {
            emulate::<u32, u32>(
                io_u32_elfs.clone(),
                Some(123u32),
                Some(123u32),
                Err(nexus_vm::error::VMError::VMExited(0)),
                emulator.clone(),
            );
            emulate::<u64, u64>(
                io_u64_elfs.clone(),
                Some(1u64 << 32),
                Some(1u64 << 32),
                Err(nexus_vm::error::VMError::VMExited(0)),
                emulator.clone(),
            );
            emulate::<u128, u128>(
                io_u128_elfs.clone(),
                Some(332306998946228968225970211937533483u128),
                Some(332306998946228968225970211937533483u128),
                Err(nexus_vm::error::VMError::VMExited(0)),
                emulator,
            );
        }
    }

    #[test]
    fn test_fib() {
        let inputs = vec![1u32, 10u32, 20u32];
        let outputs = vec![1u32, 34u32, 4181u32];
        let emulators = vec![
            EmulatorType::Harvard,
            EmulatorType::default_linear(),
            EmulatorType::TwoPass,
        ];
        let elfs = compile_multi(
            "fib",
            &[
                "-C opt-level=0",
                "-C opt-level=1",
                "-C opt-level=2",
                "-C opt-level=3",
            ],
        );

        for (input, output) in inputs.iter().zip(outputs.iter()) {
            for emulator in emulators.clone() {
                emulate::<u32, u32>(
                    elfs.clone(),
                    Some(input.clone()),
                    Some(output.clone()),
                    Err(nexus_vm::error::VMError::VMExited(0)),
                    emulator.clone(),
                );
            }
        }
    }
}
