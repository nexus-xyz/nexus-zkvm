#[cfg(test)]
mod test {
    use nexus_common::cpu::InstructionResult;
    use nexus_vm::elf::ElfFile;
    use nexus_vm::emulator::MemoryTranscript;
    use nexus_vm::emulator::{Emulator, HarvardEmulator, LinearEmulator, LinearMemoryLayout};
    use postcard::{from_bytes, to_allocvec};
    use serde::{de::DeserializeOwned, Deserialize, Serialize};
    use std::{path::PathBuf, process::Command};
    use tempfile::{tempdir, TempDir};

    enum EmulatorType {
        Harvard,
        Linear(u32, u32, u32), // heap size, stack size, program size
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

    /// Serialize a value into a vector of u32 words.
    fn serialize_into_u32_chunks<T: Serialize>(value: &T) -> Vec<u32> {
        // Serialize to bytes.
        let mut bytes = to_allocvec(value).expect("Serialization failed");
        // Pad to the next multiple of 4.
        bytes.resize((bytes.len() + 3) & !3, 0);
        // Convert to u32 chunks.
        bytes
            .chunks(4)
            .map(|chunk| u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]))
            .collect()
    }

    /// Deserialize a value from a vector of u32 words.
    fn deserialize_from_u32_chunks<T: DeserializeOwned>(u32_chunks: &[u32]) -> T {
        let mut bytes = Vec::with_capacity(u32_chunks.len() * 4);
        for &word in u32_chunks {
            bytes.extend_from_slice(&word.to_le_bytes());
        }
        from_bytes(&bytes).expect("Deserialization failed")
    }

    /// Helper function to run emulator and check that the inputs and outputs are correct.
    fn emulate<
        T: Serialize,
        U: Serialize + DeserializeOwned + std::fmt::Debug + PartialEq + Clone,
    >(
        test_name: &str,
        input: Option<T>,
        expected_output: Option<U>,
        expected_result: Result<
            (Vec<InstructionResult>, MemoryTranscript),
            nexus_vm::error::VMError,
        >,
        emulator_type: EmulatorType,
        compile_flags: &[&str],
    ) {
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
            let elf = ElfFile::from_path(&elf_path).expect("Unable to load ELF from path");
            let input_bytes: Vec<u32> = if let Some(input) = &input {
                serialize_into_u32_chunks(input)
            } else {
                vec![]
            };
            let mut deserialized_output: Option<U> = None;
            match emulator_type {
                EmulatorType::Harvard => {
                    let mut emulator = HarvardEmulator::from_elf(elf, &input_bytes, &[]);
                    assert_eq!(emulator.execute(), expected_result);
                    if expected_output.is_some() {
                        let output_vec = emulator.get_output().unwrap();
                        deserialized_output = Some(deserialize_from_u32_chunks::<U>(&output_vec));
                    }
                }
                EmulatorType::Linear(heap_size, stack_size, program_size) => {
                    let output_len = if let Some(expected_output) = expected_output.clone() {
                        serialize_into_u32_chunks(&expected_output).len()
                    } else {
                        0
                    };

                    let memory_layout = LinearMemoryLayout::new(
                        heap_size,
                        stack_size,
                        input_bytes.len() as u32 * 4,
                        output_len as u32 * 4,
                        program_size,
                        0xbeef * 4,
                    )
                    .expect("Invalid memory layout");
                    let mut emulator = LinearEmulator::from_elf(
                        memory_layout,
                        &vec![0; 0xbeef as usize],
                        elf,
                        &input_bytes,
                        &[],
                    );

                    assert_eq!(emulator.execute(), expected_result);
                    if expected_output.is_some() {
                        let output_vec = emulator.get_output().unwrap();
                        deserialized_output = Some(deserialize_from_u32_chunks::<U>(&output_vec));
                    }
                }
            };

            // Check that the program exits correctly.
            assert_eq!(deserialized_output, expected_output);
        }
    }

    #[test]
    fn test_emulate() {
        // Works.
        emulate::<u32, u32>(
            "io_u32",
            Some(123u32),
            Some(123u32),
            Err(nexus_vm::error::VMError::VMExited(0)),
            EmulatorType::Harvard,
            &["-C opt-level=0", ""],
        );
        emulate::<u64, u64>(
            "io_u64",
            Some(1u64 << 32),
            Some(1u64 << 32),
            Err(nexus_vm::error::VMError::VMExited(0)),
            EmulatorType::Harvard,
            &["-C opt-level=0", ""],
        );
        emulate::<u128, u128>(
            "io_u128",
            Some(332306998946228968225970211937533483u128),
            Some(332306998946228968225970211937533483u128),
            Err(nexus_vm::error::VMError::VMExited(0)),
            EmulatorType::Harvard,
            &["-C opt-level=0", ""],
        );
        emulate::<u32, u32>(
            "io_u32",
            Some(123u32),
            Some(123u32),
            Err(nexus_vm::error::VMError::VMExited(0)),
            EmulatorType::default_linear(),
            &["-C opt-level=0", ""],
        );
        emulate::<u64, u64>(
            "io_u64",
            Some(1u64 << 32),
            Some(1u64 << 32),
            Err(nexus_vm::error::VMError::VMExited(0)),
            EmulatorType::default_linear(),
            &["-C opt-level=0", ""],
        );
        emulate::<u128, u128>(
            "io_u128",
            Some(332306998946228968225970211937533483u128),
            Some(332306998946228968225970211937533483u128),
            Err(nexus_vm::error::VMError::VMExited(0)),
            EmulatorType::default_linear(),
            &["-C opt-level=0", ""],
        );
    }

    #[test]
    fn test_fib() {
        emulate::<u32, u32>(
            "fib",
            Some(1u32),
            Some(1u32),
            Err(nexus_vm::error::VMError::VMExited(0)),
            EmulatorType::Harvard,
            &["-C opt-level=0", ""],
        );
        emulate::<u32, u32>(
            "fib",
            Some(10u32),
            Some(34u32),
            Err(nexus_vm::error::VMError::VMExited(0)),
            EmulatorType::Harvard,
            &["-C opt-level=0", ""],
        );
        emulate::<u32, u32>(
            "fib",
            Some(20u32),
            Some(4181u32),
            Err(nexus_vm::error::VMError::VMExited(0)),
            EmulatorType::Harvard,
            &["-C opt-level=0", ""],
        );
        emulate::<u32, u32>(
            "fib",
            Some(1u32),
            Some(1u32),
            Err(nexus_vm::error::VMError::VMExited(0)),
            EmulatorType::default_linear(),
            &["-C opt-level=0", ""],
        );
        emulate::<u32, u32>(
            "fib",
            Some(10u32),
            Some(34u32),
            Err(nexus_vm::error::VMError::VMExited(0)),
            EmulatorType::default_linear(),
            &["-C opt-level=0", ""],
        );
        emulate::<u32, u32>(
            "fib",
            Some(20u32),
            Some(4181u32),
            Err(nexus_vm::error::VMError::VMExited(0)),
            EmulatorType::default_linear(),
            &["-C opt-level=0", ""],
        );
    }

    #[test]
    fn test_word_serialization() {
        let input_u32 = 1324234u32;
        let serialized_u32 = serialize_into_u32_chunks(&input_u32);
        let deserialized_u32 = deserialize_from_u32_chunks::<u32>(&serialized_u32);
        assert_eq!(input_u32, deserialized_u32);

        let input_u64 = 1u64 << 32;
        let serialized_u64 = serialize_into_u32_chunks(&input_u64);
        let deserialized_u64 = deserialize_from_u32_chunks::<u64>(&serialized_u64);
        assert_eq!(input_u64, deserialized_u64);

        #[derive(Serialize, Deserialize, Debug, PartialEq)]
        struct TestStruct {
            a: u32,
            b: u32,
            c: u128,
            d: u128,
        }

        let input_struct = TestStruct {
            a: 1,
            b: 2,
            c: 3,
            d: 4,
        };
        let serialized_struct = serialize_into_u32_chunks(&input_struct);
        let deserialized_struct = deserialize_from_u32_chunks::<TestStruct>(&serialized_struct);
        assert_eq!(input_struct, deserialized_struct);
    }
}
