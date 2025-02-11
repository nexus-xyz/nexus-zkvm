use nexus_common::constants::WORD_SIZE;
use nexus_common::cpu::InstructionResult;

use nexus_vm::elf::ElfFile;
use nexus_vm::emulator::Emulator;
use nexus_vm::emulator::MemoryTranscript;
use nexus_vm::emulator::{HarvardEmulator, LinearEmulator, LinearMemoryLayout};
use nexus_vm::error::Result;
use postcard::from_bytes;
use serde::{de::DeserializeOwned, Serialize};
use std::{path::PathBuf, process::Command};
use tempfile::{tempdir, TempDir};

#[derive(Clone)]
pub enum EmulatorType {
    Harvard,
    Linear(u32, u32, u32), // heap size, stack size, program size
    TwoPass,
}

impl EmulatorType {
    pub fn default_linear() -> Self {
        Self::Linear(0x800000, 0x100000, 0x80000)
    }
}

pub trait Input: Serialize + std::fmt::Debug + Clone {}
impl<T> Input for T where T: Serialize + std::fmt::Debug + Clone {}
pub trait Output: Serialize + DeserializeOwned + std::fmt::Debug + PartialEq + Clone {}
impl<T> Output for T where T: Serialize + DeserializeOwned + std::fmt::Debug + PartialEq + Clone {}

pub struct IOArgs<T: Input, U: Input, V: Output> {
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
    pub fn default_list() -> Vec<Self> {
        vec![Self::default()]
    }

    pub fn new(input: Option<T>, private_input: Option<U>, expected_output: Option<V>) -> Self {
        Self {
            public_input: input,
            private_input,
            expected_output,
            expected_result: Err(nexus_vm::error::VMError::VMExited(0)),
        }
    }

    pub fn simple_panic() -> Self {
        Self {
            public_input: None,
            private_input: None,
            expected_output: None,
            expected_result: Err(nexus_vm::error::VMError::VMExited(1)),
        }
    }
}

/// Parse the output bytes as exit code and output.
pub fn parse_output<T: DeserializeOwned>(
    exit_code: Vec<u8>,
    output: Vec<u8>,
) -> Result<(u32, Option<T>), postcard::Error> {
    // The first 4 bytes store the exit code.
    assert_eq!(exit_code.len(), WORD_SIZE);
    let exit_code = u32::from_le_bytes(
        exit_code[0..WORD_SIZE]
            .try_into()
            .expect("Failed to parse exit code"),
    );

    if output.len() == 0 {
        Ok((exit_code, None))
    } else {
        // Deserialize the rest as the output.
        let output: T = from_bytes(&output).expect("Deserialization failed");
        Ok((exit_code, Some(output)))
    }
}

/// Create a temporary directory with a new Cargo project that has nexus_rt as a local dependency.
pub fn create_tmp_dir() -> TempDir {
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

/// Setup project.
pub fn setup_project(tmp_project_path: &PathBuf, test_path: &str) {
    // Overwrite the main.rs file with the test file.
    let main_file = format!("{}/src/main.rs", tmp_project_path.to_str().unwrap());

    let output = Command::new("cp")
        .arg(test_path)
        .arg(main_file)
        .output()
        .expect("Failed to copy test file");

    println!("{}", String::from_utf8_lossy(&output.stderr));
    assert!(output.status.success());
}

/// Compile the test file.
pub fn compile_to_elf(path: &PathBuf, compile_flags: &str) -> Vec<u8> {
    let target = "riscv32i-unknown-none-elf";

    let linker_script = std::env::current_dir()
        .unwrap()
        .join("../../runtime/linker-scripts/default.x");

    // Compile the test file for riscv target.
    let output = Command::new("cargo")
        .current_dir(path)
        .arg("build")
        .arg("--target")
        .arg(target)
        .env(
            "RUSTFLAGS",
            &format!(
                "{compile_flags} -C relocation-model=pic -C panic=abort -C link-arg=-T{}",
                linker_script.display()
            ),
        )
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
        path.to_str().unwrap()
    );

    std::fs::read(elf_file).expect("Failed to read elf file")
}

pub fn compile_multi(test_name: &str, compile_flags: &[&str]) -> Vec<ElfFile> {
    let mut elfs = Vec::new();
    // Set up the temporary directories for intermediate project setup.
    let tmp_dir = &create_tmp_dir();
    let tmp_project_path = tmp_dir.path().join("integration");

    for flag_set in compile_flags {
        // Check that the tests compile and execute correctly.
        // Compile the test file.
        let test_dir_path = "../integration-tests";
        let test_path = format!("{test_dir_path}/{test_name}.rs");
        setup_project(&tmp_project_path, &test_path);
        let elf_contents = compile_to_elf(&tmp_project_path, flag_set);

        // Save the elf file for debugging purposes.
        let elf_path = format!("{test_dir_path}/{test_name}.elf");
        std::fs::write(&elf_path, &elf_contents).expect("Failed to write file");

        // Parse the elf file.
        let elf = ElfFile::from_bytes(&elf_contents).expect("Unable to load ELF from bytes");
        elfs.push(elf);
    }
    elfs
}

/// Helper function to run emulator and return output bytes and cycles.
/// Note that this function does not check the correctness of the exit code or I/O.
pub fn emulate(
    elfs: Vec<ElfFile>,
    public_input_bytes: Vec<u8>,
    private_input_bytes: Vec<u8>,
    output_bytes_len: usize,
    emulator_type: EmulatorType,
) -> (Vec<usize>, Vec<u8>, Vec<u8>) {
    let mut exit_code_bytes: Vec<u8> = Vec::new();
    let mut output_bytes: Vec<u8> = Vec::new();
    let ad = vec![0u8; 0xbeef as usize]; // placeholder ad until we have use for it
    let mut cycles = Vec::new();

    for elf in elfs {
        match emulator_type {
            EmulatorType::Harvard | EmulatorType::TwoPass => {
                // Use elf file to build the harvard emulator.
                let mut emulator =
                    HarvardEmulator::from_elf(&elf, &public_input_bytes, &private_input_bytes);
                let _ = emulator.execute(false);
                let mut cur_cycles = emulator.executor.global_clock;

                let view = emulator.finalize();
                exit_code_bytes = view
                    .get_exit_code()
                    .iter()
                    .map(|public_output_entry| public_output_entry.value)
                    .collect();
                output_bytes = view
                    .get_public_output()
                    .iter()
                    .map(|public_output_entry| public_output_entry.value)
                    .collect();

                // Run a second pass with a linear emulator constructed from the harvard emulator.
                if matches!(emulator_type, EmulatorType::TwoPass) {
                    // Use the data obtained from the harvard emulator to construct the linear emulator.
                    let mut linear_emulator =
                        LinearEmulator::from_harvard(&emulator, elf, &ad, &private_input_bytes)
                            .unwrap();
                    let _ = linear_emulator.execute(false);
                    cur_cycles = linear_emulator.executor.global_clock;

                    // Get output bytes.
                    let view = linear_emulator.finalize();
                    exit_code_bytes = view
                        .get_exit_code()
                        .iter()
                        .map(|public_output_entry| public_output_entry.value)
                        .collect();
                    output_bytes = view
                        .get_public_output()
                        .iter()
                        .map(|public_output_entry| public_output_entry.value)
                        .collect();
                }
                cycles.push(cur_cycles);
            }
            EmulatorType::Linear(heap_size, stack_size, program_size) => {
                // Construct the memory layout.
                let memory_layout = LinearMemoryLayout::new(
                    heap_size,
                    stack_size,
                    public_input_bytes.len() as u32,
                    output_bytes_len as u32,
                    program_size,
                    ad.len() as u32,
                )
                .expect("Invalid memory layout");

                // Construct the linear emulator.
                let mut emulator = LinearEmulator::from_elf(
                    memory_layout,
                    &ad,
                    &elf,
                    &public_input_bytes,
                    &private_input_bytes,
                );
                cycles.push(emulator.executor.global_clock);
                let _ = emulator.execute(false);

                let view = emulator.finalize();
                exit_code_bytes = view
                    .get_exit_code()
                    .iter()
                    .map(|public_output_entry| public_output_entry.value)
                    .collect();
                output_bytes = view
                    .get_public_output()
                    .iter()
                    .map(|public_output_entry| public_output_entry.value)
                    .collect();
            }
        }
    }

    (cycles, exit_code_bytes, output_bytes)
}
