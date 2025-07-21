use nexus_common::constants::WORD_SIZE;
use nexus_common::cpu::InstructionResult;

use nexus_vm::elf::ElfFile;
use nexus_vm::emulator::MemoryTranscript;
use nexus_vm::emulator::{Emulator, InternalView};
use nexus_vm::emulator::{HarvardEmulator, LinearEmulator, LinearMemoryLayout};
use nexus_vm::error::Result;
use postcard::from_bytes_cobs;
use serde::{de::DeserializeOwned, Serialize};

use std::{
    path::{Path, PathBuf},
    process::Command,
};
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
        Result<(Vec<InstructionResult>, MemoryTranscript), nexus_vm::error::VMErrorKind>,
}

impl<T: Input, U: Input, V: Output> Default for IOArgs<T, U, V> {
    fn default() -> Self {
        Self {
            public_input: None,
            private_input: None,
            expected_output: None,
            expected_result: Err(nexus_vm::error::VMErrorKind::VMExited(0)),
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
            expected_result: Err(nexus_vm::error::VMErrorKind::VMExited(0)),
        }
    }

    pub fn simple_panic() -> Self {
        Self {
            public_input: None,
            private_input: None,
            expected_output: None,
            expected_result: Err(nexus_vm::error::VMErrorKind::VMExited(1)),
        }
    }
}

/// Parse the output bytes as exit code and output.
pub fn parse_output<T: DeserializeOwned>(
    exit_code: Vec<u8>,
    mut output: Vec<u8>,
) -> Result<(u32, Option<T>), postcard::Error> {
    // The first 4 bytes store the exit code.
    assert_eq!(exit_code.len(), WORD_SIZE);
    let exit_code = u32::from_le_bytes(
        exit_code[0..WORD_SIZE]
            .try_into()
            .expect("Failed to parse exit code"),
    );

    if output.is_empty() {
        Ok((exit_code, None))
    } else {
        // Deserialize the rest as the output.
        let output: T = from_bytes_cobs(&mut output).expect("Deserialization failed");
        Ok((exit_code, Some(output)))
    }
}

/// Create a temporary directory with a new Cargo project that has nexus_rt as a local dependency.
pub fn setup_guest_project(runtime_path: &PathBuf) -> TempDir {
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

    // Add the nexus_rt dependency to the `Cargo.toml` file.
    let runtime_dir = std::env::current_dir().unwrap().join(runtime_path);
    output = Command::new("cargo")
        .current_dir(tmp_dir_str)
        .arg("add")
        .arg("nexus-rt")
        .arg("--path")
        .arg(runtime_dir)
        .output()
        .expect("Failed to add nexus_rt dependency");

    if !output.status.success() {
        eprintln!("Error: {}", String::from_utf8_lossy(&output.stderr));
        panic!("cargo add failed for nexus_rt");
    }

    tmp_dir
}

/// Setup project.
pub fn write_guest_source_code(tmp_project_path: &Path, test_path: &str) {
    // Overwrite the main.rs file with the test file.
    let main_file = format!("{}/src/main.rs", tmp_project_path.to_str().unwrap());

    let output = Command::new("cp")
        .arg(test_path)
        .arg(main_file)
        .output()
        .expect("Failed to copy test file");

    assert!(output.status.success());
}

/// Compile the test file.
pub fn compile_guest_project(
    project_path: &PathBuf,
    linker_path: &PathBuf,
    compile_flags: &str,
) -> Vec<u8> {
    let target = "riscv32im-unknown-none-elf";

    let linker_script = std::env::current_dir().unwrap().join(linker_path);

    // Compile the test file for riscv target.
    let output = Command::new("cargo")
        .current_dir(project_path)
        .arg("build")
        .arg("--target")
        .arg(target)
        .env(
            "RUSTFLAGS",
            format!(
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

    // Read the elf file to bytes.
    let elf_file = format!(
        "{}/target/{target}/debug/integration",
        project_path.to_str().unwrap()
    );

    std::fs::read(elf_file).expect("Failed to read elf file")
}

pub fn compile_multi(
    test_name: &str,
    compile_flags: &[&str],
    home_path_relative: &str,
) -> Vec<ElfFile> {
    let mut elves = Vec::new();
    // Set up the temporary directories for intermediate project setup.
    let tmp_dir = &setup_guest_project(&PathBuf::from(home_path_relative).join("runtime"));
    let tmp_project_path = tmp_dir.path().join("integration");

    for flag_set in compile_flags {
        // Check that the tests compile and execute correctly.
        // Compile the test file.
        let test_path = format!("{home_path_relative}/{test_name}.rs");
        write_guest_source_code(&tmp_project_path, &test_path);
        let elf_contents = compile_guest_project(
            &tmp_project_path,
            &PathBuf::from(home_path_relative).join("runtime/linker-scripts/default.x"),
            flag_set,
        );

        // Parse the elf file.
        let elf = ElfFile::from_bytes(&elf_contents).expect("Unable to load ELF from bytes");
        elves.push(elf);
    }
    elves
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
    let ad = vec![0u8; 0xbeef_usize]; // placeholder ad until we have use for it
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
                    let _output_log = if let Some(lines) = view.view_debug_logs() {
                        lines
                            .iter()
                            .map(|line| String::from_utf8_lossy(line).to_string())
                            .collect::<Vec<String>>()
                            .join("\n")
                    } else {
                        "".into()
                    };
                }
                cycles.push(cur_cycles);
            }
            EmulatorType::Linear(heap_size, stack_size, program_size) => {
                // Construct the memory layout.
                let memory_layout = LinearMemoryLayout::try_new(
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
