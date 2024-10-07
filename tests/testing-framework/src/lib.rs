#[cfg(test)]
mod test {
    use nexus_vm::elf::ElfFile;
    use nexus_vm::emulator::Emulator;
    use nexus_vm::riscv::Register;
    use std::{path::PathBuf, process::Command};
    use tempfile::{tempdir, TempDir};

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
    fn compile_to_elf(tmp_project_path: PathBuf, test_path: &str) -> Vec<u8> {
        // Overwrite the main.rs file with the test file.
        let main_file = format!("{}/src/main.rs", tmp_project_path.clone().to_str().unwrap());
        let target = "riscv32i-unknown-none-elf";

        let mut output = Command::new("cp")
            .arg(test_path)
            .arg(main_file)
            .output()
            .expect("Failed to copy test file");

        assert!(output.status.success());

        // Compile the test file for riscv target.
        output = Command::new("cargo")
            .current_dir(tmp_project_path.clone())
            .arg("build")
            .arg("--target")
            .arg(target)
            .env("RUSTFLAGS", "-C opt-level=0") // Disable optimizations.
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

    #[test]
    fn test_fib() {
        // Test names and expected results.
        let test_names = vec!["fib_10", "fib_20", "fib_40"];
        let test_results = vec![55, 6765, 102334155];

        // Set up the temporary directories for intermediate project setup.
        let tmp_dir = &create_tmp_dir();
        let tmp_project_path = tmp_dir.path().join("integration");

        // Check that the tests compile and execute correctly.
        for (test_name, result) in test_names.iter().zip(test_results.iter()) {
            // Compile the test file.
            let test_dir_path = "../integration-tests";
            let test_path = format!("{test_dir_path}/{test_name}.rs");
            let elf_contents = compile_to_elf(tmp_project_path.clone(), &test_path);

            // Save the elf file for debugging purposes.
            let elf_path = format!("{test_dir_path}/{test_name}.elf");
            std::fs::write(&elf_path, &elf_contents).expect("Failed to write file");

            // Parse the elf file.
            let elf = ElfFile::from_path(&elf_path).expect("Unable to load ELF from path");

            // Execute the elf file using the emulator.
            let mut emulator = Emulator::from_elf(elf);
            let _res = emulator.execute(); // Ends on unimplemented instruction.

            // Check that the result is correct.
            // Will remove this hacky check later once I/O is working.
            assert_eq!(emulator.cpu.registers.read(Register::X12), *result);
        }
    }
}
