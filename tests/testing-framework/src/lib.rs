mod test {
    use nexus_vm::elf::ElfFile;
    use nexus_vm::riscv::decode_instructions;
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

    /// Compile the test file for (riscv, native) targets.
    fn compile(tmp_project_path: PathBuf, test: String) -> Vec<u8> {
        // Overwrite the main.rs file with the test file.
        let test_file = format!("../integration_tests/{test}.rs");
        let main_file = format!("{}/src/main.rs", tmp_project_path.clone().to_str().unwrap());

        let mut output = Command::new("cp")
            .arg(test_file)
            .arg(main_file)
            .output()
            .expect("Failed to copy test file");

        assert!(output.status.success());

        // Compile the test file for riscv target.
        output = Command::new("cargo")
            .current_dir(tmp_project_path.clone())
            .arg("build")
            .arg("--target")
            .arg("riscv32i-unknown-none-elf")
            .env("RUSTFLAGS", "-C opt-level=0") // TODO: can remove this for more complicated tests
            .output()
            .expect("Failed to run test");

        if !output.status.success() {
            eprintln!("Error: {}", String::from_utf8_lossy(&output.stderr));
            panic!("cargo expand failed for RISC-V target");
        }
        assert!(output.status.success());

        // Read the elf file to bytes.
        let elf_file = format!(
            "{}/target/riscv32i-unknown-none-elf/debug/integration",
            tmp_project_path.clone().to_str().unwrap()
        );

        std::fs::read(elf_file).expect("Failed to read elf file")
    }

    #[test]
    fn test_compile() {
        let tests = vec!["simple"];
        let tmp_dir = &create_tmp_dir();
        let tmp_project_path = tmp_dir.path().join("integration");

        for test in tests {
            let elf_contents = compile(tmp_project_path.clone(), test.to_string());

            #[cfg(feature = "generate_expectations")]
            {
                std::fs::write(format!("../integration_tests/{test}.elf"), &elf_contents)
                    .expect("Failed to write file");
            }

            // Read the expected output.
            let elf_path = format!("../integration_tests/{test}.elf");
            let expected_elf = std::fs::read(&elf_path).expect("Failed to read file");

            // Compare the outputs, stripping out any differences in line endings.
            // TODO: might not need this here.
            assert_eq!(elf_contents, expected_elf);

            const WORD_SIZE: u32 = 4;
            let elf = ElfFile::from_path(&elf_path).expect("Unable to load ELF from path");
            let entry_instruction = (elf.entry - elf.base) / WORD_SIZE;

            dbg!(entry_instruction);
            dbg!(elf.entry);
            dbg!(elf.instructions.len());
            dbg!(elf.base);

            let want_instructions = 1; // TODO: change
                                       // TODO: print out the instructions/trace to expectations file so can verify consistency (@duc-nx)
            let program = decode_instructions(
                &elf.instructions
                    [entry_instruction as usize..(entry_instruction + want_instructions) as usize],
            );

            for block in program.blocks.iter() {
                println!("{}", block);
            }
        }
    }
}
