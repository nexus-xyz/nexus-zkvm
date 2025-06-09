#[cfg(test)]
mod test {
    use std::{path::PathBuf, process::Command};
    use tempfile::{tempdir, TempDir};
    /// Create a temporary directory with a new Cargo project that has nexus_rt as a local dependency.
    fn create_tmp_dir() -> TempDir {
        // Create a temporary directory.
        let tmp_dir = tempdir().expect("Failed to create temporary directory");
        let tmp_dir_path = tmp_dir.path().join("expansion");
        let tmp_dir_str = tmp_dir_path.to_str().unwrap();

        // Create a new Cargo project.
        let mut output = Command::new("cargo")
            .arg("new")
            .arg(tmp_dir_str)
            .output()
            .expect("Failed to create new Cargo project");

        assert!(output.status.success());

        // Get the current directory.
        let runtime_dir = std::env::current_dir().unwrap().join("..");

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

    /// Apply the procedural macros to the input file, and return the expansions for (riscv, native) targets.
    fn apply_proc_macro(tmp_project_path: PathBuf, test: String) -> (String, String) {
        // Overwrite the main.rs file with the test file.
        let test_file = format!("macro_expansion_tests/tests/{test}.rs");
        let main_file = format!("{}/src/main.rs", tmp_project_path.clone().to_str().unwrap());
        let mut output = Command::new("cp")
            .arg(test_file)
            .arg(main_file)
            .output()
            .expect("Failed to copy test file");

        assert!(output.status.success());

        // Expand the procedural macro using native target.
        output = Command::new("cargo")
            .current_dir(tmp_project_path.clone())
            .arg("expand")
            .output()
            .expect("Failed to run test");

        if !output.status.success() {
            eprintln!("Error: {}", String::from_utf8_lossy(&output.stderr));
            panic!("cargo expand failed for RISC-V target");
        }
        assert!(output.status.success());

        let expanded_native = String::from_utf8_lossy(&output.stdout);

        // Expand the procedural macro using riscv target.
        let output = Command::new("cargo")
            .current_dir(tmp_project_path.clone())
            .arg("expand")
            .arg("--target")
            .arg("riscv32im-unknown-none-elf")
            .output()
            .expect("Failed to run test");

        if !output.status.success() {
            eprintln!("Error: {}", String::from_utf8_lossy(&output.stderr));
            panic!("cargo expand failed for RISC-V target");
        }

        let expanded_riscv = String::from_utf8_lossy(&output.stdout);

        (expanded_riscv.to_string(), expanded_native.to_string())
    }

    #[test]
    fn test_expansion() {
        const GENERATE_EXPECTATIONS: bool = false;

        let tests = vec![
            "simple",
            "private-input",
            "public-input",
            "public-output",
            "combination",
        ];
        let tmp_dir = &create_tmp_dir();
        let tmp_project_path = tmp_dir.path().join("expansion");

        for test in tests {
            let (expand_riscv, exp_str_native) =
                apply_proc_macro(tmp_project_path.clone(), test.to_string());

            // Write the stdout to a file.
            if GENERATE_EXPECTATIONS {
                std::fs::write(
                    format!("macro_expansion_tests/tests/{test}-expanded-native.rs"),
                    &exp_str_native,
                )
                .expect("Failed to write file");
                std::fs::write(
                    format!("macro_expansion_tests/tests/{test}-expanded-riscv.rs"),
                    &expand_riscv,
                )
                .expect("Failed to write file");
            }

            // Read the expected output.
            let expected_riscv = std::fs::read_to_string(format!(
                "macro_expansion_tests/tests/{test}-expanded-riscv.rs"
            ))
            .expect("Failed to read file");
            let expected_native = std::fs::read_to_string(format!(
                "macro_expansion_tests/tests/{test}-expanded-native.rs"
            ))
            .expect("Failed to read file");

            // Compare the outputs, stripping out any differences in line endings.
            assert_eq!(
                exp_str_native.replace("\r\n", "\n"),
                expected_native.replace("\r\n", "\n")
            );
            assert_eq!(
                expand_riscv.replace("\r\n", "\n"),
                expected_riscv.replace("\r\n", "\n")
            );
        }
    }
}
