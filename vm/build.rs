use std::process::Command;

use tempfile::tempdir;

fn main() {
    // Build the ELF files for VM tests that use them.
    println!("cargo::rerun-if-changed=../precompiles/examples/dummy_div/*");
    println!("cargo::rerun-if-changed=../precompiles/examples/dummy_hash/*");

    // Determine whether to run.
    match std::env::var("NEXUS_VM_BUILD_GUEST_TEST_BINARIES") {
        // Force-disable building.
        Ok(true_val) if true_val == "0" || true_val == "false" => {
            println!(
                "cargo:info=Skipping building test guest programs because \
                NEXUS_VM_BUILD_GUEST_TEST_BINARIES is set to 0/false."
            );
            return;
        }
        // Force-enable building.
        Ok(val) => {
            println!(
                "cargo:info=Building test guest programs because \
                NEXUS_VM_BUILD_GUEST_TEST_BINARIES is set to {val}."
            );
        }
        Err(_) => {
            println!(
                "cargo:info=Skipping building test guest programs because \
                NEXUS_VM_BUILD_GUEST_TEST_BINARIES is not set."
            );
            return;
        }
    }

    // Rust guarantees that the build script's cwd is the directory containing the package's `src`
    // directory.
    let vm_src_dir = std::env::current_dir().unwrap();
    let test_dir = vm_src_dir.join("test");
    let guest_programs_dir = vm_src_dir
        .parent()
        .unwrap()
        .join("precompiles/examples/guest_programs");

    let build_temp_dir = tempdir().unwrap();
    let build_target_dir = build_temp_dir.path().join("target");

    let _output = Command::new("cargo")
        .current_dir(guest_programs_dir)
        .arg("build")
        .arg("--target-dir")
        .arg(&build_target_dir)
        .arg("--profile")
        .arg("release-for-tests")
        .env("RUSTFLAGS", "-A warnings")
        .output()
        .expect("Failed to build guest programs");

    let built_bin_dir = build_target_dir.join("riscv32im-unknown-none-elf/release-for-tests");

    const ONE_PRECOMPILE_NAME: &str = "program_with_dummy_div";
    const TWO_PRECOMPILES_NAME: &str = "program_with_two_precompiles";
    const NO_PRECOMPILES_NAME: &str = "program_with_no_precompiles";

    let one_precompile_path = built_bin_dir.join(ONE_PRECOMPILE_NAME);
    let two_precompiles_path = built_bin_dir.join(TWO_PRECOMPILES_NAME);
    let no_precompiles_path = built_bin_dir.join(NO_PRECOMPILES_NAME);

    let one_precompile_dest = test_dir.join(format!("{}.elf", ONE_PRECOMPILE_NAME));
    let two_precompiles_dest = test_dir.join(format!("{}.elf", TWO_PRECOMPILES_NAME));
    let no_precompiles_dest = test_dir.join(format!("{}.elf", NO_PRECOMPILES_NAME));

    std::fs::copy(one_precompile_path, one_precompile_dest).unwrap();
    std::fs::copy(two_precompiles_path, two_precompiles_dest).unwrap();
    std::fs::copy(no_precompiles_path, no_precompiles_dest).unwrap();
}
