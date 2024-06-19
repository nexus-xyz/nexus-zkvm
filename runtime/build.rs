// NOTE: Adapted from riscv-rt

use std::env;
use std::fs;
use std::path::PathBuf;

fn main() {
    let target = env::var("TARGET").unwrap();
    if !target.starts_with("riscv32i-") && !target.starts_with("riscv32imc-") {
        return;
    }

    // START dynamic linker script hack
    const PROVER_ENV: &str = "NEXUS_VM_PROVER";
    println!("cargo:rerun-if-env-changed={PROVER_ENV}");

    let script_path = match env::var(PROVER_ENV) {
        Ok(s) if &s == "jolt" => "linker-scripts/jolt.x",
        _ => "linker-scripts/default.x",
    };
    let script_bytes = fs::read(script_path).unwrap();

    // END hack

    // let target = env::var("TARGET").unwrap();
    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());
    let name = env::var("CARGO_PKG_NAME").unwrap();

    // if !target.starts_with("riscv32i-") && !target.starts_with("riscv32imc-") {
    //     panic!("Unsupported target: {}", target);
    // }

    let archive = format!("bin/{}.a", target);
    eprintln!("{}", archive);

    fs::copy(&archive, out_dir.join(format!("lib{}.a", name))).unwrap();
    println!("cargo:rerun-if-changed={}", archive);
    println!("cargo:rustc-link-lib=static={}", name);

    // Put the linker script somewhere the linker can find it
    // let script_bytes = include_bytes!("link.x");
    fs::write(out_dir.join("link.x"), script_bytes).unwrap();
    println!("cargo:rustc-link-search={}", out_dir.display());
    // println!("cargo:rerun-if-changed=link.x");
}
