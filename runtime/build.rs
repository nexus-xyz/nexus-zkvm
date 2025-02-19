use std::{env, fs, path::PathBuf};

fn main() {
    let target = env::var("TARGET").unwrap();
    if !target.starts_with("riscv32") {
        return;
    }

    let linker_script_path = "./linker-scripts/default.x";
    let linker_script_bytes = fs::read(linker_script_path).unwrap();
    println!("cargo:rerun-if-changed={}", linker_script_path);

    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());
    fs::write(out_dir.join("link.x"), linker_script_bytes).unwrap();
    println!("cargo:rustc-link-search={}", out_dir.display());
}
