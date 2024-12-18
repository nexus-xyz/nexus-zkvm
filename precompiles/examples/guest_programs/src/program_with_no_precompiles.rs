#![cfg_attr(target_arch = "riscv32", no_std, no_main)]

#[cfg(not(target_arch = "riscv32"))]
compile_error!("This example is only meant to be compiled for RISC-V");

#[nexus_rt::main]
fn main() {
    assert!(true);
}
