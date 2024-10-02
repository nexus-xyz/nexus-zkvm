#![cfg_attr(target_arch = "riscv32", no_std, no_main)]

#[nexus_rt::main]
fn main() {
    let x = 1;
    let y = 2;
    let z = x + y;
}
