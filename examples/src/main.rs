#![cfg_attr(target_arch = "riscv32", no_std, no_main)]

use nexus_rt::print;

#[nexus_rt::main]
fn main() {
    print!("Hello, World!\n");
}
