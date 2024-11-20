#![cfg_attr(target_arch = "riscv32", no_std, no_main)]

#[nexus_rt::main]
#[nexus_rt::public_input(x)]
fn main(x: u64) -> u64 {
    x
}
