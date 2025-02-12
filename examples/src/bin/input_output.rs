#![cfg_attr(target_arch = "riscv32", no_std, no_main)]

use nexus_rt::println;

#[nexus_rt::main]
#[nexus_rt::public_input(x)]
fn main(x: u32, y: u32) -> u32 {
    println!("Read public input:  {}", x);
    println!("Read private input: {}", y);

    x * y
}
