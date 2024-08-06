#![cfg_attr(target_arch = "riscv32", no_std, no_main)]

use nexus_rt::{println, read_public_input, write_output};

#[nexus_rt::main]
fn main() {
    let input = read_public_input::<(u32, u32)>();

    let mut z: i32 = -1;
    if let Ok((x, y)) = input {
        println!("Read public input: ({}, {})", x, y);

        z = (x * y) as i32;
    } else {
        println!("No public input provided...");
    }

    write_output::<i32>(&z)
}
