#![cfg_attr(target_arch = "riscv32", no_std, no_main)]

use nexus_rt::{Error, println, read_private_input, write_output};

#[nexus_rt::main]
fn main() {
    let input:Result<(u32, u32), Error> = read_private_input::<(u32, u32)>();

    let mut z: i32 = -1;
    if let Ok((x, y)) = input {
        println!("Read private input: ({}, {})", x, y);

        z = (x * y) as i32;
    } else {
        println!("No private input provided...");
    }

    write_output::<i32>(&z)
}
