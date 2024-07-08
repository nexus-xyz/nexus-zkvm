#![cfg_attr(target_arch = "riscv32", no_std, no_main)]

use nexus_rt::{println, read_private_input, write_output};

#[nexus_rt::main]
fn main() {
    let input: Option<(u32, u32)> = read_private_input::<u32>();

    let (x, y) = input;
    let mut z: i32 = -1;

    if let Some(v) = input {
        println!("Read private input: {}", v);

        z = (x * y) as i32;
    } else {
        println!("No private input provided...");
    }

    write_output::<i32>(&z)
}
