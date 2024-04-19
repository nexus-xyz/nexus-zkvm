#![no_std]
#![no_main]

use nexus_rt::{println, read_private_input, Write};

#[nexus_rt::main]
fn main() {
    let inp: Option<u8> = read_private_input();

    if let Some(v) = inp {
        println!("Read private input: {}", v);
    } else {
        println!("No private input provided...");
    }
}
