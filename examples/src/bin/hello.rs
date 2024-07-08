#![no_std]
#![no_main]

extern crate alloc;

use nexus_rt::println;

#[nexus_rt::main]
fn main() {
    println!("Hello!");
}
