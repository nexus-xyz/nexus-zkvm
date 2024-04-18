#![no_std]
#![no_main]

extern crate alloc;
use alloc::vec;

use nexus_rt::{Write, println};

// use 16mb
// alternatively, remove memset argument or otherwise set less than (slightly more than) 6mb and it will fail
#[nexus_rt::main(memset(16))]
fn main() {
    let vec = vec![0 as u32; 1500000];
    println!("Arbitrary vector entry so that it does not get optimized away: vec[42] = {}", vec[42]);
    println!("Success!!!");
}
