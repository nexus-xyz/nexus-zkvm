#![no_std]
#![no_main]

extern crate alloc;
use alloc::vec;
use core::hint::black_box;

use nexus_rt::{println, Write};

// use 16mb
// alternatively, remove memlimit argument or otherwise set less than (slightly more than) 6mb and it will fail
#[nexus_rt::main(memlimit(16))]
fn main() {
    let vec = vec![0 as u32; 1500000];
    black_box(vec);

    println!("Success!!!");
}
