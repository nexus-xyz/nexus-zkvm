#![cfg_attr(target_arch = "riscv32", no_std, no_main)]

extern crate alloc;
use alloc::vec;
use core::hint::black_box;

use nexus_rt::println;

// use 16mb
// alternatively, remove memlimit argument or otherwise set less than (slightly more than) 16mb and it will fail
#[nexus_rt::main(memlimit = 18)]
fn main() {
    let vec = vec![1u8; 0x1000000];
    black_box(vec);

    println!("Success!!!");
}
