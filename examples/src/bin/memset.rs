#![no_std]
#![no_main]

extern crate alloc;
use alloc::vec;

use nexus_rt::write_log;

// use 16mb
// alternatively, remove memset argument or otherwise set less than (slightly more than) 6mb and it will fail
#[nexus_rt::main(memset(16))]
fn main() {
    let _ = vec![0 as u32; 1500000];
    write_log("Success!!!\n");
}
