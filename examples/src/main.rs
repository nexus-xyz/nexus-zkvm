#![no_std]
#![no_main]

use nexus_rt::{entry, write_log};

#[entry]
fn main() {
    write_log("Hello, World!\n");
}
