#![no_std]
#![no_main]

// optional, for use of collections, etc.
extern crate alloc;

use nexus_rt::write_log;

#[nexus_rt::main]
fn main() {
    write_log("Hello World\n");
}
