#![no_std]
#![no_main]

// optional, for use of collections, etc.
// extern crate alloc;

use nexus_rt::{write_log,entry};

#[entry]
fn main() {
    write_log("Hello World");
}
