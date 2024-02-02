#![no_std]
#![no_main]

// optional, for use of collections, etc.
// extern crate alloc;

use nexus_rt::{write_log,entry};

#[entry]
fn main() {
    write_log("\n\nHello World.\n\n"); // ensure at least one blank line both before and after.
}
