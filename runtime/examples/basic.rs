#![cfg_attr(target_arch = "riscv32", no_std, no_main)]

// optional, for use of collections, etc.
extern crate alloc;

use nexus_rt::print;

#[nexus_rt::main]
fn main() {
    print!("Hello World\n");
}
