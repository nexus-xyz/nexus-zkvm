#![no_std]
#![no_main]

use nexus_rt::write_log;

#[nexus_rt::main(memset(8000))]
fn main() {
    write_log("Hello, World!\n");
}
