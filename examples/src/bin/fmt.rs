#![no_std]
#![no_main]

extern crate alloc;

use alloc::format;

use nexus_rt::{
    write_log, // primitive string printing function
    NexusLog,  // Type implementing core::fmt::Write
    Write,     // re-export or core::fmt::Write for convenience
    print,     // macro similar to std::print!
    println,   // macro similar to std::println!
};

#[nexus_rt::main]
fn main() {
    // basic output of strings
    write_log("Hello\n");

    // use of format! macro from alloc crate
    write_log(&format!("this is one: {}\n", 1));

    // output using the core::write macro(s)
    write!(&mut NexusLog, "{} + {} = ", 1, 2).unwrap();
    writeln!(&mut NexusLog, "{}", 1 + 2).unwrap();

    // output using print! macros (wrappers around write!)
    print!("Hello ");
    println!("{}", "World!");
    println!();
}
