#![feature(prelude_import)]
#![no_std]
#![no_main]
#[prelude_import]
use core::prelude::rust_2024::*;
#[macro_use]
extern crate core;
extern crate compiler_builtins as _;
fn foo(x: u32, y: u32) {
    let out = (|| { { x * y } })();
    nexus_rt::write_public_output::<u32>(&out).expect("Failed to write output");
}
const _: fn() = main;
#[no_mangle]
#[allow(unused)]
fn main() {
    let (x, y): (u32, u32) = nexus_rt::read_private_input::<(u32, u32)>()
        .expect("Failed to read public input");
    {
        {
            foo(x, y);
        }
    }
}
