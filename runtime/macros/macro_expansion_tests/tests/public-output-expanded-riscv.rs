#![feature(prelude_import)]
#![no_std]
#![no_main]
#[prelude_import]
use core::prelude::rust_2021::*;
#[macro_use]
extern crate core;
extern crate compiler_builtins as _;
fn foo(x: u32, y: u32) {
    let _out = { { x * y } };
    nexus_rt::write_public_output::<u32>(_out);
}
const _: fn() = main;
#[no_mangle]
#[allow(unused)]
fn main() {
    let (x, y): (u32, u32) = nexus_rt::read_private_input::<u32, u32>();
    {
        {
            foo(x, y);
        }
    }
}
