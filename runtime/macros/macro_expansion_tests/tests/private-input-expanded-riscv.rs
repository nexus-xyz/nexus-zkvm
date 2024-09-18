#![feature(prelude_import)]
#![no_std]
#![no_main]
#[prelude_import]
use core::prelude::rust_2021::*;
#[macro_use]
extern crate core;
extern crate compiler_builtins as _;
const _: fn() = main;
#[no_mangle]
#[allow(unused)]
fn main() {
    let _out = {
        {
            let (y): (u32) = nexus_rt::read_private_input::<u32>();
            {
                {
                    let (x): (u32) = nexus_rt::read_private_input::<u32>();
                    { { x * y } }
                }
            }
        }
    };
    nexus_rt::write_public_output::<u32>(_out);
}
