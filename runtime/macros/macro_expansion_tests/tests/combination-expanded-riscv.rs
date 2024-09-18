#![feature(prelude_import)]
#![no_std]
#![no_main]
#[prelude_import]
use core::prelude::rust_2021::*;
#[macro_use]
extern crate core;
extern crate compiler_builtins as _;
fn foo() -> u32 {
    1
}
fn boo() -> u32 {
    9
}
fn fizz() -> (u32, u32, u32) {
    (12, 11, 10)
}
fn buzz() -> u32 {
    0
}
fn moo() {
    let (b): (u32) = buzz();
    {
        let _out = {
            {
                let (x, y, z): (u32, u32, u32) = fizz();
                {
                    let (a): (u32) = boo();
                    { a + b + x + y + z }
                }
            }
        };
        output_handler(_out);
    }
}
fn hello() -> u32 {
    let (x): (u32) = nexus_rt::read_public_input::<u32>();
    {
        let (a): (u32) = foo();
        {
            let i: u32 = 0;
            let b = i + a;
            i + b + x
        }
    }
}
const _: fn() = main;
#[no_mangle]
#[allow(unused)]
fn main() {
    let _out = {
        {
            {
                moo();
                foo() + hello()
            }
        }
    };
    nexus_rt::write_public_output::<u32>(_out);
}
