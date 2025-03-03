#![feature(prelude_import)]
#![no_std]
#![no_main]
#[prelude_import]
use core::prelude::rust_2024::*;
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
    let (b): (u32) = buzz().expect("Failed to read public input");
    {
        let out = (|| {
            {
                let (x, y, z): (u32, u32, u32) = fizz()
                    .expect("Failed to read public input");
                {
                    let (a): (u32) = boo().expect("Failed to read public input");
                    { a + b + x + y + z }
                }
            }
        })();
        output_handler(&out).expect("Failed to write output");
    }
}
fn hello() -> u32 {
    let (x): (u32) = nexus_rt::read_public_input::<(u32)>()
        .expect("Failed to read public input");
    {
        let (a): (u32) = foo().expect("Failed to read public input");
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
    let out = (|| {
        {
            {
                moo();
                foo() + hello()
            }
        }
    })();
    nexus_rt::write_public_output::<u32>(&out).expect("Failed to write output");
}
