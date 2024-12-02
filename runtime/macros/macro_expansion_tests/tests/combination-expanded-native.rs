#![feature(prelude_import)]
#[prelude_import]
use std::prelude::rust_2021::*;
#[macro_use]
extern crate std;
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
#[cfg(not(target_arch = "riscv32"))]
fn output_handler(x: u32) {
    {
        ::std::io::_print(format_args!("Output: {0}\n", x));
    };
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
    let (x): (u32) = buzz().expect("Failed to read public input");
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
    output_handler(&out).expect("Failed to write output");
}
