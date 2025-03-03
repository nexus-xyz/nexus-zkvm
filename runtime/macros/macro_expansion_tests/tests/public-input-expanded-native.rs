#![feature(prelude_import)]
#[prelude_import]
use std::prelude::rust_2024::*;
#[macro_use]
extern crate std;
#[cfg(not(target_arch = "riscv32"))]
fn input_handler() -> (u32, u32) {
    (1, 2)
}
#[cfg(not(target_arch = "riscv32"))]
fn output_handler(result: u32) {
    {
        ::std::io::_print(format_args!("Output: {0}\n", result));
    };
}
const _: fn() = main;
#[allow(unused)]
fn main() {
    let out = (|| {
        {
            let (x, y): (u32, u32) = input_handler()
                .expect("Failed to read public input");
            { { x * y } }
        }
    })();
    output_handler(&out).expect("Failed to write output");
}
