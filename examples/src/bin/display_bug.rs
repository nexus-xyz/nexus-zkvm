#![no_std]
#![no_main]

extern crate alloc;

use alloc::string::String;
use core::fmt;

#[repr(C, align(4))]
struct Parens(u8);

#[nexus_rt::main]
fn main() {
    let x = Parens(0);

    let mut buf = String::new();
    fmt::write(&mut buf, format_args!("({}", x.0))
        .expect("Error occurred while trying to write in String");

    // assertion fails unless the workaround in the `Display` impl is used instead
    //    assert_eq!(x.to_string(), r#"(0)"#);
}
