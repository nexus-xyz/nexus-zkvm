#![no_std]
#![no_main]

extern crate alloc;

use alloc::string::ToString;
use core::fmt::Display;
use nexus_rt::Write;

struct Parens(u8);

impl Display for Parens {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "~~({})~~", self.0)
    }
}

// Alternative implementation which apparently works around the problem:
// impl Display for Parens {
//     fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
//         write!(f, "~~({}", self.0)?;
//         write!(f, ")~~")
//     }
// }


#[nexus_rt::main]
fn main() {
    let x = Parens(0);
    let y = x.to_string();

    nexus_rt::print!("~~A~~\n");
    nexus_rt::print!("{}\n", x);
    nexus_rt::print!("~~B~~\n");
    nexus_rt::print!("{}\n", y);
    nexus_rt::print!("~~C~~\n");

    // assertion fails unless the workaround in the `Display` impl is used instead
    assert_eq!(y, r#"~~(0)~~"#);
}
