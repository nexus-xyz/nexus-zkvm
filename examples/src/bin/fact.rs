#![no_std]
#![no_main]

use nexus_rt::{Write, println};

#[nexus_rt::main]
fn main() {
    fn f(n: u32) -> u32 {
        if n <= 1 {
            1
        } else {
            n * f(n - 1)
        }
    }
    let n = 15;
    println!("fact {n} = {}", f(n))
}
