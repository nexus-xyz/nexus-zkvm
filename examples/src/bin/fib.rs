#![no_std]
#![no_main]

use nexus_rt::*;

fn fib(n: u32) -> u32 {
    match n {
        0 => 1,
        1 => 1,
        _ => fib(n - 1) + fib(n - 2),
    }
}

#[entry]
fn main() {
    for n in 0..10 {
        println!("fib({n}) = {}", fib(n));
    }
}
