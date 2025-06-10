#![cfg_attr(target_arch = "riscv32", no_std, no_main)]
#[cfg(target_arch = "riscv32")]
use nexus_rt::println;
#[cfg(not(target_arch = "riscv32"))]
use std::println;

use core::ops::Add;

#[derive(Copy, Clone)]
struct BN([u128; 6]);

const ONE: BN = BN([1, 0, 0, 0, 0, 0]);

// carrying_add is unstable, so we define it here
fn adc(x: u128, y: u128, c: bool) -> (u128, bool) {
    let (z1, c1) = x.overflowing_add(y);
    let (z2, c2) = z1.overflowing_add(if c { 1 } else { 0 });
    (z2, c1 || c2)
}

impl Add for BN {
    type Output = BN;
    fn add(self, rhs: Self) -> Self::Output {
        let (a, o) = adc(self.0[0], rhs.0[0], false);
        let (b, o) = adc(self.0[1], rhs.0[1], o);
        let (c, o) = adc(self.0[2], rhs.0[2], o);
        let (d, o) = adc(self.0[3], rhs.0[3], o);
        let (e, o) = adc(self.0[4], rhs.0[4], o);
        let (f, _) = adc(self.0[5], rhs.0[5], o);
        Self([a, b, c, d, e, f])
    }
}

fn fib_iter(n: u32) -> BN {
    let mut a = ONE;
    let mut b = ONE;

    for n in 0..n + 1 {
        if n > 1 {
            let c = a + b;
            a = b;
            b = c;
        }
    }
    b
}

#[cfg(not(target_arch = "riscv32"))]
fn public_input_native() -> Result<u32, String> {
    use std::io::{self, BufRead};
    let stdin = io::stdin();
    let mut lines = stdin.lock().lines();

    let line = lines
        .next()
        .ok_or("No input provided")?
        .map_err(|e| format!("Failed to read line: {}", e))?;

    line.trim()
        .parse()
        .map_err(|e| format!("Failed to parse input as u32: {}", e))
}

#[nexus_rt::main]
#[cfg_attr(target_arch = "riscv32", nexus_rt::public_input(x))]
#[cfg_attr(
    not(target_arch = "riscv32"),
    nexus_rt::custom_input(x, public_input_native)
)]
fn main(x: u32) {
    let b = fib_iter(x);

    // we have to use the result to prevent the optimizer
    // from discarding everything
    println!("{:?}", b.0);
}
