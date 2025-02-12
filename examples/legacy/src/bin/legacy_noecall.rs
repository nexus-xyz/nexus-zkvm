#![cfg_attr(target_arch = "riscv32", no_std, no_main)]

fn fib(n: u32) -> u32 {
    match n {
        0 => 0,
        1 => 1,
        _ => fib(n - 1) + fib(n - 2),
    }
}

#[nexus_rt::main]
fn main() {
    let n = 10;
    let result = fib(n);
    core::hint::black_box(result);
}
