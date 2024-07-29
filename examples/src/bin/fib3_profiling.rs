// Used in the CI as a small example that uses memory store
#![cfg_attr(target_arch = "riscv32", no_std, no_main)]

#[nexus_rt::profile]
fn fib(n: u32) -> u32 {
    match n {
        0 => 0,
        1 => 1,
        _ => fib(n - 1) + fib(n - 2),
    }
}

#[nexus_rt::profile]
fn fib2(n: u32) -> u32 {
    if n == 0 {
        return 0;
    }
    if n == 1 {
        return 1;
    }
    let mut a = 0;
    let mut b = 1;
    let mut result = 0;
    for _ in 2..=n {
        result = a + b;
        a = b;
        b = result;
    }
    result
}

#[nexus_rt::main]
fn main() {
    let n = 3;
    assert_eq!(fib(n), 2);
    assert_eq!(fib2(n), 2);
}
