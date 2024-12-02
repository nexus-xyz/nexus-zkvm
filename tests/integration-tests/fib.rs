#![cfg_attr(target_arch = "riscv32", no_std, no_main)]

#[nexus_rt::main]
#[nexus_rt::public_input(n)]
fn main(n: u32) -> u32 {
    let mut a = 0;
    let mut b = 1;

    if n == 0 {
        return a;
    }

    for _ in 2..n {
        let c = a + b;
            a = b;
        b = c;
    }

    b
}
