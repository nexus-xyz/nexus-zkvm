#![cfg_attr(target_arch = "riscv32", no_std, no_main)]

#[nexus_rt::main]
fn main() {
    let mut a = 0;
    let mut b = 1;
    for _ in 0..=10 {
        let c = a + b;
        a = b;
        b = c;
    }
}
