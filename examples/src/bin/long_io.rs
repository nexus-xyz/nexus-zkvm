#![cfg_attr(target_arch = "riscv32", no_std, no_main)]

#[nexus_rt::main]
#[nexus_rt::public_input(a0, a1, a2, a3, a4)]
#[nexus_rt::private_input(b0, b1, b2, b3, b4)]
fn main(
    a0: bool,
    a1: u8,
    a2: u16,
    a3: u32,
    a4: u64,
    b0: bool,
    b1: u8,
    b2: u16,
    b3: u32,
    b4: u64,
) -> (bool, u8, u16, u32, u64) {
    (a0 & b0, a1 + b1, a2 + b2, a3 + b3, a4 + b4)
}
