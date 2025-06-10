#![cfg_attr(target_arch = "riscv32", no_std, no_main)]

use nexus_rt::{
    keccak::{Hasher, Keccak},
    println,
};

#[nexus_rt::main]
fn main() {
    let mut keccak = Keccak::v256();
    keccak.update(b"Hello, World!");

    let mut output = [0u8; 32];
    keccak.finalize(&mut output);

    println!("{:?}", output);
}
