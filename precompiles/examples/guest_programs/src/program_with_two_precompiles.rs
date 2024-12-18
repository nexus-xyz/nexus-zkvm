#![cfg_attr(target_arch = "riscv32", no_std, no_main)]

#[cfg(not(target_arch = "riscv32"))]
compile_error!("This example is only meant to be compiled for RISC-V");

use nexus_precompiles::use_precompiles;

use_precompiles!(::dummy_div::DummyDiv as MyDiv, ::dummy_hash::DummyHash);

#[nexus_rt::main]
fn main() {
    assert_eq!(MyDiv::div(10, 5), 2);
    // assert_eq!(DummyHash::hash(&[1, 2, 3, 4, 5, 6, 7]), 0);
}
