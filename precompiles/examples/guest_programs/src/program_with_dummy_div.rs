#![cfg_attr(target_arch = "riscv32", no_std, no_main)]

#[cfg(not(target_arch = "riscv32"))]
compile_error!("This example is only meant to be compiled for RISC-V");

use nexus_precompiles::use_precompiles;

use_precompiles!(::dummy_div::DummyDiv as MyDiv);

#[nexus_rt::main]
fn main() {
    assert_eq!(MyDiv::div(10, 5), 2);
}
