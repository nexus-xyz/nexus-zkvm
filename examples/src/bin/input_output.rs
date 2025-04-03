#![cfg_attr(target_arch = "riscv32", no_std, no_main)]

use nexus_rt::println;

#[cfg(not(target_arch = "riscv32"))]
fn read_inputs() -> Result<(u32, u32), String> {
    Ok((42, 24))
}

#[cfg(not(target_arch = "riscv32"))]
fn result(output: &u32) -> Result<(), String> {
    println!("Result: {}", output);
    Ok(())
}

#[nexus_rt::main]
#[cfg_attr(not(target_arch = "riscv32"), nexus_rt::custom_input((x, y), read_inputs))]
#[cfg_attr(not(target_arch = "riscv32"), nexus_rt::custom_output(result))]
#[cfg_attr(target_arch = "riscv32", nexus_rt::public_input(x))]
fn main(x: u32, y: u32) -> u32 {
    println!("Read public input:  {}", x);
    println!("Read private input: {}", y);

    x * y
}
