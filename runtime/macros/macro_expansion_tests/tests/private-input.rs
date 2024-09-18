#![cfg_attr(target_arch = "riscv32", no_std, no_main)]

#[cfg(not(target_arch = "riscv32"))]
fn input_handler()-> (u32,u32) {
    (1, 2)
}

#[cfg(not(target_arch = "riscv32"))]
fn output_handler(result:u32) {
    println!("Output: {}", result);
}
#[nexus_rt::main]
#[cfg_attr(not(target_arch = "riscv32"), nexus_rt::custom_input((x,y),input_handler))]
#[cfg_attr(not(target_arch = "riscv32"), nexus_rt::custom_output(output_handler))]
#[cfg_attr(target_arch = "riscv32", nexus_rt::private_input(x))]
fn main(x: u32, y:u32) -> u32{
    x * y
}