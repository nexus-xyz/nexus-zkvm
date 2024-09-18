#![cfg_attr(target_arch = "riscv32", no_std, no_main)]
fn foo() -> u32 {
    1
}

fn boo() -> u32 {
    9
}
fn fizz() -> (u32, u32, u32) {
    (12, 11, 10)
}
fn buzz() -> u32 {
    0
}
#[cfg(not(target_arch = "riscv32"))]
fn output_handler(x:u32) {
    println!("Output: {}", x);
}
#[nexus_rt::custom_input(a,boo)]
#[nexus_rt::custom_input((x,y,z),fizz)]
#[nexus_rt::custom_output(output_handler)]
#[nexus_rt::custom_input((b),buzz)]
fn moo(a:u32, b:u32, x: u32, y: u32, z:u32) -> u32 {
    a+b+x+y+z
}

#[nexus_rt::custom_input(a, foo)]
#[cfg_attr(target_arch = "riscv32", nexus_rt::public_input(x))]
#[cfg_attr(not(target_arch = "riscv32"), nexus_rt::custom_input(x,buzz))]
fn hello(a:u32, x:u32) -> u32 {
    let i:u32 = 0;
    let b = i + a;
    i + b + x
}

#[nexus_rt::main]
#[cfg_attr(not(target_arch = "riscv32"), nexus_rt::custom_output(output_handler))]
fn main() -> u32 {
    moo();
    foo() + hello()
}