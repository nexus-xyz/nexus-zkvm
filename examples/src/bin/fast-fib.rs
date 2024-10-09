#![no_std]
#![no_main]

use nexus_rt::{read_from_private_input, write_output};

fn fib(n: u32, mut t1: i32, mut t2: i32) -> i32 {
    let mut t3 = 0;
    for _int in 0..n {
        t3 = t1 + t2;
        t1 = t2;
        t2 = t3;
    }
    return t3;
}

#[nexus_rt::main]
fn main() {
    let n = read_from_private_input().unwrap_or(10) as u32;
    let t1 = read_from_private_input().unwrap_or(0) as i32;
    let t2 = read_from_private_input().unwrap_or(1) as i32;
    let result = fib(n, t1, t2);
    write_output::<i32>(&result);
}
