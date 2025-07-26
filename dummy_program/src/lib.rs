#![no_std]
#![no_main]

#[no_mangle]
pub extern "C" fn main() -> u64 {
    add(2, 2)
}

#[no_mangle]
pub extern "C" fn add(left: u64, right: u64) -> u64 {
    left + right
}