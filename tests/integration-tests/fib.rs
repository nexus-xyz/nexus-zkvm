#![cfg_attr(target_arch = "riscv32", no_std, no_main)]

#[nexus_rt::main]
#[nexus_rt::public_input(n)]
fn main(n: u32) -> u32 {
    // Handle edge cases
    if n == 0 {
        return 0;
    }
    if n == 1 {
        return 1;
    }

    let mut a = 0u32;
    let mut b = 1u32;

    for _ in 2..n {
        // Check for potential overflow before addition
        if let Some(c) = a.checked_add(b) {
            a = b;
            b = c;
        } else {
            // In case of overflow, return max value
            return u32::MAX;
        }
    }

    b
}
