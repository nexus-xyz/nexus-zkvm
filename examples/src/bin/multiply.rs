#![cfg_attr(target_arch = "riscv32", no_std, no_main)]
#![allow(asm_sub_register)]

use nexus_rt::println;

// Basic multiplication
#[inline(never)]
#[cfg(target_arch = "riscv32")]
fn test_mul(a: i32, b: i32) -> i32 {
    unsafe {
        let result: i32;
        core::arch::asm!(
            "mul {result}, {a}, {b}",
            result = out(reg) result,
            a = in(reg) a,
            b = in(reg) b,
        );
        result
    }
}

#[inline(never)]
#[cfg(not(target_arch = "riscv32"))]
fn test_mul(a: i32, b: i32) -> i32 {
    a * b // Fallback for non-RISC-V targets
}

// Signed multiply high
#[inline(never)]
#[cfg(target_arch = "riscv32")]
fn test_mulh(a: i32, b: i32) -> i32 {
    unsafe {
        let result: i32;
        core::arch::asm!(
            "mulh {result}, {a}, {b}",
            result = out(reg) result,
            a = in(reg) a,
            b = in(reg) b,
        );
        result
    }
}

#[inline(never)]
#[cfg(not(target_arch = "riscv32"))]
fn test_mulh(a: i32, b: i32) -> i32 {
    (((a as i64) * (b as i64)) >> 32) as i32 // Fallback implementation
}

// Signed-unsigned multiply high
#[inline(never)]
#[cfg(target_arch = "riscv32")]
fn test_mulhsu(a: i32, b: u32) -> i32 {
    unsafe {
        let result: i32;
        core::arch::asm!(
            "mulhsu {result}, {a}, {b}",
            result = out(reg) result,
            a = in(reg) a,
            b = in(reg) b,
        );
        result
    }
}

#[inline(never)]
#[cfg(not(target_arch = "riscv32"))]
fn test_mulhsu(a: i32, b: u32) -> i32 {
    (((a as i64) * (b as i64)) >> 32) as i32 // Fallback implementation
}

// Unsigned multiply high
#[inline(never)]
#[cfg(target_arch = "riscv32")]
fn test_mulhu(a: u32, b: u32) -> u32 {
    unsafe {
        let result: u32;
        core::arch::asm!(
            "mulhu {result}, {a}, {b}",
            result = out(reg) result,
            a = in(reg) a,
            b = in(reg) b,
        );
        result
    }
}

#[inline(never)]
#[cfg(not(target_arch = "riscv32"))]
fn test_mulhu(a: u32, b: u32) -> u32 {
    (((a as u64) * (b as u64)) >> 32) as u32 // Fallback implementation
}

// Signed division
#[inline(never)]
#[cfg(target_arch = "riscv32")]
fn test_div(a: i32, b: i32) -> i32 {
    unsafe {
        let result: i32;
        core::arch::asm!(
            "div {result}, {a}, {b}",
            result = out(reg) result,
            a = in(reg) a,
            b = in(reg) b,
        );
        result
    }
}

#[inline(never)]
#[cfg(not(target_arch = "riscv32"))]
fn test_div(a: i32, b: i32) -> i32 {
    if b == 0 {
        -1
    } else {
        a / b
    } // Fallback with RISC-V div-by-zero behavior
}

// Unsigned division
#[inline(never)]
#[cfg(target_arch = "riscv32")]
fn test_divu(a: u32, b: u32) -> u32 {
    unsafe {
        let result: u32;
        core::arch::asm!(
            "divu {result}, {a}, {b}",
            result = out(reg) result,
            a = in(reg) a,
            b = in(reg) b,
        );
        result
    }
}

#[inline(never)]
#[cfg(not(target_arch = "riscv32"))]
fn test_divu(a: u32, b: u32) -> u32 {
    if b == 0 {
        u32::MAX
    } else {
        a / b
    } // Fallback with RISC-V div-by-zero behavior
}

// Signed remainder
#[inline(never)]
#[cfg(target_arch = "riscv32")]
fn test_rem(a: i32, b: i32) -> i32 {
    unsafe {
        let result: i32;
        core::arch::asm!(
            "rem {result}, {a}, {b}",
            result = out(reg) result,
            a = in(reg) a,
            b = in(reg) b,
        );
        result
    }
}

#[inline(never)]
#[cfg(not(target_arch = "riscv32"))]
fn test_rem(a: i32, b: i32) -> i32 {
    if b == 0 {
        a
    } else {
        a % b
    } // Fallback with RISC-V rem-by-zero behavior
}

// Unsigned remainder
#[inline(never)]
#[cfg(target_arch = "riscv32")]
fn test_remu(a: u32, b: u32) -> u32 {
    unsafe {
        let result: u32;
        core::arch::asm!(
            "remu {result}, {a}, {b}",
            result = out(reg) result,
            a = in(reg) a,
            b = in(reg) b,
        );
        result
    }
}

#[inline(never)]
#[cfg(not(target_arch = "riscv32"))]
fn test_remu(a: u32, b: u32) -> u32 {
    if b == 0 {
        a
    } else {
        a % b
    } // Fallback with RISC-V remu-by-zero behavior
}

#[nexus_rt::main]
fn main() {
    println!("=== Testing RISC-V M Extension Instructions ===");

    // Test data
    let a: i32 = 42;
    let b: i32 = 7;
    let ua: u32 = 42;
    let ub: u32 = 7;
    let large_a: i32 = 0x7FFFFFFF; // Max positive i32
    let large_b: i32 = 2;

    println!("Test values: a={}, b={}, ua={}, ub={}", a, b, ua, ub);
    println!("Large values: large_a={}, large_b={}", large_a, large_b);

    // Test MUL instruction
    let mul_result = test_mul(a, b);
    println!("MUL: {} * {} = {}", a, b, mul_result);

    // Test MULH instruction (signed high multiplication)
    let mulh_result = test_mulh(large_a, large_b);
    println!("MULH: {} *H {} = {}", large_a, large_b, mulh_result);

    // Test MULHSU instruction (signed-unsigned high multiplication)
    let mulhsu_result = test_mulhsu(large_a, ub);
    println!("MULHSU: {} *HSU {} = {}", large_a, ub, mulhsu_result);

    // Test MULHU instruction (unsigned high multiplication)
    let mulhu_result = test_mulhu(ua, ub);
    println!("MULHU: {} *HU {} = {}", ua, ub, mulhu_result);

    // Test DIV instruction
    let div_result = test_div(a, b);
    println!("DIV: {} / {} = {}", a, b, div_result);

    // Test DIVU instruction
    let divu_result = test_divu(ua, ub);
    println!("DIVU: {} /U {} = {}", ua, ub, divu_result);

    // Test REM instruction
    let rem_result = test_rem(a, b);
    println!("REM: {} % {} = {}", a, b, rem_result);

    // Test REMU instruction
    let remu_result = test_remu(ua, ub);
    println!("REMU: {} %U {} = {}", ua, ub, remu_result);

    // Test edge cases
    println!("\n=== Edge Cases ===");

    // Division by zero (should return -1 for DIV, max value for DIVU)
    let div_zero = test_div(a, 0);
    let divu_zero = test_divu(ua, 0);
    println!("DIV by zero: {} / 0 = {}", a, div_zero);
    println!("DIVU by zero: {} / 0 = {}", ua, divu_zero);

    // Remainder by zero (should return dividend)
    let rem_zero = test_rem(a, 0);
    let remu_zero = test_remu(ua, 0);
    println!("REM by zero: {} % 0 = {}", a, rem_zero);
    println!("REMU by zero: {} % 0 = {}", ua, remu_zero);

    // Overflow case for signed division
    let overflow_div = test_div(-2147483648i32, -1);
    println!(
        "Overflow DIV: {} / {} = {}",
        -2147483648i32, -1, overflow_div
    );

    println!("\n=== All M Extension Tests Completed ===");
}
