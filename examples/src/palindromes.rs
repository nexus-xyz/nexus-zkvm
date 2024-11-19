#![cfg_attr(target_arch = "riscv32", no_std, no_main)]

extern crate alloc;

use alloc::string::String;
use nexus_rt::println;

fn is_palindrome_string(s: &str) -> bool {
    let rev_s: String = s.chars().rev().collect(); // Reverse the string
    s == rev_s // Check if the original string is equal to the reversed string
}

fn is_palindrome_decimal(mut n: u32) -> bool {
    // If the number ends with 0, it cannot be a palindrome (except for 0 itself).
    if n == 0 || (n % 10 != 0) {
        let mut reversed = 0;
        while n > reversed {
            reversed = reversed * 10 + n % 10;
            n /= 10;
        }
        // When the loop ends, n has been reduced to half its size, and reversed contains the reversed second half.
        // We compare the first half (n) with the second half (reversed). For odd number of digits, we divide reversed by 10.
        return n == reversed || n == reversed / 10;
    }
    false
}

fn is_palindrome_binary(n: u32) -> bool {
    // Find the highest set bit position
    let mut high_bit = 31; // Assuming 32-bit unsigned integer
    while high_bit > 0 && n & (1 << high_bit) == 0 {
        high_bit -= 1;
    }

    let mut low_bit = 0;
    while low_bit < high_bit {
        // Check if the bits at the low_bit and high_bit positions are different
        if (n & (1 << low_bit)) >> low_bit != (n & (1 << high_bit)) >> high_bit {
            return false;
        }
        low_bit += 1;
        high_bit -= 1;
    }

    true
}

#[nexus_rt::main]
fn main() {
    let mut input_str = "madam";
    let mut is_pal = is_palindrome_string(input_str);
    assert!(is_pal);
    println!("{} is a string palindrome", input_str);

    let mut input_dec = 23432;
    is_pal = is_palindrome_decimal(input_dec);
    assert!(is_pal);
    println!("{} is a decimal palindrome", input_dec);

    let mut input_bin = 0b100001; // Example input (33 in decimal, binary representation is palindromic)
    is_pal = is_palindrome_binary(input_bin);
    assert!(is_pal);
    println!("{} is a binary palindrome", input_bin);

    input_str = "nexus";
    is_pal = is_palindrome_string(input_str);
    assert!(!is_pal);
    println!("{} is not a string palindrome", input_str);

    input_dec = 12345;
    is_pal = is_palindrome_decimal(input_dec);
    assert!(!is_pal);
    println!("{} is not a decimal palindrome", input_dec);

    input_bin = 0b100000; // Example input (32 in decimal, binary representation is not palindromic)
    is_pal = is_palindrome_binary(input_bin);
    assert!(!is_pal);
    println!("{} is not a binary palindrome", input_bin);
}
