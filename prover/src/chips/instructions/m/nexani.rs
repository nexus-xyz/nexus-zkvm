//! THE IMPLEMENTATION WILL BE MOVED INTO NEXANI CRATE IN THE FUTURE!!
//! Gadget for arithmetic operations on limb-based representations
//!
//! This module contains the implementation of fundamental arithmetic operations
//! for 32-bit and 64-bit integers represented as byte limbs (8-bit chunks).
//!
//! ## Operations Supported:
//! - **Multiplication**: 32-bit × 32-bit → 64-bit using Karatsuba algorithm
//! - **Division**: 32-bit ÷ 32-bit with quotient and remainder verification
//! - **Absolute Value**: Two's complement absolute value for 32-bit and 64-bit integers
//!
//! ## Implementation Details:
//! - Uses limb-by-limb operations for circuit-friendly computation
//! - Karatsuba multiplication reduces complexity from O(n²) to O(n^log₂3)
//! - Division uses multiplication verification: a = b × c + r where 0 ≤ r < c
//! - Absolute value uses two's complement negation with carry propagation
//! - All intermediate values and carries are exposed for zero-knowledge proof constraints

/// Result structure for 32-bit × 32-bit multiplication using Karatsuba algorithm
///
/// Contains all intermediate values and carries needed for zero-knowledge proof verification.
/// The multiplication computes `b × c = a_h << 32 + a_l` where the result is split into
/// high and low 32-bit parts.
pub(super) struct MulResult {
    /// Karatsuba intermediate product p1 = (c0+c1)(b0+b1) - z0 - z1 (2 bytes, little-endian)
    pub p1: [u8; 2],
    /// Carry flag from p1 computation (true if p1 overflowed 16 bits)
    pub c1: bool,
    /// Karatsuba intermediate product p3' = (c0+c3)(b0+b3) - z0 - z3 (2 bytes, little-endian)
    pub p3_prime: [u8; 2],
    /// Carry flag from p3' computation (true if p3' overflowed 16 bits)
    pub c3_prime: bool,
    /// Karatsuba intermediate product p3'' = (c1+c2)(b1+b2) - z1 - z2 (2 bytes, little-endian)
    pub p3_prime_prime: [u8; 2],
    /// Carry flag from p3'' computation (true if p3'' overflowed 16 bits)
    pub c3_prime_prime: bool,
    /// Karatsuba intermediate product p5 = (c2+c3)(b2+b3) - z2 - z3 (2 bytes, little-endian)
    pub p5: [u8; 2],
    /// Carry flag from p5 computation (true if p5 overflowed 16 bits)
    pub c5: bool,
    /// Low 32 bits of the multiplication result b × c (4 bytes, little-endian)
    pub a_l: [u8; 4],
    /// High 32 bits of the multiplication result b × c (4 bytes, little-endian)
    pub a_h: [u8; 4],
    /// Carry values from low 32-bit computation [carry_0, carry_1]
    pub carry_l: [u8; 2],
    /// Carry values from high 32-bit computation [carry_2_low, carry_2_high, carry_3]
    pub carry_h: [u8; 3],
}

/// Multiply two 32-bit unsigned integers using the Karatsuba algorithm
///
/// This function implements 32-bit × 32-bit → 64-bit multiplication using the Karatsuba
/// divide-and-conquer algorithm, which reduces the computational complexity from O(n²) to O(n^log₂3).
/// The implementation is circuit-friendly and returns all intermediate values for the AIR trace.
/// ## Verification process:
/// 1. **Multiplication**: Compute `t = b × c` using `mull_limb`
/// 2. **Constraint Validation**: Ensure all intermediate values satisfy circuit constraints
/// 3. **Result Validation**: Verify that the result matches the expected 64-bit product
///
/// ## Algorithm Overview:
/// 1. **Limb Decomposition**: Split inputs into 4 byte limbs each
/// 2. **Basic Products**: Compute z0, z1, z2, z3 (byte × byte multiplications)
/// 3. **Karatsuba Products**: Compute intermediate cross-products p1, p3', p3'', p5
/// 4. **Result Assembly**: Combine products to form the final 64-bit result
pub(super) fn mull_limb(b: u32, c: u32) -> MulResult {
    // Convert inputs to limbs (4 bytes each)
    let b_limbs = b.to_le_bytes();
    let c_limbs = c.to_le_bytes();

    // Calculate the full 64-bit product using built-in operation
    // This serves as our reference result for verification
    let product = (b as u64) * (c as u64);
    let a_l = product as u32;
    let a_h = (product >> 32) as u32;
    let a_l_bytes = a_l.to_le_bytes();
    let a_h_bytes = a_h.to_le_bytes();

    //--------------------------------------------------------------
    // STEP 1: Compute the 8x8 bit multiplications for each byte pair
    //--------------------------------------------------------------
    // Calculate the individual limb products (each byte multiplied)
    let z0_prod = (c_limbs[0] as u16) * (b_limbs[0] as u16);
    let z0_l = z0_prod as u8;
    let z0_h = (z0_prod >> 8) as u8;

    let z1_prod = (c_limbs[1] as u16) * (b_limbs[1] as u16);
    let z1_l = z1_prod as u8;
    let z1_h = (z1_prod >> 8) as u8;

    let z2_prod = (c_limbs[2] as u16) * (b_limbs[2] as u16);
    let z2_l = z2_prod as u8;
    let z2_h = (z2_prod >> 8) as u8;

    let z3_prod = (c_limbs[3] as u16) * (b_limbs[3] as u16);
    let z3_l = z3_prod as u8;
    let z3_h = (z3_prod >> 8) as u8;

    // Combine low and high parts of each limb product to form 16-bit values
    let z0 = (z0_l as u16).wrapping_add((z0_h as u16) << 8);
    let z1 = (z1_l as u16).wrapping_add((z1_h as u16) << 8);
    let z2 = (z2_l as u16).wrapping_add((z2_h as u16) << 8);
    let z3 = (z3_l as u16).wrapping_add((z3_h as u16) << 8);

    // Convert limbs to u32 for easier calculations with larger intermediate values
    let c_limbs = c_limbs.map(|x| x as u32);
    let b_limbs = b_limbs.map(|x| x as u32);

    //--------------------------------------------------------------
    // STEP 2: Karatsuba multiplication - compute intermediate products
    //--------------------------------------------------------------
    // p1 = (c0+c1)(b0+b1) - z0 - z1
    let p1 = (c_limbs[0].wrapping_add(c_limbs[1]))
        .wrapping_mul(b_limbs[0].wrapping_add(b_limbs[1]))
        .wrapping_sub(z0 as u32)
        .wrapping_sub(z1 as u32);
    let (p1, c1) = (p1 as u16, (p1 >> 16));

    // p2_prime = (c0+c2)(b0+b2) - z0 - z2
    let p2_prime = (c_limbs[0].wrapping_add(c_limbs[2]))
        .wrapping_mul(b_limbs[0].wrapping_add(b_limbs[2]))
        .wrapping_sub(z0 as u32)
        .wrapping_sub(z2 as u32);

    // p3_prime = (c0+c3)(b0+b3) - z0 - z3
    let p3_prime = (c_limbs[0].wrapping_add(c_limbs[3]))
        .wrapping_mul(b_limbs[0].wrapping_add(b_limbs[3]))
        .wrapping_sub(z0 as u32)
        .wrapping_sub(z3 as u32);
    let (p3_prime, c3_prime) = (p3_prime as u16, p3_prime >> 16);

    // p3_prime_prime = (c1+c2)(b1+b2) - z1 - z2
    let p3_prime_prime = (c_limbs[1].wrapping_add(c_limbs[2]))
        .wrapping_mul(b_limbs[1].wrapping_add(b_limbs[2]))
        .wrapping_sub(z1 as u32)
        .wrapping_sub(z2 as u32);
    let (p3_prime_prime, c3_prime_prime) = (p3_prime_prime as u16, p3_prime_prime >> 16);

    // Verify that our carries stay within expected bounds
    // These assertions help catch potential overflow issues
    assert!(c1 < 2, "Carry c1 exceeds expected bounds");
    assert!(c3_prime < 2, "Carry c3_prime exceeds expected bounds");
    assert!(
        c3_prime_prime < 2,
        "Carry c3_prime_prime exceeds expected bounds"
    );

    // Split intermediate products into high and low bytes for further calculations
    let (p1_h, p1_l) = (p1 >> 8, p1 & 0xFF);

    // Get low bytes from intermediate products
    let p3_prime_l = p3_prime & 0xFF;
    let p3_prime_h = (p3_prime >> 8) & 0xFF; // Extract high byte properly

    let p3_prime_prime_l = p3_prime_prime & 0xFF;
    let p3_prime_prime_h = (p3_prime_prime >> 8) & 0xFF; // Extract high byte properly

    //--------------------------------------------------------------
    // STEP 3: Form the lower 32 bits of the final result
    //--------------------------------------------------------------
    // First two bytes of the result (bytes 0-1)
    // Calculate z0 + (p1_l << 8)
    let temp_sum_0 = (z0 as u32) + ((p1_l << 8) as u32);
    let a01 = temp_sum_0 as u16;
    let carry_0 = (temp_sum_0 >> 16) as u16; // Carry value (0 or 1)

    // Next two bytes of the result (bytes 2-3)
    let a23 = (z1 as u32)
        .wrapping_add(p1_h as u32)
        .wrapping_add(p2_prime)
        .wrapping_add(carry_0 as u32)
        .wrapping_add(((p3_prime_l + p3_prime_prime_l + c1 as u16) as u32) << 8);
    let (a23, carry_1) = (a23 as u16, (a23 >> 16));

    // Verify our calculations match the built-in multiplication
    assert!(carry_1 < 5, "Carry_1 exceeds expected bounds {}", carry_1);
    assert_eq!(
        a01.to_le_bytes(),
        [a_l_bytes[0], a_l_bytes[1]],
        "Low bytes (0-1) mismatch"
    );
    assert_eq!(
        a23.to_le_bytes(),
        [a_l_bytes[2], a_l_bytes[3]],
        "Low bytes (2-3) mismatch"
    );

    //--------------------------------------------------------------
    // STEP 4: Form the upper 32 bits of the final result
    //--------------------------------------------------------------
    // Calculate remaining Karatsuba products needed for high bytes
    let p4_prime = b_limbs[1]
        .wrapping_add(b_limbs[3])
        .wrapping_mul(c_limbs[1].wrapping_add(c_limbs[3]))
        .wrapping_sub(z1 as u32)
        .wrapping_sub(z3 as u32);

    let p5 = b_limbs[2]
        .wrapping_add(b_limbs[3])
        .wrapping_mul(c_limbs[2].wrapping_add(c_limbs[3]))
        .wrapping_sub(z2 as u32)
        .wrapping_sub(z3 as u32);

    let (p5, c5) = (p5 as u16, p5 >> 16);
    let (p5_h, p5_l) = (p5 >> 8, p5 & 0xFF);

    assert!(c5 < 2, "Carry c5 exceeds expected bounds");

    // Bytes 4-5 of the final result
    let a45 = (z2 as u32)
        .wrapping_add(p4_prime)
        .wrapping_add(p3_prime_h as u32)
        .wrapping_add(p3_prime_prime_h as u32)
        .wrapping_add((p5_l as u32) << 8)
        .wrapping_add(carry_1)
        .wrapping_add((c3_prime) << 8)
        .wrapping_add((c3_prime_prime) << 8);
    let (a45, carry_2) = (a45 as u16, (a45 >> 16));

    assert!(carry_2 < 4, "Carry_2 exceeds expected bounds {}", carry_2);

    // Bytes 6-7 of the final result
    let a67 = (z3 as u32)
        .wrapping_add(p5_h as u32)
        .wrapping_add((c5) << 8)
        .wrapping_add(carry_2);
    let (a67, carry_3) = (a67 as u16, (a67 >> 16));

    assert!(carry_3 < 2, "Carry_3 exceeds expected bounds");

    // Verify our high bytes match the built-in multiplication
    assert_eq!(
        a45.to_le_bytes(),
        [a_h_bytes[0], a_h_bytes[1]],
        "High bytes (4-5) mismatch"
    );
    assert_eq!(
        a67.to_le_bytes(),
        [a_h_bytes[2], a_h_bytes[3]],
        "High bytes (6-7) mismatch"
    );
    let (carry_2_0, carry_2_1) = (carry_2 & 0x1, (carry_2 >> 1) & 0x1);

    // Return all intermediate and final results for verification and testing
    MulResult {
        p1: p1.to_le_bytes(),
        c1: c1 == 1,
        p3_prime: p3_prime.to_le_bytes(),
        c3_prime: c3_prime == 1,
        p3_prime_prime: p3_prime_prime.to_le_bytes(),
        c3_prime_prime: c3_prime_prime == 1,
        p5: p5.to_le_bytes(),
        c5: c5 == 1,
        a_l: a_l_bytes,
        a_h: a_h_bytes,
        carry_l: [carry_0 as u8, carry_1 as u8],
        carry_h: [carry_2_0 as u8, carry_2_1 as u8, carry_3 as u8],
    }
}

/// Result structure for division verification operations
///
/// Contains the remainder and verification values needed to prove that
/// the division relationship `dividend = quotient × divisor + remainder` holds
/// with `0 ≤ remainder < divisor`.
pub struct DivResult {
    /// Remainder r = dividend - quotient × divisor (4 bytes, little-endian)
    pub r: [u8; 4],
    /// Borrow flags from r = dividend - (quotient × divisor) subtraction
    /// [borrow_0, borrow_1] where borrow_1 must be false for valid division
    pub r_borrow: [bool; 2],
    /// Check value u = divisor - remainder - 1 (4 bytes, little-endian)
    pub u: [u8; 4],
    /// Borrow flags from u = divisor - remainder - 1 subtraction
    /// [borrow_2, borrow_3] where borrow_3 must be false for valid division
    pub u_borrow: [bool; 2],
}

/// Verify a 32-bit unsigned integer division operation
///
/// This function **verifies** rather than **computes** division. Given a quotient, remainder,
/// dividend, and divisor, it checks that the division relationship holds:
/// `dividend = quotient × divisor + remainder` where `0 ≤ remainder < divisor`.
///
/// ## Verification Process:
/// 1. **Multiplication**: Compute `t = quotient × divisor` using `mull_limb`
/// 2. **Remainder Check**: Compute `r = dividend - t` and verify `r ≥ 0`
/// 3. **Bound Check**: Compute `u = divisor - r - 1` and verify `u ≥ 0`
/// 4. **Constraint Validation**: Ensure all intermediate values satisfy circuit constraints
///
/// ## Division by Zero:
/// When `divisor = 0`, follows RISC-V semantics:
/// - DIVU: quotient = 2³² - 1, remainder = dividend
/// - REMU: quotient = undefined, remainder = dividend
///
/// ## Panics:
/// - If `quotient × divisor` overflows 32 bits
/// - If `remainder ≥ divisor` (invalid division)
/// - If any circuit constraints are violated
///
/// ## Example:
/// ```ignore
/// // Verify that 100 ÷ 7 = 14 remainder 2
/// let result = divu_limb(14, 2, 100, 7);
/// assert_eq!(result.r, [2, 0, 0, 0]); // remainder in little-endian bytes
/// assert_eq!(result.r_borrow, [false, false]); // no underflow
/// ```
pub fn divu_limb(quotient: u32, remainder: u32, dividend: u32, divisor: u32) -> DivResult {
    let dividend_bytes = dividend.to_le_bytes();
    let divisor_bytes = divisor.to_le_bytes();
    let quotient_bytes = quotient.to_le_bytes();
    let remainder_bytes = remainder.to_le_bytes();

    // When divisor is 0, for DIVU, the result is 2^32 - 1
    // For REMU, the result is the dividend
    if divisor == 0 {
        return DivResult {
            r: [
                dividend_bytes[0],
                dividend_bytes[1],
                dividend_bytes[2],
                dividend_bytes[3],
            ],
            r_borrow: [false, false],
            // u = c - r - 1 >= 0 is not possible when c = 0, thus we set u to 0
            u: [0, 0, 0, 0],
            u_borrow: [false, false],
        };
    }

    // Calculate t = quotient * divisor
    let t = mull_limb(quotient, divisor);
    // t.a_l contains the low 32 bits of quotient * divisor
    let quotient_divisor_bytes = t.a_l;

    // Assert that quotient * divisor fits within 32 bits (high part of multiplication is zero)
    assert_eq!(
        t.a_h,
        [0, 0, 0, 0],
        "Overflow: quotient * divisor exceeds u32::MAX"
    );

    // Assertions based on mul_limb internal details/constraints
    // These might be specific to the circuit implementation relying on mul_limb
    assert_eq!(t.c5, false);
    assert_eq!(t.p3_prime_prime[1], 0);
    assert_eq!(t.c3_prime_prime, false);
    assert_eq!(t.c3_prime, false);
    assert_eq!(t.p3_prime[1], 0);
    assert_eq!(t.carry_l[1], 0);

    // The above assertions can be combined into a single assertion
    {
        let quotient_bytes = quotient_bytes.map(|x| x as u32);
        let divisor_bytes = divisor_bytes.map(|x| x as u32);
        assert_eq!(
            (quotient_bytes[2] + quotient_bytes[3]) * (divisor_bytes[2] + divisor_bytes[3])
                + quotient_bytes[1] * divisor_bytes[3]
                + quotient_bytes[3] * divisor_bytes[1],
            0
        );
    }

    // Calculate r = a - t = (a - bc) using 16-bit chunks
    let a_low = u16::from_le_bytes([dividend_bytes[0], dividend_bytes[1]]);
    let bc_low = u16::from_le_bytes([quotient_divisor_bytes[0], quotient_divisor_bytes[1]]);
    let (r_low, borrow_0) = a_low.borrowing_sub(bc_low, false);

    let a_high = u16::from_le_bytes([dividend_bytes[2], dividend_bytes[3]]);
    let bc_high = u16::from_le_bytes([quotient_divisor_bytes[2], quotient_divisor_bytes[3]]);
    // Propagate borrow from the low part subtraction
    let (r_high, borrow_1) = a_high.borrowing_sub(bc_high, borrow_0);

    // Combine the 16-bit results back into r_bytes
    let r_bytes = [
        r_low.to_le_bytes()[0],
        r_low.to_le_bytes()[1],
        r_high.to_le_bytes()[0],
        r_high.to_le_bytes()[1],
    ];

    assert_eq!(r_bytes, remainder_bytes, "Remainder is incorrect");

    // Verify the subtraction r = a - bc
    let r_val = u32::from_le_bytes(r_bytes);
    let bc_val = u32::from_le_bytes(quotient_divisor_bytes);
    assert_eq!(r_val, dividend.wrapping_sub(bc_val));

    // Verify the low part subtraction: r_low + borrow_0 * 2^16 = bc_low + r_low
    assert_eq!(
        a_low as u32 + ((borrow_0 as u32) << 16),
        bc_low as u32 + r_low as u32,
        "Low part subtraction check failed"
    );

    // Verify the high part subtraction: a_high + borrow_1 * 2^16 = bc_high + r_high + borrow_0
    assert_eq!(
        a_high as u32 + ((borrow_1 as u32) << 16),
        bc_high as u32 + r_high as u32 + borrow_0 as u32,
        "High part subtraction check failed"
    );
    // Check if r >= 0. This is the core requirement for standard division remainder.
    // If a >= bc, borrow_1 would be false.
    assert_eq!(borrow_1, false, "Remainder r is negative (a < b*c)");

    // Calculate u = c - r - 1
    // This check helps ensure r < c. If c - r - 1 >= 0, then c - r > 0, so c > r.
    let c_low = u16::from_le_bytes([divisor_bytes[0], divisor_bytes[1]]);
    // Start with an initial borrow of 1 for the "- 1" part
    let (u_low, borrow_2) = c_low.borrowing_sub(r_low, true);

    let c_high = u16::from_le_bytes([divisor_bytes[2], divisor_bytes[3]]);
    // Propagate borrow from the low part subtraction
    let (u_high, borrow_3) = c_high.borrowing_sub(r_high, borrow_2);

    // Combine the 16-bit results back into u_bytes
    let u_bytes = [
        u_low.to_le_bytes()[0],
        u_low.to_le_bytes()[1],
        u_high.to_le_bytes()[0],
        u_high.to_le_bytes()[1],
    ];

    // Verify the subtraction u = c - r - 1
    let u_val = u_low as u32 + ((u_high as u32) << 16);
    assert_eq!(u_val, divisor.wrapping_sub(r_val).wrapping_sub(1));

    // Check if u >= 0 (i.e., c - r - 1 >= 0 => c > r).
    // If c <= r, borrow_3 must be false.
    assert_eq!(borrow_3, false, "Check u >= 0 failed (c <= r)");

    // An explicit check that c >= r, which is implied by borrow_3 == false if r is non-negative.
    assert!(divisor >= r_val, "Constraint c >= r failed");

    DivResult {
        r: r_bytes, // r = a - t
        r_borrow: [borrow_0, borrow_1],
        u: u_bytes, // u = c - r - 1
        u_borrow: [borrow_2, borrow_3],
    }
}

/// Result structure for 32-bit absolute value computation
///
/// Contains the absolute value and intermediate carry values from the two's complement
/// negation process used for negative numbers.
pub(super) struct AbsResult {
    /// Absolute value as 4 bytes in little-endian format
    pub abs_limbs: [u8; 4],
    /// Carry flags from two's complement addition: [carry_16bit, carry_32bit]
    /// Only relevant for negative inputs where two's complement negation is performed
    pub carry: [bool; 2],
    /// Sign of the original input (true if negative, false if non-negative)
    pub sgn: bool,
}

/// Compute the absolute value of a 32-bit signed integer using limb-by-limb operations
///
/// This function computes the absolute value using a circuit-friendly approach that
/// explicitly handles the two's complement negation for negative numbers.
/// The implementation is circuit-friendly and returns all intermediate values for the AIR trace.
///
/// ## Algorithm:
/// 1. **Sign Detection**: Extract the sign bit from the input
/// 2. **Conditional Negation**: For negative numbers, perform two's complement:
///    - First complement: Invert all bits (subtract each byte from 255)
///    - Second complement: Add 1 with carry propagation across limbs
/// 3. **Verification**: Validate the result using mathematical constraints
///
/// ## Two's Complement Details:
/// For negative numbers, the algorithm computes `|n| = ~n + 1` where:
/// - `~n` inverts all bits (each byte becomes `255 - byte`)
/// - `+1` adds one with carry propagation across all limbs
/// - Carry flags capture overflow between 16-bit and 32-bit boundaries
///
/// ## Example:
/// ```ignore
/// // Absolute value of -42
/// let result = abs_limb(-42i32 as u32);
/// assert_eq!(result.abs_limbs, [42, 0, 0, 0]); // 42 in little-endian
/// assert_eq!(result.sgn, true); // Original was negative
///
/// // Absolute value of 42 (positive)
/// let result = abs_limb(42);
/// assert_eq!(result.abs_limbs, [42, 0, 0, 0]); // Same result
/// assert_eq!(result.sgn, false); // Original was non-negative
/// ```
///
/// ## Circuit Constraints:
/// The implementation validates correctness using mathematical equations that verify:
/// - Lower 16 bits: `(1-sgn) × unsigned + sgn × signed = unsigned`
/// - Upper 16 bits: Similar constraint with carry propagation
/// - These equations ensure the two's complement negation is computed correctly
pub fn abs_limb(n: u32) -> AbsResult {
    //--------------------------------------------------------------
    // STEP 1: Determine the sign of input and prepare limbs
    //--------------------------------------------------------------
    // Extract the sign bit (1 if negative, 0 if positive)
    let sgn_n = (n >> 31) & 1;
    assert!(sgn_n < 2, "Sign bit must be 0 or 1");

    // Convert input to individual bytes (limbs)
    let n_limbs = n.to_le_bytes().map(|x| x as u32);
    let mut limbs = n.to_le_bytes();

    //--------------------------------------------------------------
    // STEP 2: Negate using two's complement (for negative numbers)
    //--------------------------------------------------------------
    // First complement: invert all bits
    for l in &mut limbs {
        *l = u8::MAX - *l;
    }

    // Second complement: add 1 and propagate carry
    let mut carry = [false; 4];

    // Add 1 to the least significant limb and propagate carry
    (limbs[0], carry[0]) = limbs[0].overflowing_add(1);
    (limbs[1], carry[1]) = limbs[1].overflowing_add(carry[0] as u8);
    (limbs[2], carry[2]) = limbs[2].overflowing_add(carry[1] as u8);
    (limbs[3], carry[3]) = limbs[3].overflowing_add(carry[2] as u8);

    //--------------------------------------------------------------
    // STEP 3: Verify correctness using mathematical constraints
    //--------------------------------------------------------------
    // Convert boolean carries to u32 and limbs to u32 for verification
    let carry_u32 = carry.map(|x| x as u32);
    let limbs_u32 = limbs.map(|x| x as u32);

    // Verify lower 16 bits correctness
    let unsigned_lower: u32 = limbs_u32[0] + (limbs_u32[1] << 8);
    let signed_lower: u32 = (1u32 << 16)
        .wrapping_sub(n_limbs[0])
        .wrapping_sub(n_limbs[1] << 8)
        .wrapping_sub((carry_u32[1]) << 16);

    // This equation verifies correct two's complement calculation for lower 16 bits
    assert_eq!(
        (1 - sgn_n) * unsigned_lower + sgn_n * signed_lower,
        unsigned_lower,
        "Lower 16 bits verification failed"
    );

    // Verify upper 16 bits correctness
    let unsigned_upper: u32 = limbs_u32[2] + (limbs_u32[3] << 8);
    let signed_upper: u32 = (1u32 << 16)
        .wrapping_sub(1)
        .wrapping_sub(n_limbs[2])
        .wrapping_sub(n_limbs[3] << 8)
        .wrapping_add(carry_u32[1])
        .wrapping_sub((carry_u32[3]) << 16);

    // This equation verifies correct two's complement calculation for upper 16 bits
    assert_eq!(
        (1 - sgn_n) * unsigned_upper + sgn_n * signed_upper,
        unsigned_upper,
        "Upper 16 bits verification failed"
    );

    //--------------------------------------------------------------
    // STEP 4: Return the absolute value
    //--------------------------------------------------------------
    // Early return for non-negative numbers
    if sgn_n == 0 {
        AbsResult {
            sgn: sgn_n == 1,
            abs_limbs: n.to_le_bytes(),
            carry: [false, false],
        }
    } else {
        // For negative input, return the computed absolute value
        AbsResult {
            sgn: sgn_n == 1,
            abs_limbs: limbs,
            carry: [carry[1], carry[3]], // Store only the important carry bits
        }
    }
}

/// Result structure for 64-bit absolute value computation
///
/// Contains the absolute value and intermediate carry values from the two's complement
/// negation process, organized into low and high 32-bit sections.
#[derive(Debug, Clone, Copy)]
pub struct AbsResult64 {
    /// Absolute value as 8 bytes in little-endian format
    pub _abs_limbs: [u8; 8],
    /// Carry flags from two's complement addition in low 32 bits: [carry_16bit, carry_32bit]
    pub carry_low: [bool; 2],
    /// Carry flags from two's complement addition in high 32 bits: [carry_48bit, carry_64bit]
    pub carry_high: [bool; 2],
    /// Sign of the original input (true if negative, false if non-negative)
    pub sgn: bool,
}

/// Compute the absolute value of a 64-bit signed integer using limb-by-limb operations
///
/// This function extends the 32-bit absolute value computation to 64-bit integers,
/// taking the input as separate low and high 32-bit parts. It uses the same two's
/// complement approach but with carry propagation across all 8 byte limbs.
/// The implementation is circuit-friendly and returns all intermediate values for the AIR trace.
///
/// ## Algorithm:
/// 1. **Sign Detection**: Extract the sign bit from the high 32 bits
/// 2. **Conditional Negation**: For negative numbers, perform two's complement:
///    - First complement: Invert all bits across all 8 bytes
///    - Second complement: Add 1 with carry propagation from low to high
/// 3. **Verification**: Validate using mathematical constraints for each 16-bit section
///
/// ## Carry Propagation:
/// The algorithm tracks carries at 16-bit boundaries:
/// - `carry_low[0]`: Carry from bits 0-15 to bits 16-31
/// - `carry_low[1]`: Carry from bits 16-31 to bits 32-47
/// - `carry_high[0]`: Carry from bits 32-47 to bits 48-63
/// - `carry_high[1]`: Carry from bits 48-63 (overflow indicator)
///
/// ## Example:
/// ```ignore
/// // Absolute value of -12345678901234567890
/// let low = 0x12345678u32;
/// let high = 0x9ABCDEFu32 | 0x80000000u32; // Set sign bit
/// let result = abs64_limb(low, high);
/// assert_eq!(result.sgn, true); // Original was negative
/// // result._abs_limbs contains the absolute value in little-endian bytes
/// ```
///
/// ## Circuit Constraints:
/// The implementation validates correctness using mathematical equations for each
/// 16-bit section, ensuring the two's complement negation is computed correctly
/// across the full 64-bit range with proper carry propagation.
pub fn abs64_limb(low: u32, high: u32) -> AbsResult64 {
    //--------------------------------------------------------------
    // STEP 1: Determine the sign of input and prepare limbs
    //--------------------------------------------------------------
    // Extract the sign bit (1 if negative, 0 if positive)
    let n = ((high as u64) << 32) | low as u64;
    let sgn_n = (high >> 31) & 1;
    assert!(sgn_n < 2, "Sign bit must be 0 or 1");

    // Convert input to individual bytes (limbs)
    let n_limbs = n.to_le_bytes().map(|x| x as u32);
    let mut limbs = n.to_le_bytes();

    //--------------------------------------------------------------
    // STEP 2: Negate using two's complement (for negative numbers)
    //--------------------------------------------------------------
    // First complement: invert all bits
    for l in &mut limbs {
        *l = u8::MAX - *l;
    }

    // Second complement: add 1 and propagate carry
    let mut carry = [false; 8];

    // Add 1 to the least significant limb and propagate carry
    (limbs[0], carry[0]) = limbs[0].overflowing_add(1);
    (limbs[1], carry[1]) = limbs[1].overflowing_add(carry[0] as u8);
    (limbs[2], carry[2]) = limbs[2].overflowing_add(carry[1] as u8);
    (limbs[3], carry[3]) = limbs[3].overflowing_add(carry[2] as u8);
    (limbs[4], carry[4]) = limbs[4].overflowing_add(carry[3] as u8);
    (limbs[5], carry[5]) = limbs[5].overflowing_add(carry[4] as u8);
    (limbs[6], carry[6]) = limbs[6].overflowing_add(carry[5] as u8);
    (limbs[7], carry[7]) = limbs[7].overflowing_add(carry[6] as u8);

    //--------------------------------------------------------------
    // STEP 3: Verify correctness using mathematical constraints
    //--------------------------------------------------------------
    // Convert boolean carries to u32 and limbs to u32 for verification
    let carry_u32 = carry.map(|x| x as u32);
    let limbs_u32 = limbs.map(|x| x as u32);

    // Verify lower 32 bits correctness
    // Verify bits 0->15 correctness
    let unsigned_lower_0_15: u32 = limbs_u32[0] + (limbs_u32[1] << 8);
    let signed_lower_0_15: u32 = (1u32 << 16)
        .wrapping_sub(n_limbs[0])
        .wrapping_sub(n_limbs[1] << 8)
        .wrapping_sub((carry_u32[1]) << 16);

    // This equation verifies correct two's complement calculation for lower 16 bits
    assert_eq!(
        (1 - sgn_n) * unsigned_lower_0_15 + sgn_n * signed_lower_0_15,
        unsigned_lower_0_15,
        "Lower 16 bits verification failed"
    );

    // Verify bits 16->31 correctness
    let unsigned_upper_16_31: u32 = limbs_u32[2] + (limbs_u32[3] << 8);
    let signed_upper_16_31: u32 = (1u32 << 16)
        .wrapping_sub(1)
        .wrapping_sub(n_limbs[2])
        .wrapping_sub(n_limbs[3] << 8)
        .wrapping_add(carry_u32[1])
        .wrapping_sub((carry_u32[3]) << 16);

    // This equation verifies correct two's complement calculation for upper 16 bits
    assert_eq!(
        (1 - sgn_n) * unsigned_upper_16_31 + sgn_n * signed_upper_16_31,
        unsigned_upper_16_31,
        "Upper 16 bits verification failed"
    );

    // Verify upper 32 bits correctness
    // Verify bits 32->47 correctness
    let unsigned_upper_32_47: u32 = limbs_u32[4] + (limbs_u32[5] << 8);
    let signed_upper_32_47: u32 = (1u32 << 16)
        .wrapping_sub(1)
        .wrapping_sub(n_limbs[4])
        .wrapping_sub(n_limbs[5] << 8)
        .wrapping_add(carry_u32[3])
        .wrapping_sub((carry_u32[5]) << 16);

    // This equation verifies correct two's complement calculation for upper 16 bits
    assert_eq!(
        (1 - sgn_n) * unsigned_upper_32_47 + sgn_n * signed_upper_32_47,
        unsigned_upper_32_47,
        "Upper 16 bits verification failed"
    );

    // Verify bits 48->63 correctness
    let unsigned_upper_48_63: u32 = limbs_u32[6] + (limbs_u32[7] << 8);
    let signed_upper_48_63: u32 = (1u32 << 16)
        .wrapping_sub(1)
        .wrapping_sub(n_limbs[6])
        .wrapping_sub(n_limbs[7] << 8)
        .wrapping_add(carry_u32[5])
        .wrapping_sub((carry_u32[7]) << 16);

    // This equation verifies correct two's complement calculation for upper 16 bits
    assert_eq!(
        (1 - sgn_n) * unsigned_upper_48_63 + sgn_n * signed_upper_48_63,
        unsigned_upper_48_63,
        "Upper 16 bits verification failed"
    );

    //--------------------------------------------------------------
    // STEP 4: Return the absolute value
    //--------------------------------------------------------------
    // Early return for non-negative numbers
    if sgn_n == 0 {
        AbsResult64 {
            sgn: sgn_n == 1,
            _abs_limbs: n.to_le_bytes(),
            carry_low: [false, false],  // No carry for non-negative numbers
            carry_high: [false, false], // No carry for non-negative numbers
        }
    } else {
        // For negative input, return the computed absolute value
        AbsResult64 {
            sgn: sgn_n == 1,
            _abs_limbs: limbs,
            carry_low: [carry[1], carry[3]], // Store only the important carry bits
            carry_high: [carry[5], carry[7]], // Store only the important carry bits
        }
    }
}
