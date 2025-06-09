/// THE IMPLEMENTATION WILL BE MOVED INTO NEXANI CRATE IN THE FUTURE!!
/// Gadget for multiplication and division operations
///
/// This module contains the implementation of the multiplication and division operations
/// for the 32-bit limbs.
///
/// The implementation is based on the Karatsuba algorithm, which is a divide-and-conquer
/// algorithm for multiplying two large numbers.
pub(super) struct MulResult {
    pub p1: [u8; 2],
    pub c1: bool,
    pub p3_prime: [u8; 2],
    pub c3_prime: bool,
    pub p3_prime_prime: [u8; 2],
    pub c3_prime_prime: bool,
    pub p5: [u8; 2],
    pub c5: bool,
    pub a_l: [u8; 4],
    pub a_h: [u8; 4],
    pub carry_l: [u8; 3],
    pub carry_h: [u8; 3],
}

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
    assert!(carry_1 < 4, "Carry_1 exceeds expected bounds {}", carry_1);
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
    let (carry_1_0, carry_1_1) = (carry_1 & 0x1, (carry_1 >> 1) & 0x1);
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
        carry_l: [carry_0 as u8, carry_1_0 as u8, carry_1_1 as u8],
        carry_h: [carry_2_0 as u8, carry_2_1 as u8, carry_3 as u8],
    }
}

pub struct DivResult {
    // Remainder: r = a - b * c = a - t
    pub r: [u8; 4],
    // Borrows for r = a - t calculation
    pub r_borrow: [bool; 2],
    // Check value: u = c - r - 1
    pub u: [u8; 4],
    // Borrows for u = c - r - 1 calculation
    pub u_borrow: [bool; 2],
}

// This function verifies the relationship a = b * c + r, where 0 <= r < c.
// It computes t = b * c, r = a - t, and u = c - r - 1.
// It asserts that the intermediate borrow flags are as expected,
// specifically that r >= 0 (borrow_1 is false) and u >= 0 (borrow_3 is false).
// This implies 0 <= r < c.
//
// Preconditions:
// - b * c must fit within a u32 (checked by mul_limb result t.a_h == [0; 4]).
// - The specific implementation details of mul_limb might impose further constraints
//   (e.g., related to t.c5, t.p3_prime_prime, etc.), which are asserted here.
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

pub(super) struct AbsResult {
    pub abs_limbs: [u8; 4],
    pub carry: [bool; 2],
    pub sgn: bool,
}

/// Compute the absolute value of a 32-bit integer represented as 4 8-bit limbs
///
/// This function implements absolute value computation using limb-by-limb operations:
/// 1. For negative numbers: We negate each limb (two's complement) and add 1
/// 2. For non-negative numbers: We return the original value
///
/// The two's complement negation is done by:
/// - Inverting each bit (complementing)
/// - Adding 1 to the result
///
/// Returns the absolute value result as limbs and carry flags
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

#[derive(Debug, Clone, Copy)]
pub struct AbsResult64 {
    pub _abs_limbs: [u8; 8],
    pub carry_low: [bool; 2],
    pub carry_high: [bool; 2],
    pub sgn: bool,
}

/// Compute the absolute value of a 64-bit integer represented as 8 8-bit limbs
///
/// This function implements absolute value computation using limb-by-limb operations:
/// 1. For negative numbers: We negate each limb (two's complement) and add 1
/// 2. For non-negative numbers: We return the original value
///
/// The two's complement negation is done by:
/// - Inverting each bit (complementing)
/// - Adding 1 to the result
///
/// Returns the absolute value result as limbs and carry flags
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
