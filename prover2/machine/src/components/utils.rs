use nexus_vm::WORD_SIZE;
use nexus_vm_prover_trace::program::{BoolWord, Word};

/// Adds two 4-byte words with carry propagation across each byte.
pub fn add_with_carries(a: Word, b: Word) -> (Word, BoolWord) {
    let mut sum_bytes = [0u8; WORD_SIZE];
    let mut carry_bits = [false; WORD_SIZE];

    // Compute the sum and carry of each limb.
    let (sum, c0) = a[0].overflowing_add(b[0]);
    carry_bits[0] = c0;
    sum_bytes[0] = sum;
    // Process the remaining bytes
    for i in 1..WORD_SIZE {
        // Add the bytes and the previous carry
        let (sum, c1) = a[i].overflowing_add(carry_bits[i - 1] as u8);
        let (sum, c2) = sum.overflowing_add(b[i]);
        // There can't be 2 carry in: a + b + carry, either c1 or c2 is true.
        carry_bits[i] = c1 || c2;
        sum_bytes[i] = sum;
    }
    (sum_bytes, carry_bits)
}

/// Computes the byte-wise subtraction `x - y` with borrow bits across a 4-byte word.
pub fn subtract_with_borrow(x: Word, y: Word) -> (Word, BoolWord) {
    let mut diff_bytes = [0u8; WORD_SIZE];
    let mut borrow_bits: BoolWord = [false; WORD_SIZE];

    let (diff, b0) = x[0].overflowing_sub(y[0]);
    borrow_bits[0] = b0;
    diff_bytes[0] = diff;

    // Process the remaining difference bytes
    for i in 1..WORD_SIZE {
        // Subtract the bytes and the previous borrow
        let (diff, b1) = x[i].overflowing_sub(borrow_bits[i - 1] as u8);
        let (diff, b2) = diff.overflowing_sub(y[i]);

        // There can't be 2 borrow in: a - b - borrow, either b1 or b2 is true.
        borrow_bits[i] = b1 || b2;
        diff_bytes[i] = diff;
    }
    (diff_bytes, borrow_bits)
}

/// Performs x - 1 - y, returning the result and the borrow bits
///
/// Note that for - 1 - y, for every limb, just one borrow bit suffices
pub fn decr_subtract_with_borrow(x: Word, y: Word) -> (Word, BoolWord) {
    let (diff, borrow1) = subtract_with_borrow(x, 1u32.to_le_bytes());
    let (diff, borrow2) = subtract_with_borrow(diff, y);
    for i in 0..WORD_SIZE {
        assert!(!borrow1[i] || !borrow2[i]);
    }
    let borrow = std::array::from_fn(|i| borrow1[i] | borrow2[i]);
    (diff, borrow)
}

/// Splits a 32-bit unsigned integer into two 16-bit limbs in little-endian order.
pub fn u32_to_16bit_parts_le(a: u32) -> [u16; 2] {
    let mask = (1 << 16) - 1;
    [(a & mask) as u16, ((a >> 16) & mask) as u16]
}

/// Adds a value to the lower part of a half-word, returns a carry flag along with result.
pub fn add_16bit_with_carry(a: [u16; 2], i: u16) -> ([u16; 2], bool) {
    assert!(i == 1 || i == WORD_SIZE as u16);

    let (low, carry) = a[0].overflowing_add(i);
    let high = a[1] + u16::from(carry);

    ([low, high], carry)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_16bit_conversion() {
        for (a, expected) in [
            (0, [0, 0]),
            ((0xFFFF_FFFF), [0xFFFF, 0xFFFF]),
            ((0xFFFF_0000), [0x0000, 0xFFFF]),
            ((0x1234_5678), [0x5678, 0x1234]),
            ((0x0000_0001), [0x0001, 0x0000]),
        ] {
            assert_eq!(u32_to_16bit_parts_le(a), expected);
        }
    }

    #[test]
    fn test_increment_16bit() {
        for a in [0, 0xF, 0xFF, 0xFFFF, 0xFFFFF, 0xFFFAF] {
            let a_parts = u32_to_16bit_parts_le(a);
            let a_inc = a + 1;
            let expected = u32_to_16bit_parts_le(a_inc);

            let (result, carry) = add_16bit_with_carry(a_parts, 1);
            assert_eq!(result, expected);
            assert_eq!(carry, a_parts[0] == u16::MAX);
        }
    }

    #[test]
    fn test_add_word_16bit() {
        for a in [0, 0xF, 0xFF, 0xFFFF, 0xFFFFF, 0xFFFAF, 0xFFFB] {
            let a_parts = u32_to_16bit_parts_le(a);
            let a_inc = a + WORD_SIZE as u32;
            let expected = u32_to_16bit_parts_le(a_inc);

            let (result, carry) = add_16bit_with_carry(a_parts, WORD_SIZE as u16);

            assert_eq!(result, expected);
            assert_eq!(carry, a_parts[0] > u16::MAX - WORD_SIZE as u16);
        }
    }
}
