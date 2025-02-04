pub fn sign_extend(value: u32, num_bits: usize) -> u32 {
    let mask = (1 << num_bits) - 1;
    let lower_bits = value & mask;

    if value & (1 << (num_bits)) != 0 {
        // sign extend
        return lower_bits + (1 << num_bits);
    }

    lower_bits
}

#[cfg(test)]
mod tests {
    use super::sign_extend;

    #[test]
    fn test() {
        let a = 0u32.wrapping_sub(8);
        let b = sign_extend(a, 12);
        assert_eq!(b, 0b1111_1111_1000 + (1 << 12));
        assert_eq!(sign_extend(2047, 12), 2047);

        let a = 0u32.wrapping_sub(30000);
        let b = sign_extend(a, 16);
        assert_eq!(b, 0b1000_1010_1101_0000 + (1 << 16));

        assert_eq!(sign_extend(524287, 20), 524287);
    }
}
