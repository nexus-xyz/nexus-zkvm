use std::fmt::{Debug, Display};

use crate::constants::WORD_SIZE;

pub trait Alignable: Sized + Copy + Display + Debug {
    /// Align the value to the lowest multiple of `WORD_SIZE` at least as large as `self`.
    fn word_align(self) -> Self {
        self.align_to::<WORD_SIZE>()
    }

    /// Align the value to the lowest multiple of `WORD_SIZE` larger than `self`. This function's
    /// behavior only differs from `word_align` for word-aligned values, where this function will
    /// add `WORD_SIZE` to the value and `word_align` will not.
    fn next_word_boundary(self) -> Self {
        self.next_aligned_boundary::<WORD_SIZE>()
    }

    /// Return true if the value is an integer multiple of `WORD_SIZE`.
    fn is_word_aligned(self) -> bool {
        self.is_aligned_to::<WORD_SIZE>()
    }

    /// Align the value to the lowest multiple of `N` at least as large as `self`. `N` must be a
    /// power of 2 that fits in `Self`.
    fn align_to<const N: usize>(self) -> Self;

    /// Align the value to the lowest multiple of `N` larger than `self`. This function's behavior
    /// only differs from `align_to` for aligned values, where this function will add `N` to the
    /// value and `align_to` will not.
    ///
    /// `N` must be a power of 2 that fits in `Self`.
    fn next_aligned_boundary<const N: usize>(self) -> Self;

    /// Return true if the value is an integer multiple of `N`. `N` must be a power of 2 that
    /// fits in `Self`.
    fn is_aligned_to<const N: usize>(self) -> bool;

    fn assert_aligned_to<const N: usize>(self) {
        assert!(
            self.is_aligned_to::<N>(),
            "{} is not aligned to {}",
            self,
            N
        );
    }

    /// Assert that the value is aligned to a word boundary.
    fn assert_word_aligned(self) {
        self.assert_aligned_to::<WORD_SIZE>();
    }

    /// Convert a byte length into a word length. This is the number of words needed to store the
    /// given number of bytes `self`.
    fn byte_len_in_words(self) -> Self;
}

impl Alignable for u32 {
    fn align_to<const N: usize>(self) -> Self {
        // Rust doesn't tolerate const computations on generics for some reason.
        debug_assert!(N.count_ones() == 1);
        debug_assert!(N < u32::MAX as usize);

        self.next_multiple_of(N as u32)
    }

    fn next_aligned_boundary<const N: usize>(self) -> Self {
        // Rust doesn't tolerate const computations on generics for some reason.
        debug_assert!(N.count_ones() == 1);
        debug_assert!(N < u32::MAX as usize);

        (self + N as u32) & !(N as u32 - 1)
    }

    fn is_aligned_to<const N: usize>(self) -> bool {
        // Rust doesn't tolerate const computations on generics for some reason.
        debug_assert!(N.count_ones() == 1);
        debug_assert!(N < u32::MAX as usize);

        self & (N as u32 - 1) == 0
    }

    fn byte_len_in_words(self) -> Self {
        self.div_ceil(WORD_SIZE as u32)
    }
}

impl Alignable for usize {
    fn align_to<const N: usize>(self) -> Self {
        // Rust doesn't tolerate const computations on generics for some reason.
        debug_assert!(N.count_ones() == 1);

        self.next_multiple_of(N)
    }

    fn next_aligned_boundary<const N: usize>(self) -> Self {
        // Rust doesn't tolerate const computations on generics for some reason.
        debug_assert!(N.count_ones() == 1);

        (self + N) & !(N - 1)
    }

    fn is_aligned_to<const N: usize>(self) -> bool {
        // Rust doesn't tolerate const computations on generics for some reason.
        debug_assert!(N.count_ones() == 1);

        self & (N - 1) == 0
    }

    fn byte_len_in_words(self) -> Self {
        self.div_ceil(WORD_SIZE)
    }
}

#[cfg(test)]
mod tests {
    use super::Alignable;

    #[test]
    fn test_alignable() {
        // Test `word_align`
        #[allow(clippy::reversed_empty_ranges)] // absurd false positive
        for i in 0x1001..1005 {
            assert_eq!((i as u32).word_align(), 0x1004);
            assert_eq!((i as usize).word_align(), 0x1004);
        }

        // Test `align_to`
        for i in 0x1001..0x1011 {
            assert_eq!((i as u32).align_to::<0x10>(), 0x1010);
            assert_eq!((i as usize).align_to::<0x10>(), 0x1010);
        }

        for i in 0x1001..0x1010 {
            assert!(!(i as u32).is_aligned_to::<0x10>());
            assert!(!(i as usize).is_aligned_to::<0x10>());
        }

        assert!(0x1010u32.is_aligned_to::<0x10>());
        assert!(0x1010usize.is_aligned_to::<0x10>());

        // Test `word_after`
        for i in 0x1000..0x1004 {
            assert_eq!((i as u32).next_word_boundary(), 0x1004);
            assert_eq!((i as usize).next_word_boundary(), 0x1004);
        }

        // Test `byte_len_in_words`
        for i in 0x5..0x8 {
            assert_eq!((i as u32).byte_len_in_words(), 2);
            assert_eq!((i as usize).byte_len_in_words(), 2);
        }
    }
}
