use std::{
    cmp::Ordering,
    collections::BTreeMap,
    ops::{Index, IndexMut},
};

use nexus_common::{constants::WORD_SIZE, error::MemoryError, memory::alignment::Alignable};

use crate::{elf::ElfError, error::VMErrorKind};

#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct MemorySegmentImage {
    image: Vec<u32>,
    base: u32,
}

/// A memory image is a contiguous region of memory that is word-aligned. Each loadable segment
/// produced by the ELF parser can be a `MemorySegmentImage`.
///
/// Invariants:
/// * The base address is word-aligned.
/// * The end address is word-aligned.
/// * The image is contiguous, i.e., data exists for every word-aligned address in [base, end).
impl MemorySegmentImage {
    /// Create a new `MemorySegmentImage` from a BTreeMap mapping addresses to words. This fails
    /// when:
    ///
    /// * The addresses are not word-aligned.
    /// * The addresses are not contiguous.
    ///
    /// Superfluous addresses (entries) are ignored (i.e., non-word-aligned addresses in the middle).
    pub fn try_from_contiguous_btree(image: &BTreeMap<u32, u32>) -> Result<Self, VMErrorKind> {
        if image.is_empty() {
            return Ok(MemorySegmentImage {
                image: vec![],
                base: 0,
            });
        }

        for (address, _) in image.iter() {
            if !address.is_word_aligned() {
                return Err(ElfError::UnalignedVirtualAddress.into());
            }
        }

        let start = *image.first_key_value().unwrap().0;
        let end = (*image.last_key_value().unwrap().0).next_word_boundary();

        let num_words = (end - start) as usize / WORD_SIZE;
        let mut vec = Vec::with_capacity(num_words);

        for address in (start..end).step_by(WORD_SIZE) {
            vec.push(*image.get(&address).unwrap_or(&0));
        }

        Ok(Self {
            image: vec,
            base: start,
        })
    }

    pub fn empty_at(base: u32) -> Self {
        Self {
            image: vec![],
            base,
        }
    }

    /// Extend the memory image by consuming another which immediately follows this one.
    ///
    /// # Errors
    ///
    /// * `VMError::NonContiguousMemory` if the other memory image is not contiguous.
    pub fn extend(&mut self, other: Self) -> Result<(), MemoryError> {
        if self.base + self.len_bytes() as u32 != other.base {
            return Err(MemoryError::UndefinedMemoryRegion);
        }

        self.image.extend(other.image);
        Ok(())
    }

    /// Extend the memory image with a contiguous slice of words.
    pub fn extend_from_word_slice<T: AsRef<[u32]>>(&mut self, slice: T) {
        self.image.extend_from_slice(slice.as_ref());
    }

    /// Append a word to the memory image.
    pub fn push_word(&mut self, word: u32) {
        self.image.push(word);
    }

    /// Set a word at a given address. Returns the previous value.
    pub fn set_word(&mut self, address: u32, value: u32) -> Result<u32, MemoryError> {
        if !address.is_word_aligned() {
            return Err(MemoryError::UnalignedMemoryWrite(address));
        }

        let index = (address - self.base) as usize / WORD_SIZE;
        let old_word = self.image[index];
        self.image[index] = value;

        Ok(old_word)
    }

    pub fn get_word(&self, address: u32) -> Result<Option<u32>, MemoryError> {
        if !address.is_word_aligned() {
            return Err(MemoryError::UnalignedMemoryRead(address));
        }

        if address < self.base
            || address >= self.base + (self.image.len() as u32 * WORD_SIZE as u32)
        {
            return Ok(None);
        }

        let index = (address - self.base) as usize / WORD_SIZE;
        Ok(Some(self.image[index]))
    }

    pub fn get_range_words(&self, start: u32, end: u32) -> Result<&[u32], MemoryError> {
        assert!(start.is_word_aligned());
        assert!(end.is_word_aligned());
        assert!(start < end);
        assert!(start >= self.base);
        assert!(end <= self.base + (self.image.len() as u32 * WORD_SIZE as u32));

        let start_index = (start - self.base) as usize / WORD_SIZE;
        let end_index = (end - self.base) as usize / WORD_SIZE;

        Ok(&self.image[start_index..end_index])
    }

    pub fn len_words(self) -> usize {
        self.image.len()
    }

    pub fn len_bytes(&self) -> usize {
        self.image.len() * WORD_SIZE
    }

    pub fn is_empty(&self) -> bool {
        self.image.is_empty()
    }

    #[cfg(target_endian = "little")]
    pub fn as_byte_slice(&self) -> &[u8] {
        // SAFETY: The image is a contiguous region of memory, and this function is only compiled on
        // little-endian targets. It'd be great to use `as_bytes` here, but that's only available in
        // nightly.
        unsafe { core::slice::from_raw_parts(self.image.as_ptr() as *const u8, self.len_bytes()) }
    }

    pub fn as_word_slice(&self) -> &[u32] {
        &self.image
    }

    /// Guaranteed to be word-aligned.
    pub fn base(&self) -> u32 {
        self.base
    }

    /// Guaranteed to be word-aligned.
    pub fn end(&self) -> u32 {
        self.base + (self.image.len() as u32 * WORD_SIZE as u32)
    }

    pub fn get_byte(&self, address: u32) -> Option<u8> {
        let word = self.image.get((address - self.base) as usize / WORD_SIZE)?;
        let byte = (address % WORD_SIZE as u32) as usize;
        Some((*word >> (byte * 8)) as u8)
    }

    pub fn addressed_iter(&self) -> impl Iterator<Item = (u32, u32)> + '_ {
        self.image
            .iter()
            .enumerate()
            .map(|(i, &v)| (i as u32 * WORD_SIZE as u32 + self.base, v))
    }
}

impl Index<usize> for MemorySegmentImage {
    type Output = u32;

    fn index(&self, index: usize) -> &Self::Output {
        &self.image[index - self.base as usize]
    }
}

impl IndexMut<usize> for MemorySegmentImage {
    fn index_mut(&mut self, index: usize) -> &mut Self::Output {
        &mut self.image[index - self.base as usize]
    }
}

impl Index<u32> for MemorySegmentImage {
    type Output = u32;

    fn index(&self, index: u32) -> &Self::Output {
        &self.image[index as usize - self.base as usize]
    }
}

impl IndexMut<u32> for MemorySegmentImage {
    fn index_mut(&mut self, index: u32) -> &mut Self::Output {
        &mut self.image[index as usize - self.base as usize]
    }
}

impl From<MemorySegmentImage> for Vec<u32> {
    fn from(image: MemorySegmentImage) -> Self {
        image.image
    }
}

impl AsRef<[u32]> for MemorySegmentImage {
    fn as_ref(&self) -> &[u32] {
        &self.image
    }
}

impl AsMut<[u32]> for MemorySegmentImage {
    fn as_mut(&mut self) -> &mut [u32] {
        &mut self.image
    }
}

impl From<MemorySegmentImage> for BTreeMap<u32, u32> {
    fn from(image: MemorySegmentImage) -> Self {
        let mut map = BTreeMap::new();

        map.extend(
            image
                .image
                .iter()
                .enumerate()
                .map(|(i, &word)| (image.base + (i as u32 * WORD_SIZE as u32), word)),
        );

        map
    }
}

/// MemorySegmentImages are equal to storage containers and algorithms if they describe the same
/// memory region. The contents of said memory region are not considered.
impl PartialEq for MemorySegmentImage {
    fn eq(&self, other: &Self) -> bool {
        self.base == other.base && self.image.len() == other.image.len()
    }
}

impl Eq for MemorySegmentImage {}

impl PartialOrd for MemorySegmentImage {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for MemorySegmentImage {
    fn cmp(&self, other: &Self) -> Ordering {
        self.base.cmp(&other.base)
    }
}
