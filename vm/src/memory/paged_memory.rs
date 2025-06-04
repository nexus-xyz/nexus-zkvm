use std::{cmp, collections::BTreeMap};

use nexus_common::{constants::WORD_SIZE, error::MemoryError, memory::alignment::Alignable};
use rangemap::RangeSet;
use rustc_hash::FxHashMap;
use serde::{Deserialize, Serialize};

use crate::error::VMErrorKind;

use super::page::{next_page_base, page_number, page_word_offset, Page, PAGE_SIZE_BYTES};

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct PagedMemory {
    /// Maps page numbers to their backing store.
    segments: FxHashMap<u32, Box<Page>>,

    /// The set of all addresses that have been accessed.
    ranges: RangeSet<u32>,
}

impl PagedMemory {
    /// Create an empty memory image.
    pub fn new() -> Self {
        Self {
            segments: FxHashMap::default(),
            ranges: RangeSet::new(),
        }
    }

    /// Create a memory image from a contiguous BTreeMap of addresses to values.
    pub fn try_from_contiguous_btree(image: &BTreeMap<u32, u32>) -> Result<Self, VMErrorKind> {
        if image.is_empty() {
            return Ok(Self::new());
        }

        let start = *image.first_key_value().unwrap().0;
        let end = *image.last_key_value().unwrap().0 + WORD_SIZE as u32;

        if !start.is_word_aligned() {
            return Err(MemoryError::InvalidMemorySegment.into());
        }

        if !end.is_word_aligned() {
            return Err(MemoryError::InvalidMemorySegment.into());
        }

        let expected_addresses = (start..end).step_by(WORD_SIZE);
        let actual_addresses_values = image.iter();

        let mut memory_image = Self::new();

        for (expected_address, (&actual_address, &value)) in
            expected_addresses.zip(actual_addresses_values)
        {
            if actual_address != expected_address {
                return Err(MemoryError::InvalidMemorySegment.into());
            }

            memory_image.set_word(expected_address, value)?;
        }

        Ok(memory_image)
    }

    pub fn get_word(&self, address: u32) -> Result<Option<u32>, MemoryError> {
        if !address.is_word_aligned() {
            return Err(MemoryError::InvalidMemoryAccess(address, "get_word"));
        }

        if !self.ranges.contains(&address) {
            return Ok(None);
        }

        let page = self.segments.get(&page_number(address)).unwrap();

        Ok(Some(page.get_from_address(address)))
    }

    pub fn set_word(&mut self, address: u32, value: u32) -> Result<Option<u32>, MemoryError> {
        if !address.is_word_aligned() {
            return Err(MemoryError::InvalidMemoryAccess(address, "set_word"));
        }

        // Allow us to freely add WORD_SIZE to the address
        if address >= u32::MAX - WORD_SIZE as u32 {
            return Err(MemoryError::AddressCalculationOverflow);
        }

        let mut old_val = None;

        let page = self
            .segments
            .entry(page_number(address))
            .or_insert_with(|| Box::new(Page::new()));

        if self.ranges.contains(&address) {
            old_val = Some(page.get_from_address(address));
        } else {
            self.ranges.insert(address..address + WORD_SIZE as u32);
        }

        page.set_at_address(address, value);
        Ok(old_val)
    }

    pub fn set_words(&mut self, address: u32, values: &[u32]) -> Result<(), MemoryError> {
        if address
            .checked_add(values.len() as u32 * WORD_SIZE as u32)
            .is_none()
        {
            return Err(MemoryError::AddressCalculationOverflow);
        }

        if values.is_empty() {
            return Ok(());
        }

        let end_address = address + values.len() as u32 * WORD_SIZE as u32;

        let mut current_address = address;
        let mut current_index = 0;

        while current_index < values.len() {
            let page = self
                .segments
                .entry(page_number(current_address))
                .or_default();

            let chunk_end = cmp::min(next_page_base(current_address), end_address);
            let chunk_size_words = (chunk_end - current_address) as usize / WORD_SIZE;

            // Calculate the buffer inside `values` we're copying from.
            let values_start_index = current_index;
            let values_end_index = values_start_index + chunk_size_words;

            // Calculate the buffer inside the page we're writing to.
            let page_buffer_start = page_word_offset(current_address);
            let page_buffer_end = page_buffer_start + chunk_size_words;

            page.data[page_buffer_start..page_buffer_end]
                .copy_from_slice(&values[values_start_index..values_end_index]);

            self.ranges.insert(current_address..chunk_end);

            current_address = chunk_end;
            current_index += chunk_size_words;
        }

        Ok(())
    }

    /// Create an iterator over a range of words in the memory image.
    pub fn range_words_iter(
        &self,
        start: u32,
        end: Option<u32>,
    ) -> Result<impl Iterator<Item = u32> + '_, MemoryError> {
        let range = self
            .ranges
            .get(&start)
            .ok_or(MemoryError::InvalidMemoryAccess(start, "range_words"))?;

        let end = end.unwrap_or(range.end);

        if end > range.end {
            return Err(MemoryError::InvalidMemoryAccess(
                end,
                concat!(file!(), ":", line!(), ":", column!()),
            ));
        }

        Ok(SegmentIter {
            memory_image: self,
            current_page: None,
            current_address: start,
            end,
        })
    }

    pub fn range_bytes(&self, start: u32, end: Option<u32>) -> Result<Vec<u8>, MemoryError> {
        let iter = self.range_words_iter(start, end)?;

        let iter_len = end.unwrap_or_else(|| self.ranges.get(&start).unwrap().end) - start;

        let mut bytes = Vec::with_capacity(iter_len as usize);
        bytes.extend(iter.flat_map(|word| word.to_le_bytes()));

        Ok(bytes)
    }

    pub fn addressed_iter(&self) -> impl Iterator<Item = (u32, u32)> + '_ {
        self.ranges.iter().flat_map(|range| {
            (range.start..range.end)
                .step_by(WORD_SIZE)
                // Safety: this address is in a range, so it is present.
                .map(|addr| (addr, self.get_word(addr).unwrap().unwrap()))
        })
    }

    pub fn occupied_bytes(&self) -> u32 {
        self.ranges
            .iter()
            .map(|range| range.end - range.start)
            .sum()
    }

    pub fn bytes_spanned(&self) -> u32 {
        if self.ranges.is_empty() {
            return 0;
        }

        self.ranges.last().unwrap().end - self.ranges.first().unwrap().start
    }
}

struct SegmentIter<'a> {
    memory_image: &'a PagedMemory,
    current_page: Option<&'a Page>,
    current_address: u32,
    end: u32,
}

impl<'a> Iterator for SegmentIter<'a> {
    type Item = u32;

    fn next(&mut self) -> Option<Self::Item> {
        if self.current_address >= self.end {
            return None;
        }

        if self.current_page.is_none() || (self.current_address & (PAGE_SIZE_BYTES as u32 - 1)) == 0
        {
            self.current_page = self
                .memory_image
                .segments
                .get(&page_number(self.current_address))
                .map(|v| &**v);
        }

        let page = self.current_page.unwrap();

        let value = page.get_from_address(self.current_address);
        self.current_address += WORD_SIZE as u32;

        Some(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::memory::page::{page_number, PAGE_SIZE_BYTES};

    #[test]
    fn test_new_memory_image() {
        let image = PagedMemory::new();
        assert!(image.segments.is_empty());
        assert!(image.ranges.is_empty());
    }

    #[test]
    fn test_get_word_empty_memory() {
        let image = PagedMemory::new();

        assert!(matches!(image.get_word(0), Ok(None)));
        assert!(matches!(image.get_word(0xFFFFFFFC), Ok(None)));
    }

    #[test]
    fn test_set_and_get_word() {
        let mut image = PagedMemory::new();

        // Test setting and getting words at various addresses
        let test_addresses = [
            0x0,                        // Start of memory
            0x4,                        // Basic word-aligned address
            0x12340,                    // Random address in middle
            0xFFFFFFF8,                 // Last writable word in the entire memory
            PAGE_SIZE_BYTES as u32 - 4, // Last word of first page
            PAGE_SIZE_BYTES as u32,     // First word of second page
            PAGE_SIZE_BYTES as u32 + 4, // Just after last word of first page
        ];

        for &addr in &test_addresses {
            let test_value = 0xA5000000 | addr; // Create unique value based on address

            // Set the word and verify it was stored
            assert_eq!(image.set_word(addr, test_value), Ok(None));
            assert_eq!(image.get_word(addr), Ok(Some(test_value)));

            // Update the same word and verify old value is returned
            let new_value = 0xB7000000 | addr;
            assert_eq!(image.set_word(addr, new_value), Ok(Some(test_value)));
            assert_eq!(image.get_word(addr), Ok(Some(new_value)));

            // Verify page was created
            let page_num = page_number(addr);
            assert!(image.segments.contains_key(&page_num));
        }
    }

    #[test]
    fn test_set_words() {
        let mut image = PagedMemory::new();
        let values = [0x11111111, 0x22222222, 0x33333333, 0x44444444];

        // Set multiple words
        assert!(image.set_words(0x2000, &values).is_ok());

        // Verify each word was stored correctly
        assert_eq!(image.get_word(0x2000), Ok(Some(0x11111111)));
        assert_eq!(image.get_word(0x2004), Ok(Some(0x22222222)));
        assert_eq!(image.get_word(0x2008), Ok(Some(0x33333333)));
        assert_eq!(image.get_word(0x200C), Ok(Some(0x44444444)));
    }

    #[test]
    fn test_cross_page_set_words() {
        let mut image = PagedMemory::new();

        // Create a large array that will span multiple pages
        let page_words = PAGE_SIZE_BYTES / WORD_SIZE;
        let mut values = vec![0xDEADBEEF; page_words + 10];
        let values_len = values.len();

        // Put different values at the beginning, middle and end
        values[0] = 0x11111111;
        values[page_words - 1] = 0x22222222;
        values[page_words] = 0x33333333;
        values[values_len - 1] = 0x44444444;

        // Choose an address near the end of a page
        let base_addr = PAGE_SIZE_BYTES as u32 - 4;
        assert!(image.set_words(base_addr, &values).is_ok());

        // Verify values across page boundaries
        assert_eq!(image.get_word(base_addr), Ok(Some(0x11111111)));
        assert_eq!(
            image.get_word(base_addr + (page_words as u32 - 1) * 4),
            Ok(Some(0x22222222))
        );
        assert_eq!(
            image.get_word(base_addr + (page_words as u32) * 4),
            Ok(Some(0x33333333))
        );
        assert_eq!(
            image.get_word(base_addr + (values.len() as u32 - 1) * 4),
            Ok(Some(0x44444444))
        );

        // Verify page allocation
        let first_page = page_number(base_addr);
        let second_page = page_number(base_addr + (page_words as u32) * 4);
        assert!(image.segments.contains_key(&first_page));
        assert!(image.segments.contains_key(&second_page));
    }

    #[test]
    fn test_empty_set_words() {
        let mut image = PagedMemory::new();
        let empty: [u32; 0] = [];

        // Setting empty array should succeed
        assert!(image.set_words(0x3000, &empty).is_ok());

        // Memory should remain unchanged
        assert!(matches!(image.get_word(0x3000), Ok(None)));
        assert!(image.segments.is_empty());
    }

    #[test]
    fn test_address_overflow() {
        let mut image = PagedMemory::new();
        let values = [0x11111111, 0x22222222];

        // Test overflow in set_word
        assert_eq!(
            image.set_word(u32::MAX - 3, 0x12345678),
            Err(MemoryError::AddressCalculationOverflow)
        );

        // Test overflow in set_words
        assert_eq!(
            image.set_words(u32::MAX - 3, &values),
            Err(MemoryError::AddressCalculationOverflow)
        );
    }

    #[test]
    fn test_ranges_tracking() {
        let mut image = PagedMemory::new();

        // Set two separate words
        assert_eq!(image.set_word(0x1000, 0x12345678), Ok(None));
        assert_eq!(image.set_word(0x2000, 0xABCDEF01), Ok(None));

        // Verify ranges are tracked correctly
        assert!(image.ranges.contains(&0x1000));
        assert!(image.ranges.contains(&0x2000));
        assert!(!image.ranges.contains(&0x1004));

        // Update existing word and verify range doesn't change
        let ranges_before = image.ranges.clone();
        assert_eq!(image.set_word(0x1000, 0x87654321), Ok(Some(0x12345678)));
        assert_eq!(image.ranges, ranges_before);
    }
}
