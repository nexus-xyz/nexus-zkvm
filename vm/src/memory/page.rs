use nexus_common::constants::WORD_SIZE;
use serde::{Deserialize, Serialize};

pub const PAGE_SIZE_LOG2: u8 = 12;
pub const PAGE_SIZE_BYTES: usize = 1 << PAGE_SIZE_LOG2;

const _: () = {
    assert!(PAGE_SIZE_BYTES > WORD_SIZE);
};

/// Calculate the page number for a given address.
pub const fn page_number(address: u32) -> u32 {
    address >> PAGE_SIZE_LOG2
}

/// Calculate the offset of an address within its page.
pub const fn page_offset(address: u32) -> u32 {
    address & ((PAGE_SIZE_BYTES - 1) as u32)
}

/// Calculate the offset of an address within its page, in words. This is the index of the word
/// within the page's buffer.
pub const fn page_word_offset(address: u32) -> usize {
    page_offset(address) as usize / WORD_SIZE
}

/// Calculate the base address of the next page.
pub const fn next_page_base(address: u32) -> u32 {
    (address & !(PAGE_SIZE_BYTES as u32 - 1)) + PAGE_SIZE_BYTES as u32
}

/// A page of memory. In most modern OS's and in RISC-V environs, pages are 4KiB, so we go with that
/// as our default. Future application-specific benchmarks might find a better value for this.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct Page {
    #[serde(with = "serde_arrays")]
    pub(super) data: [u32; PAGE_SIZE_BYTES / WORD_SIZE],
}

impl Page {
    pub fn new() -> Self {
        Self {
            data: [0; PAGE_SIZE_BYTES / WORD_SIZE],
        }
    }

    pub fn get_from_address(&self, address: u32) -> u32 {
        self.data[page_word_offset(address)]
    }

    pub fn set_at_address(&mut self, address: u32, value: u32) {
        self.data[page_word_offset(address)] = value;
    }
}

impl Default for Page {
    fn default() -> Self {
        Self::new()
    }
}
