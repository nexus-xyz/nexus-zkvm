#![deny(missing_docs)]

// RISC-V leaves the meaning of misaligned loads and stores
// up to the Execution Environment Interface (EEI).
// Our expectation is that front-end compilers targeting
// the basic instruction set(s) will not emit misaligned
// loads and stores. Best efforts will be made to accommodate
// misaligned loads and stores, but there is no guarantee
// that such code will execute without exception.

use std::collections::BTreeMap;

/// A simple memory for RV32
///
/// Memory is organized as a collection of 4K pages.
/// A binary tree is used to represent a sparsely
/// populated memory space of 4K pages.

#[derive(Default)]
pub struct Mem {
    tree: BTreeMap<u32, Page>,
}
type Page = [u8; 4096];

impl Mem {
    pub(crate) fn wr_page(&mut self, addr: u32) -> &mut [u8] {
        let page = addr >> 12;
        let offset = (addr & 0xfff) as usize;
        let arr = self.tree.entry(page).or_insert_with(|| [0u8; 4096]);
        &mut arr[offset..]
    }

    pub(crate) fn rd_page(&self, addr: u32) -> &[u8] {
        let page = addr >> 12;
        let offset = (addr & 0xfff) as usize;

        static ZEROS: [u8; 4] = [0; 4];
        match self.tree.get(&page) {
            None => &ZEROS,
            Some(arr) => &arr[offset..],
        }
    }

    /// store the lowest byte of val at addr
    pub fn sb(&mut self, addr: u32, val: u32) {
        self.wr_page(addr)[0] = (val & 0xff) as u8;
    }

    /// store the lowest two bytes of val at addr
    pub fn sh(&mut self, addr: u32, val: u32) {
        let arr = self.wr_page(addr);
        arr[0] = (val & 0xff) as u8;
        arr[1] = ((val >> 8) & 0xff) as u8;
    }

    /// store val at addr
    pub fn sw(&mut self, addr: u32, val: u32) {
        let arr = self.wr_page(addr);
        arr[0] = (val & 0xff) as u8;
        arr[1] = ((val >> 8) & 0xff) as u8;
        arr[2] = ((val >> 16) & 0xff) as u8;
        arr[3] = ((val >> 24) & 0xff) as u8;
    }

    /// load byte at addr, zero-extended
    pub fn lbu(&self, addr: u32) -> u32 {
        self.rd_page(addr)[0] as u32
    }

    /// load 16-bit value at addr, zero-extended
    pub fn lhu(&self, addr: u32) -> u32 {
        let arr = self.rd_page(addr);
        (arr[0] as u32) | (arr[1] as u32) << 8
    }

    /// load 32-bit value at addr
    pub fn lw(&self, addr: u32) -> u32 {
        let arr = self.rd_page(addr);
        (arr[0] as u32) | (arr[1] as u32) << 8 | (arr[2] as u32) << 16 | (arr[3] as u32) << 24
    }

    /// load byte at addr, sign-extended
    pub fn lb(&self, addr: u32) -> u32 {
        let val = self.lbu(addr);
        if val & 0x80 == 0 {
            val
        } else {
            0xffffff00 | val
        }
    }

    /// load 16-bit value at addr, sign-extended
    pub fn lh(&self, addr: u32) -> u32 {
        let val = self.lhu(addr);
        if val & 0x8000 == 0 {
            val
        } else {
            0xffff0000 | val
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_mem() {
        let mut mem = Mem::default();
        mem.sb(0x100, 1);
        mem.sb(0x101, 2);
        mem.sb(0x103, 3);
        mem.sb(0x104, 4);
        mem.sb(0x1000, 1);
        assert_eq!(mem.tree.len(), 2);

        assert_eq!(mem.lbu(0xff), 0);
        assert_eq!(mem.lbu(0x100), 1);
        assert_eq!(mem.lbu(0x101), 2);
        assert_eq!(mem.lbu(0x103), 3);
        assert_eq!(mem.lbu(0x104), 4);
        assert_eq!(mem.lbu(0x105), 0);
        assert_eq!(mem.lbu(0x1000), 1);
        assert_eq!(mem.lbu(0x1001), 0);

        mem.sh(0x100, 0x708);
        assert_eq!(mem.tree.len(), 2);
        assert_eq!(mem.lbu(0x100), 8);
        assert_eq!(mem.lbu(0x101), 7);
        assert_eq!(mem.lhu(0x100), 0x708);
        assert_eq!(mem.lhu(0xff), 0x800);
        assert_eq!(mem.lhu(0x101), 7);
        assert_eq!(mem.lhu(0x200), 0);

        mem.sw(0x200, 0x10203040);
        assert_eq!(mem.tree.len(), 2);
        assert_eq!(mem.lbu(0x200), 0x40);
        assert_eq!(mem.lbu(0x201), 0x30);
        assert_eq!(mem.lbu(0x202), 0x20);
        assert_eq!(mem.lbu(0x203), 0x10);
        assert_eq!(mem.lhu(0x200), 0x3040);
        assert_eq!(mem.lhu(0x202), 0x1020);
        assert_eq!(mem.lw(0x200), 0x10203040);

        mem.sb(0x300, 0x81);
        assert_eq!(mem.lb(0x300), 0xffffff81);

        mem.sh(0x300, 0x8321);
        assert_eq!(mem.lh(0x300), 0xffff8321);
    }
}
