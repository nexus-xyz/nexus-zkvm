//! Virtual Machine Memory

// RISC-V leaves the meaning of misaligned loads and stores up to the Execution Environment
// Interface (EEI).  Our expectation is that front-end compilers targeting the basic instruction
// set(s) will not emit misaligned loads and stores.  The memory circuits depend on this
// assumption, and we check it here to catch any violations early.

#![allow(dead_code)]

pub mod cacheline;
pub mod path;
pub mod trie;

use crate::error::*;
use crate::rv32::*;

//use cacheline::*;
use path::*;
use trie::*;

/// The memory of the machine, implemented by a prefix trie
/// with optional merkle hashing.

#[derive(Default)]
pub struct Memory {
    trie: MerkleTrie,
}

impl Memory {
    /// construct a new memory, with or without merkle hashing
    pub fn new(merkle: bool) -> Self {
        Self { trie: MerkleTrie::new(merkle) }
    }

    /// return merkle root (if any)
    pub fn root(&self) -> Option<Digest> {
        self.trie.root()
    }

    /// return memory at address
    pub(crate) fn read_slice(&self, addr: u32) -> Result<(&[u8], Option<Path>)> {
        let (cl, path) = self.trie.query(addr);
        Ok((cl.bytes(addr), path))
    }

    /// perform load according to `lop`
    pub fn load(&self, lop: LOP, addr: u32) -> Result<(u32, Option<Path>)> {
        let (cl, path) = self.trie.query(addr);
        Ok((cl.load(lop, addr)?, path))
    }

    /// perform store according to `sop`
    pub fn store(&mut self, sop: SOP, addr: u32, val: u32) -> Result<Option<Path>> {
        self.trie.update(addr, |cl| cl.store(sop, addr, val))
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_mem_no_hash() {
        test_mem(Memory::new(false));
    }

    #[test]
    fn test_mem_hash() {
        test_mem(Memory::new(true));
    }

    fn test_mem(mut mem: Memory) {
        // read before write
        assert_eq!(mem.load(LW, 0x1000).unwrap().0, 0);

        mem.store(SW, 0x1000, 1).unwrap();
        mem.store(SB, 0x1100, 1).unwrap();
        mem.store(SB, 0x1101, 2).unwrap();
        mem.store(SB, 0x1103, 3).unwrap();
        mem.store(SB, 0x1104, 4).unwrap();
        mem.store(SB, 0x11000, 1).unwrap();

        assert_eq!(mem.load(LBU, 0x10ff).unwrap().0, 0);
        assert_eq!(mem.load(LBU, 0x1100).unwrap().0, 1);
        assert_eq!(mem.load(LBU, 0x1101).unwrap().0, 2);
        assert_eq!(mem.load(LBU, 0x1103).unwrap().0, 3);
        assert_eq!(mem.load(LBU, 0x1104).unwrap().0, 4);
        assert_eq!(mem.load(LBU, 0x1105).unwrap().0, 0);
        assert_eq!(mem.load(LBU, 0x11000).unwrap().0, 1);
        assert_eq!(mem.load(LBU, 0x11001).unwrap().0, 0);

        mem.store(SH, 0x1100, 0x708).unwrap();
        assert_eq!(mem.load(LBU, 0x1100).unwrap().0, 8);
        assert_eq!(mem.load(LBU, 0x1101).unwrap().0, 7);
        assert_eq!(mem.load(LHU, 0x1100).unwrap().0, 0x708);
        assert_eq!(mem.load(LHU, 0x1200).unwrap().0, 0);

        mem.store(SW, 0x1200, 0x10203040).unwrap();
        assert_eq!(mem.load(LBU, 0x1200).unwrap().0, 0x40);
        assert_eq!(mem.load(LBU, 0x1201).unwrap().0, 0x30);
        assert_eq!(mem.load(LBU, 0x1202).unwrap().0, 0x20);
        assert_eq!(mem.load(LBU, 0x1203).unwrap().0, 0x10);
        assert_eq!(mem.load(LHU, 0x1200).unwrap().0, 0x3040);
        assert_eq!(mem.load(LHU, 0x1202).unwrap().0, 0x1020);
        assert_eq!(mem.load(LW, 0x1200).unwrap().0, 0x10203040);

        mem.store(SH, 0x1300, 0x81).unwrap();
        assert_eq!(mem.load(LB, 0x1300).unwrap().0, 0xffffff81);

        mem.store(SH, 0x1300, 0x8321).unwrap();
        assert_eq!(mem.load(LH, 0x1300).unwrap().0, 0xffff8321);
    }
}
