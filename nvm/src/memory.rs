//! Virtual Machine Memory

pub mod cacheline;
pub mod path;
mod trie;

use crate::error::*;
use crate::instructions::Width;

use path::{Digest, Path};
use trie::MerkleTrie;

/// The memory of the machine, implemented by a prefix trie
/// with optional merkle hashing.

#[derive(Default)]
pub struct Memory {
    trie: MerkleTrie,
}

impl Memory {
    /// return the current merkle root
    pub fn root(&self) -> Digest {
        self.trie.root()
    }

    /// read instruction at address
    pub fn read_inst(&self, addr: u32) -> Result<(u64, Path)> {
        let (cl, path) = self.trie.query(addr);
        Ok((cl.ldw(addr)?, path))
    }

    /// write instruction at address
    pub fn write_inst(&mut self, addr: u32, val: u64) -> Result<()> {
        let _ = self.trie.update(addr, |cl| cl.sdw(addr, val))?;
        Ok(())
    }

    /// perform load according to `width`
    pub fn load(&self, width: Width, addr: u32) -> Result<(u32, Path)> {
        let (cl, path) = self.trie.query(addr);
        Ok((cl.load(width, addr)?, path))
    }

    /// perform store according to `width`
    pub fn store(&mut self, width: Width, addr: u32, val: u32) -> Result<Path> {
        self.trie.update(addr, |cl| cl.store(width, addr, val))
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use Width::*;

    #[test]
    fn test_mem() {
        let mut mem = Memory::default();

        // read before write
        assert_eq!(mem.load(W, 0x1000).unwrap().0, 0);

        mem.store(W, 0x1000, 1).unwrap();
        mem.store(B, 0x1100, 1).unwrap();
        mem.store(B, 0x1101, 2).unwrap();
        mem.store(B, 0x1103, 3).unwrap();
        mem.store(B, 0x1104, 4).unwrap();
        mem.store(B, 0x11000, 1).unwrap();

        assert_eq!(mem.load(BU, 0x10ff).unwrap().0, 0);
        assert_eq!(mem.load(BU, 0x1100).unwrap().0, 1);
        assert_eq!(mem.load(BU, 0x1101).unwrap().0, 2);
        assert_eq!(mem.load(BU, 0x1103).unwrap().0, 3);
        assert_eq!(mem.load(BU, 0x1104).unwrap().0, 4);
        assert_eq!(mem.load(BU, 0x1105).unwrap().0, 0);
        assert_eq!(mem.load(BU, 0x11000).unwrap().0, 1);
        assert_eq!(mem.load(BU, 0x11001).unwrap().0, 0);

        mem.store(H, 0x1100, 0x708).unwrap();
        assert_eq!(mem.load(BU, 0x1100).unwrap().0, 8);
        assert_eq!(mem.load(BU, 0x1101).unwrap().0, 7);
        assert_eq!(mem.load(HU, 0x1100).unwrap().0, 0x708);
        assert_eq!(mem.load(HU, 0x1200).unwrap().0, 0);

        mem.store(W, 0x1200, 0x10203040).unwrap();
        assert_eq!(mem.load(BU, 0x1200).unwrap().0, 0x40);
        assert_eq!(mem.load(BU, 0x1201).unwrap().0, 0x30);
        assert_eq!(mem.load(BU, 0x1202).unwrap().0, 0x20);
        assert_eq!(mem.load(BU, 0x1203).unwrap().0, 0x10);
        assert_eq!(mem.load(HU, 0x1200).unwrap().0, 0x3040);
        assert_eq!(mem.load(HU, 0x1202).unwrap().0, 0x1020);
        assert_eq!(mem.load(W, 0x1200).unwrap().0, 0x10203040);

        mem.store(H, 0x1300, 0x81).unwrap();
        assert_eq!(mem.load(B, 0x1300).unwrap().0, 0xffffff81);

        mem.store(H, 0x1300, 0x8321).unwrap();
        assert_eq!(mem.load(H, 0x1300).unwrap().0, 0xffff8321);
    }
}
