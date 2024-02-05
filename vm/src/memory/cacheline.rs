//! Memory cache lines

use std::fmt::{Debug, Formatter, Error};

use ark_bn254::Fr as F;
use ark_ff::PrimeField;

use crate::error::*;
use crate::instructions::{Width, Width::*};

use NexusVMError::Misaligned;

/// A CacheLine represents the smallest unit of memory that can be read
/// or written. This size if chosen to be a power of two and convenient
/// for the VM circuits.

#[derive(Copy, Clone)]
pub union CacheLine {
    pub dwords: [u64; 4],
    pub words: [u32; 8],
    pub halfs: [u16; 16],
    pub bytes: [u8; 32],
}

/// The number of bits of address the cacheline holds
pub const CACHE_BITS: usize = 5;

/// The log of the number of `CacheLines` in a complete memory.
pub const CACHE_LOG: usize = 32 - CACHE_BITS;

// This will generate a compile error if CacheLine is not the right size
const _: fn() = || {
    let _ = core::mem::transmute::<CacheLine, [u8; 32]>;
};

impl Default for CacheLine {
    fn default() -> Self {
        CacheLine::from([0; 32])
    }
}

impl From<[u8; 32]> for CacheLine {
    fn from(bytes: [u8; 32]) -> Self {
        CacheLine { bytes }
    }
}

impl From<[u32; 8]> for CacheLine {
    fn from(words: [u32; 8]) -> Self {
        CacheLine { words }
    }
}

impl Debug for CacheLine {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::result::Result<(), Error> {
        unsafe { self.words.fmt(f) }
    }
}

impl PartialEq for CacheLine {
    fn eq(&self, other: &CacheLine) -> bool {
        unsafe { self.dwords == other.dwords }
    }
}

impl CacheLine {
    pub const ZERO: CacheLine = CacheLine { words: [0; 8] };

    /// convert to scalars used in circuits
    pub fn scalars(&self) -> [F; 2] {
        let f1 = unsafe { F::from_le_bytes_mod_order(&self.bytes[0..16]) };
        let f2 = unsafe { F::from_le_bytes_mod_order(&self.bytes[16..32]) };
        [f1, f2]
    }

    // return slice at address. This slice will only extend to the
    // end of the cacheline. (used by instruction parsing)
    //pub(crate) fn bytes(&self, addr: u32) -> &[u8] {
    //    let offset = (addr & 31) as usize;
    //    unsafe { &self.bytes[offset..] }
    //}

    /// perform load according to `width`
    pub fn load(&self, width: Width, addr: u32) -> Result<u32> {
        match width {
            B => self.lb(addr),
            H => self.lh(addr),
            W => self.lw(addr),
            BU => self.lbu(addr),
            HU => self.lhu(addr),
        }
    }

    /// perform store according to `width`
    pub fn store(&mut self, width: Width, addr: u32, val: u32) -> Result<()> {
        match width {
            B | BU => self.sb(addr, val as u8),
            H | HU => self.sh(addr, val as u16),
            W => self.sw(addr, val),
        }
    }

    /// load byte at addr, zero-extended
    pub fn lbu(&self, addr: u32) -> Result<u32> {
        let b = unsafe { self.bytes[(addr & 31) as usize] };
        Ok(b as u32)
    }

    /// load 16-bit value at addr, zero-extended
    pub fn lhu(&self, addr: u32) -> Result<u32> {
        if (addr & 1) != 0 {
            return Err(Misaligned(addr));
        }
        let h = unsafe { self.halfs[((addr >> 1) & 15) as usize] };
        Ok(h as u32)
    }

    /// load 32-bit value at addr
    pub fn lw(&self, addr: u32) -> Result<u32> {
        if (addr & 3) != 0 {
            return Err(Misaligned(addr));
        }
        unsafe { Ok(self.words[((addr >> 2) & 7) as usize]) }
    }

    /// load 64-bit value at addr
    pub fn ldw(&self, addr: u32) -> Result<u64> {
        if (addr & 7) != 0 {
            return Err(Misaligned(addr));
        }
        unsafe { Ok(self.dwords[((addr >> 3) & 3) as usize]) }
    }

    /// load byte at addr, sign-extended
    pub fn lb(&self, addr: u32) -> Result<u32> {
        let val = self.lbu(addr)?;
        if val & 0x80 == 0 {
            Ok(val)
        } else {
            Ok(0xffffff00 | val)
        }
    }

    /// load 16-bit value at addr, sign-extended
    pub fn lh(&self, addr: u32) -> Result<u32> {
        let val = self.lhu(addr)?;
        if val & 0x8000 == 0 {
            Ok(val)
        } else {
            Ok(0xffff0000 | val)
        }
    }

    /// store the lowest byte of val at addr
    pub fn sb(&mut self, addr: u32, val: u8) -> Result<()> {
        unsafe {
            self.bytes[(addr & 31) as usize] = val;
        }
        Ok(())
    }

    /// store the lowest two bytes of val at addr
    pub fn sh(&mut self, addr: u32, val: u16) -> Result<()> {
        if (addr & 1) != 0 {
            return Err(Misaligned(addr));
        }
        unsafe {
            self.halfs[((addr >> 1) & 15) as usize] = val;
        }
        Ok(())
    }

    /// store val at addr
    pub fn sw(&mut self, addr: u32, val: u32) -> Result<()> {
        if (addr & 3) != 0 {
            return Err(Misaligned(addr));
        }
        unsafe {
            self.words[((addr >> 2) & 7) as usize] = val;
        }
        Ok(())
    }

    /// store 64-bit value at addr
    pub fn sdw(&mut self, addr: u32, val: u64) -> Result<()> {
        if (addr & 7) != 0 {
            return Err(Misaligned(addr));
        }
        unsafe {
            self.dwords[((addr >> 3) & 3) as usize] = val;
        }
        Ok(())
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn cache_eq() {
        let a = CacheLine::default();
        let b = CacheLine::default();
        assert_eq!(a, b);

        let b = CacheLine::from([1; 32]);
        assert_ne!(a, b);
    }

    #[test]
    fn cache_le() {
        let mut cache = CacheLine::from([0xff; 32]);
        assert_eq!(cache.lw(0).unwrap(), 0xffffffff);
        assert_eq!(cache.lw(4 * 7).unwrap(), 0xffffffff);

        cache.sw(0, 0x01020304).unwrap();
        assert_eq!(cache.lw(0).unwrap(), 0x01020304);
        assert_eq!(cache.lhu(0).unwrap(), 0x0304);
        assert_eq!(cache.lhu(2).unwrap(), 0x0102);
        assert_eq!(cache.lbu(0).unwrap(), 4);
        assert_eq!(cache.lbu(1).unwrap(), 3);
        assert_eq!(cache.lbu(2).unwrap(), 2);
        assert_eq!(cache.lbu(3).unwrap(), 1);

        cache.sb(0, 4).unwrap();
        cache.sb(1, 5).unwrap();
        cache.sb(2, 6).unwrap();
        cache.sb(3, 7).unwrap();
        assert_eq!(cache.lw(0).unwrap(), 0x07060504);

        cache.sh(0, 0x0a0b).unwrap();
        cache.sh(2, 0x0c0d).unwrap();
        assert_eq!(cache.lw(0).unwrap(), 0x0c0d0a0b);
    }

    #[test]
    fn cache_64() {
        let mut cache = CacheLine::from([0; 32]);
        cache.sw(0, 0x01020304).unwrap();
        cache.sw(4, 0x05060708).unwrap();
        cache.sw(8, 0x01020304).unwrap();
        cache.sw(12, 0x05060708).unwrap();
        assert_eq!(cache.ldw(0).unwrap(), 0x0506070801020304);
        assert_eq!(cache.ldw(8).unwrap(), 0x0506070801020304);
    }

    #[test]
    #[should_panic]
    fn cache_misaligned_half() {
        let cache = CacheLine::default();
        cache.lhu(1).unwrap();
    }

    #[test]
    #[should_panic]
    fn cache_misaligned_word() {
        let cache = CacheLine::default();
        cache.lw(2).unwrap();
    }

    #[test]
    #[should_panic]
    fn cache_misaligned_dword() {
        let cache = CacheLine::default();
        cache.ldw(4).unwrap();
    }
}
