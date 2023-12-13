#![allow(clippy::box_default)]

// RISC-V leaves the meaning of misaligned loads and stores up to the Execution Environment
// Interface (EEI).  Our expectation is that front-end compilers targeting the basic instruction
// set(s) will not emit misaligned loads and stores.  The memory circuits depend on this
// assumption, and we check it here to catch any violations early.

use std::collections::BTreeMap;

pub use ark_bn254::Fr as F;
use ark_crypto_primitives::{
    sponge::poseidon::{PoseidonConfig, find_poseidon_ark_and_mds},
    crh::poseidon,
    merkle_tree::{Config, IdentityDigestConverter, MerkleTree, Path as MTPath},
};

use crate::error::*;
use VMError::{SegFault, Misaligned};

// This array defines the memory map of the machine.

#[rustfmt::skip]
#[allow(non_upper_case_globals)]
const memory_map: [(u32,u32,u32); 3] = [
    //  virtual        size       phys
    (0x0000_1000, 0x10_0000,         0),
    (0x1000_0000, 0x2f_0000, 0x10_0000),
    (0xfffe_ffff, 0x01_0000, 0x3f_0000),
];

#[allow(non_upper_case_globals)]
const num_cells: usize = 0x10_0000;

#[allow(non_upper_case_globals)]
const cells_exp: usize = num_cells.ilog2() as usize;

/// Convert a virtual address to a physical address.
///
/// This function will fail if the virtual addresss is not mapped (a.k.a. seg-fault).

pub const fn virt2phys(addr: u32) -> Result<u32> {
    let mut i = 0;
    loop {
        if i >= memory_map.len() {
            break;
        }
        let (start, length, phys) = memory_map[i];
        if addr >= start && addr < start + length {
            return Ok(addr - start + phys);
        }
        i += 1
    }
    Err(SegFault(addr))
}

// A Cell represents a location in memory with little-endian layout

#[derive(Copy, Clone)]
pub union Cell {
    words: u32,
    halfs: [u16; 2],
    bytes: [u8; 4],
}

// This will generate a compile error if Cell is not 4 bytes as expected
const _: fn() = || {
    let _ = core::mem::transmute::<Cell, u32>;
};

impl Default for Cell {
    fn default() -> Self {
        Cell::from(0u32)
    }
}

impl From<u32> for Cell {
    fn from(word: u32) -> Self {
        Cell { words: word }
    }
}

impl Cell {
    pub fn bytes(&self) -> &[u8] {
        unsafe { &self.bytes }
    }

    pub fn lbu(&self, addr: u32) -> u8 {
        unsafe { self.bytes[(addr & 0b11) as usize] }
    }

    pub fn lhu(&self, addr: u32) -> Result<u16> {
        if (addr & 1) != 0 {
            return Err(Misaligned(addr));
        }
        unsafe { Ok(self.halfs[((addr >> 1) & 1) as usize]) }
    }

    pub fn lw(&self, addr: u32) -> Result<u32> {
        if (addr & 3) != 0 {
            return Err(Misaligned(addr));
        }
        unsafe { Ok(self.words) }
    }

    pub fn sb(&mut self, addr: u32, val: u8) {
        unsafe {
            self.bytes[(addr & 0b11) as usize] = val;
        }
    }

    pub fn sh(&mut self, addr: u32, val: u16) -> Result<()> {
        if (addr & 1) != 0 {
            return Err(Misaligned(addr));
        }
        unsafe {
            self.halfs[((addr >> 1) & 1) as usize] = val;
        }
        Ok(())
    }

    pub fn sw(&mut self, addr: u32, val: u32) -> Result<()> {
        if (addr & 3) != 0 {
            return Err(Misaligned(addr));
        }
        self.words = val;
        Ok(())
    }
}

/// An interface for Cell containers. All addresses must be 4-byte aligned.

pub trait Cells {
    /// returns a refernce to the cell at address `addr`.
    fn cell(&self, addr: u32) -> &Cell;

    /// returns a mutable refernce to the cell at address `addr`.
    fn cell_mut(&mut self, addr: u32) -> &mut Cell;

    /// returns the current merkle-tree root
    fn root(&self) -> Option<F> {
        None
    }

    /// returns the merkle-path for an address if available
    fn path(&self, _addr: u32) -> Option<Path> {
        None
    }

    /// returns both the root and a path
    fn root_path(&self, addr: u32) -> Option<(F, Path)> {
        if let (Some(r), Some(p)) = (self.root(), self.path(addr)) {
            Some((r, p))
        } else {
            None
        }
    }
}

/// The memory of the machine, implemented by a Cell container.

pub struct Memory(pub(crate) Box<dyn Cells>);

impl Default for Memory {
    fn default() -> Self {
        Memory::new(false)
    }
}

impl Memory {
    pub fn new(merkle: bool) -> Self {
        let cells: Box<dyn Cells> = if merkle {
            Box::new(MerkleMem::default())
        } else {
            Box::new(ArrayMem::default())
        };
        Memory(cells)
    }

    /// return cell at address (must be 32-bit aligned)
    pub fn read_cell(&self, addr: u32) -> Result<&Cell> {
        let addr = virt2phys(addr)?;
        Ok(self.0.cell(addr))
    }

    /// store the lowest byte of val at addr
    pub fn sb(&mut self, addr: u32, val: u32) -> Result<()> {
        let addr = virt2phys(addr)?;
        self.0.cell_mut(addr).sb(addr, val as u8);
        Ok(())
    }

    /// store the lowest two bytes of val at addr
    pub fn sh(&mut self, addr: u32, val: u32) -> Result<()> {
        let addr = virt2phys(addr)?;
        self.0.cell_mut(addr).sh(addr, val as u16)
    }

    /// store val at addr
    pub fn sw(&mut self, addr: u32, val: u32) -> Result<()> {
        let addr = virt2phys(addr)?;
        self.0.cell_mut(addr).sw(addr, val)
    }

    /// load byte at addr, zero-extended
    pub fn lbu(&self, addr: u32) -> Result<u32> {
        let addr = virt2phys(addr)?;
        Ok(self.0.cell(addr).lbu(addr) as u32)
    }

    /// load 16-bit value at addr, zero-extended
    pub fn lhu(&self, addr: u32) -> Result<u32> {
        let addr = virt2phys(addr)?;
        Ok(self.0.cell(addr).lhu(addr)? as u32)
    }

    /// load 32-bit value at addr
    pub fn lw(&self, addr: u32) -> Result<u32> {
        let addr = virt2phys(addr)?;
        self.0.cell(addr).lw(addr)
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
}

/// A paged memory suitable for large address spaces
///
/// A binary tree is used to represent a sparsely
/// populated memory space of 4K pages.

#[derive(Default)]
pub struct PagedMem {
    tree: BTreeMap<u32, Page>,
    zero: Cell,
}
type Page = [Cell; 1024];

impl Cells for PagedMem {
    fn cell(&self, addr: u32) -> &Cell {
        let page = addr >> 12;
        let offset = ((addr & 0xfff) >> 2) as usize;
        match self.tree.get(&page) {
            Some(cells) => &cells[offset],
            None => &self.zero,
        }
    }

    fn cell_mut(&mut self, addr: u32) -> &mut Cell {
        let page = addr >> 12;
        let offset = ((addr & 0xfff) >> 2) as usize;
        let cells = self
            .tree
            .entry(page)
            .or_insert_with(|| [Cell::default(); 1024]);
        &mut cells[offset]
    }
}

/// A linear array memory suitable for small address spaces

pub struct ArrayMem {
    array: Vec<Cell>,
}

impl Default for ArrayMem {
    fn default() -> Self {
        Self { array: vec![Cell::default(); num_cells] }
    }
}

impl Cells for ArrayMem {
    fn cell(&self, addr: u32) -> &Cell {
        let offset = (addr >> 2) as usize;
        &self.array[offset]
    }

    fn cell_mut(&mut self, addr: u32) -> &mut Cell {
        let offset = (addr >> 2) as usize;
        &mut self.array[offset]
    }
}

/// A Merkle-Tree memory suitable for proof generation

pub struct MerkleMem {
    pub array: ArrayMem,
    pub config: PoseidonConfig<F>,
    pub tree: MerkleTree<MTConfig>,
}

pub struct MTConfig;

impl Config for MTConfig {
    type Leaf = [F];
    type LeafDigest = F;
    type LeafInnerDigestConverter = IdentityDigestConverter<F>;
    type InnerDigest = F;
    type LeafHash = poseidon::CRH<F>;
    type TwoToOneHash = poseidon::TwoToOneCRH<F>;
}

pub type Path = MTPath<MTConfig>;

const FULL_ROUNDS: usize = 8;
const PARTIAL_ROUNDS: usize = 57;
const ALPHA: u64 = 5;
const RATE: usize = 2;
const CAPACITY: usize = 1;
const MODULUS_BITS: u64 = 254;

pub fn poseidon_config() -> PoseidonConfig<F> {
    let (ark, mds) = find_poseidon_ark_and_mds::<F>(
        MODULUS_BITS,
        RATE,
        FULL_ROUNDS as u64,
        PARTIAL_ROUNDS as u64,
        0,
    );
    PoseidonConfig {
        full_rounds: FULL_ROUNDS,
        partial_rounds: PARTIAL_ROUNDS,
        alpha: ALPHA,
        ark,
        mds,
        rate: RATE,
        capacity: CAPACITY,
    }
}

impl Default for MerkleMem {
    fn default() -> Self {
        let config = poseidon_config();
        let tree = MerkleTree::<MTConfig>::blank(&config, &config, cells_exp + 1).unwrap();
        Self { array: ArrayMem::default(), config, tree }
    }
}

impl Cells for MerkleMem {
    fn cell(&self, addr: u32) -> &Cell {
        self.array.cell(addr)
    }

    fn cell_mut(&mut self, addr: u32) -> &mut Cell {
        let cell = self.array.cell_mut(addr);
        // errors are handled by Memory struct impl
        if let Ok(v) = cell.lw(addr) {
            let addr = (addr >> 2) as usize;
            let _ = self.tree.update(addr, &[F::from(v)]);
        }
        cell
    }

    fn root(&self) -> Option<F> {
        Some(self.tree.root())
    }

    fn path(&self, addr: u32) -> Option<Path> {
        self.tree.generate_proof(addr as usize).ok()
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_le() {
        let mut cell = Cell::from(0x01020304);
        assert_eq!(cell.lw(0).unwrap(), 0x01020304);
        assert_eq!(cell.lhu(0).unwrap(), 0x0304);
        assert_eq!(cell.lhu(2).unwrap(), 0x0102);
        assert_eq!(cell.lbu(0), 4);
        assert_eq!(cell.lbu(1), 3);
        assert_eq!(cell.lbu(2), 2);
        assert_eq!(cell.lbu(3), 1);

        cell.sb(0, 4);
        cell.sb(1, 5);
        cell.sb(2, 6);
        cell.sb(3, 7);
        assert_eq!(cell.lw(0).unwrap(), 0x07060504);

        cell.sh(0, 0x0a0b).unwrap();
        cell.sh(2, 0x0c0d).unwrap();
        assert_eq!(cell.lw(0).unwrap(), 0x0c0d0a0b);
    }

    fn test_mem(mut mem: Memory) {
        // read before write
        mem.lw(0x1000).unwrap();
        mem.sw(0x1000, 1).unwrap();

        mem.sb(0x1100, 1).unwrap();
        mem.sb(0x1101, 2).unwrap();
        mem.sb(0x1103, 3).unwrap();
        mem.sb(0x1104, 4).unwrap();
        mem.sb(0x11000, 1).unwrap();

        assert_eq!(mem.lbu(0x10ff).unwrap(), 0);
        assert_eq!(mem.lbu(0x1100).unwrap(), 1);
        assert_eq!(mem.lbu(0x1101).unwrap(), 2);
        assert_eq!(mem.lbu(0x1103).unwrap(), 3);
        assert_eq!(mem.lbu(0x1104).unwrap(), 4);
        assert_eq!(mem.lbu(0x1105).unwrap(), 0);
        assert_eq!(mem.lbu(0x11000).unwrap(), 1);
        assert_eq!(mem.lbu(0x11001).unwrap(), 0);

        mem.sh(0x1100, 0x708).unwrap();
        assert_eq!(mem.lbu(0x1100).unwrap(), 8);
        assert_eq!(mem.lbu(0x1101).unwrap(), 7);
        assert_eq!(mem.lhu(0x1100).unwrap(), 0x708);
        assert_eq!(mem.lhu(0x1200).unwrap(), 0);

        mem.sw(0x1200, 0x10203040).unwrap();
        assert_eq!(mem.lbu(0x1200).unwrap(), 0x40);
        assert_eq!(mem.lbu(0x1201).unwrap(), 0x30);
        assert_eq!(mem.lbu(0x1202).unwrap(), 0x20);
        assert_eq!(mem.lbu(0x1203).unwrap(), 0x10);
        assert_eq!(mem.lhu(0x1200).unwrap(), 0x3040);
        assert_eq!(mem.lhu(0x1202).unwrap(), 0x1020);
        assert_eq!(mem.lw(0x1200).unwrap(), 0x10203040);

        mem.sb(0x1300, 0x81).unwrap();
        assert_eq!(mem.lb(0x1300).unwrap(), 0xffffff81);

        mem.sh(0x1300, 0x8321).unwrap();
        assert_eq!(mem.lh(0x1300).unwrap(), 0xffff8321);

        // check memory map
        for (start, size, _) in memory_map {
            mem.sw(start, 1).unwrap();
            mem.sh(start, 1).unwrap();
            mem.sb(start, 1).unwrap();
            mem.sw(start + size - 4, 1).unwrap();
            mem.sh(start + size - 2, 1).unwrap();
            mem.sb(start + size - 1, 1).unwrap();

            mem.lw(start).unwrap();
            mem.lh(start).unwrap();
            mem.lb(start).unwrap();
            mem.lw(start + size - 4).unwrap();
            mem.lh(start + size - 2).unwrap();
            mem.lb(start + size - 1).unwrap();
        }
    }

    #[test]
    fn test_memory_paged() {
        test_mem(Memory(Box::new(PagedMem::default())));
    }

    #[test]
    fn test_memory_array() {
        test_mem(Memory(Box::new(ArrayMem::default())));
    }

    #[test]
    #[ignore]
    fn test_memory_merkle() {
        test_mem(Memory(Box::new(MerkleMem::default())));
    }
}
