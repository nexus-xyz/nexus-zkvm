//! Virtual Machine Memory

use crate::error::Result;
use crate::rv32::{LOP, SOP};

/// A `Memory` implementation is responsible for managing the machine's
/// memory, and providing access to `CacheLine`s. Each implementation
/// has associated commitment values and circuits for checking the
/// commitments to the memory contents. A `Memory` implementation
/// is referred to as a "memory controller".
pub trait Memory: Default {
    /// Query the cacheline at `addr`
    fn query(&self, addr: u32) -> u32;

    /// Updatee the cacheline at `addr` using the function `f`.
    fn update<F>(&mut self, addr: u32, f: F) -> Result<()>
    where
        F: Fn() -> Result<()>;

    /// read instruction at address
    fn read_inst(&self, addr: u32) -> Result<u32>;

    /// write instruction at address
    fn write_inst(&mut self, addr: u32, _val: u32) -> Result<()> {
        self.update(addr, || Ok(()))?;
        Ok(())
    }

    /// perform load according to `lop`
    fn load(&self, _lop: LOP, addr: u32) -> Result<u32> {
        Ok(self.query(addr))
    }

    /// Load n bytes from an address
    fn load_n(&self, address: u32, len: u32) -> Result<Vec<u8>>;

    /// perform store according to `sop`
    fn store(&mut self, _sop: SOP, addr: u32, _val: u32) -> Result<()> {
        self.update(addr, || Ok(()))
    }
}

#[cfg(test)]
mod test {}
