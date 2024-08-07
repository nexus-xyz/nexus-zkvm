use jolt_common::rv_trace::JoltDevice;

use super::cacheline::CacheLine;
use super::Memory;
use super::paged::{Paged, UncheckedMemory};
use crate::error::Result;

/// A simple memory combined with a Jolt IO interface.
#[derive(Default)]
pub struct Jolt {
    ram: Paged,
    io: JoltDevice,
}

impl Memory for Jolt {
    // the Jolt prover will generate its own memory proofs, so we don't need to provide them
    type Proof = UncheckedMemory;

    fn query(&self, addr: u32) -> (&CacheLine, Self::Proof) {
        let int_addr = self.io.convert_read_address(addr);

        if self.io.inputs.len() <= int_addr {
            self.ram.query(addr)
        } else {
            let x = self.io.inputs[int_addr];
            (x, UncheckedMemory { data: x.scalars() })
        }
    }

    fn update<F>(&mut self, addr: u32, f: F) -> Result<Self::Proof>
    where
        F: Fn(&mut CacheLine) -> Result<()>,
    {
        if addr == self.io.memory_layout.panic {
            self.io.panic = true;
            return Err();
        }
        let int_addr = self.io.convert_write_address(addr);

        if self.io.outputs.len() <= int_addr {
            return self.ram.update(int_addr + 1, f);
        }

        f(&mut self.io.outputs[int_addr])?;
        Ok(UncheckedMemory { data: self.io.outputs[int_addr].scalars() })
    }

}
