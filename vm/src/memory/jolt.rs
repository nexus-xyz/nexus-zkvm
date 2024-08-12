use jolt_common::{constants, rv_trace::JoltDevice};

use super::cacheline::CacheLine;
use super::paged::{Paged, UncheckedMemory};
use super::Memory;
use crate::error::Result;

/// A simple memory combined with a Jolt IO interface.
pub struct Jolt {
    ram: Paged,
    io: JoltDevice,
}

impl Default for Jolt {
    fn default() -> Self {
        Self {
            ram: Paged::default(),
            io: JoltDevice::new(
                constants::DEFAULT_MAX_INPUT_SIZE,
                constants::DEFAULT_MAX_OUTPUT_SIZE * 2,
            ),
        }
    }
}

impl Jolt {
    fn convert_read_addr(&self, addr: u64) -> usize {
        (addr - self.io.memory_layout.input_start) as usize
    }

    fn convert_write_addr(&self, addr: u64) -> usize {
        (addr - self.io.memory_layout.output_start) as usize
    }

    fn is_ram(&self, addr: u64) -> bool {
        !self.io.is_input(addr as u64) && !self.io.is_output(addr as u64) && !self.io.is_panic(addr as u64)
    }
}

impl Memory for Jolt {
    // the Jolt prover will generate its own memory proofs, so we don't need to provide them
    type Proof = UncheckedMemory;

    fn query(&self, addr: u32) -> (CacheLine, Self::Proof) {
        if self.is_ram(addr as u64) {
            return self.ram.query(addr);
        }
        let int_addr = self.convert_read_addr(addr as u64);

        if !self.io.is_input(addr as u64) || self.io.inputs.len() <= int_addr {
            let cl = CacheLine::ZERO;
            (cl, UncheckedMemory { data: cl.scalars() })
        } else {
            let st = (int_addr >> 12) + ((int_addr >> 5) & 0x7f);

            let mut sl = [0; 32];
            sl.clone_from_slice(&self.io.outputs[st..st + 32]);

            let cl = CacheLine::from(sl);
            (cl, UncheckedMemory { data: cl.scalars() })
        }
    }

    fn update<F>(&mut self, addr: u32, f: F) -> Result<Self::Proof>
    where
        F: Fn(&mut CacheLine) -> Result<()>,
    {
        if addr as u64 == self.io.memory_layout.panic {
            self.io.panic = true;

            let sl = [0; 32];
            let cl = CacheLine::from(sl);

            return Ok(UncheckedMemory { data: cl.scalars() });
        }

        if !self.is_ram(addr as u64) {
            return self.ram.update(addr, f);
        }

        let int_addr = self.convert_write_addr(addr as u64);

        if self.io.outputs.len() <= int_addr {
            self.io.outputs.resize(int_addr + 1, 0);
        }

        let st = (int_addr >> 12) + ((int_addr >> 5) & 0x7f);

        let mut sl = [0; 32];
        sl.clone_from_slice(&self.io.outputs[st..st + 32]);

        let mut cl = CacheLine::from(sl);
        f(&mut cl)?;

        let mut tail = self.io.outputs.split_off(st + 32);
        self.io.outputs.truncate(st);
        unsafe { self.io.outputs.extend_from_slice(&cl.bytes) };
        self.io.outputs.append(&mut tail);

        Ok(UncheckedMemory {
            data: cl.scalars(),
        })
    }
}
