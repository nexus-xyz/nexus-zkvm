// This file defines the side note structures for main trace filling

use std::collections::{BTreeMap, BTreeSet};

use nexus_vm::{
    emulator::{MemoryInitializationEntry, View},
    WORD_SIZE,
};

use super::{program_trace::ProgramTracesBuilder, regs::RegisterMemCheckSideNote};

pub struct ProgramMemCheckSideNote {
    /// For each Pc, the number of accesses to that Pc so far (None if never)
    pub(crate) last_access_counter: BTreeMap<u32, u32>,
    /// Program counter written on the first row. The current assumption is that the program is in contiguous memory starting from [`Self::pc_offset`].
    /// This value is used by the program memory checking when it computes the row index corresponding to a pc value.
    pc_offset: u32,
    num_instructions: usize,
}

/// Side note for committing to the final RW memory content and for computing the final read digest
#[derive(Default)]
pub struct ReadWriteMemCheckSideNote {
    /// u32 is the access counter, u8 is the value of the byte
    pub(crate) last_access: BTreeMap<u32, (u32, u8)>,
    /// Public input values
    pub(crate) public_input: BTreeMap<u32, u8>,
    /// Public output addresses
    pub(crate) public_output_addresses: BTreeSet<u32>,
}

impl ReadWriteMemCheckSideNote {
    /// Create a new side note for read write memory checking
    ///
    /// The side note will be used for keeping track of the latest value and access counter for each address, to be put under memory checking.
    /// * `initial_memory` an iterator of public input entries and ELF RAM, ROM entries given byte-wise.
    /// * `public_output_addresses` an iterator of addresses that are guaranteed to be included in memory checking
    pub fn new<I: Iterator<Item = MemoryInitializationEntry>, I2: Iterator<Item = u32>>(
        initial_memory: I,
        public_output_addresses: I2,
    ) -> Self {
        let mut ret: Self = Default::default();
        for MemoryInitializationEntry { address, value } in initial_memory {
            let old = ret.last_access.insert(address, (0, value));
            assert!(old.is_none(), "Duplicate memory initialization entry");
            let old = ret.public_input.insert(address, value);
            assert!(old.is_none(), "Duplicate memory initialization entry");
        }
        for public_output_address in public_output_addresses {
            let old = ret.public_output_addresses.insert(public_output_address);
            assert!(old, "Duplicate public output address");
        }
        ret
    }
}

impl ProgramMemCheckSideNote {
    /// Finds the row_idx from pc
    pub(crate) fn find_row_idx(&self, pc: u32) -> Option<usize> {
        if pc < self.pc_offset {
            return None;
        }
        let pc = pc - self.pc_offset;
        let pc = pc as usize;
        if pc % WORD_SIZE != 0 {
            return None;
        }
        let row_idx = pc / WORD_SIZE;
        if row_idx >= self.num_instructions {
            return None;
        }
        Some(row_idx)
    }
}

pub struct SideNote {
    pub program_mem_check: ProgramMemCheckSideNote,
    pub(crate) register_mem_check: RegisterMemCheckSideNote,
    pub(crate) rw_mem_check: ReadWriteMemCheckSideNote,
}

impl SideNote {
    pub fn new<I>(
        program_traces: &ProgramTracesBuilder,
        view: &View,
        public_output_addresses: I,
    ) -> Self
    where
        I: IntoIterator<Item = u32>,
    {
        Self {
            program_mem_check: ProgramMemCheckSideNote {
                last_access_counter: BTreeMap::new(),
                pc_offset: program_traces.pc_offset,
                num_instructions: program_traces.num_instructions,
            },
            register_mem_check: RegisterMemCheckSideNote::default(),
            rw_mem_check: ReadWriteMemCheckSideNote::new(
                view.get_initial_memory().copied(),
                public_output_addresses.into_iter(),
            ),
        }
    }
}
