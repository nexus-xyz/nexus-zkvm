// This file defines the side note structures for main trace filling

use std::collections::BTreeMap;

use super::{program_trace::ProgramTraces, regs::RegisterMemCheckSideNote};

pub struct ProgramMemCheckSideNote<'a> {
    /// For each Pc, the number of accesses to that Pc so far (None if never)
    pub(crate) last_access_counter: BTreeMap<u32, u32>,
    /// program trace
    pub(crate) program_trace: &'a ProgramTraces,
}

/// Side note for committing to the final RW memory content and for computing the final read digest
#[derive(Default)]
pub struct ReadWriteMemCheckSideNote {
    /// u32 is the access counter, u8 is the value of the byte
    pub(crate) last_access: BTreeMap<u32, (u32, u8)>,
}

pub struct SideNote<'a> {
    pub program_mem_check: ProgramMemCheckSideNote<'a>,
    pub(crate) register_mem_check: RegisterMemCheckSideNote,
    pub(crate) rw_mem_check: ReadWriteMemCheckSideNote,
}

impl<'a> SideNote<'a> {
    pub fn new(program_traces: &'a ProgramTraces) -> Self {
        Self {
            program_mem_check: ProgramMemCheckSideNote {
                program_trace: program_traces,
                last_access_counter: BTreeMap::new(),
            },
            register_mem_check: RegisterMemCheckSideNote::default(),
            rw_mem_check: ReadWriteMemCheckSideNote::default(),
        }
    }
}
