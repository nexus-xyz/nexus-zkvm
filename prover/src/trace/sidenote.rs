// This file defines the side note structures for main trace filling

use std::collections::BTreeMap;

use super::{program_trace::ProgramTraces, regs::RegisterMemCheckSideNote};

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Range256SideNote {
    pub(crate) global_multiplicity: u32,
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Range32SideNote {
    pub(crate) global_multiplicity: u32,
}

pub struct ProgramMemCheckSideNote<'a> {
    /// For each Pc, the number of accesses to that Pc so far (None if never)
    pub(crate) last_access_counter: BTreeMap<u32, u32>,
    /// program trace
    pub(crate) program_trace: &'a ProgramTraces,
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Range128SideNote {
    pub(crate) global_multiplicity: u32,
}

pub struct SideNote<'a> {
    pub program_mem_check: ProgramMemCheckSideNote<'a>,
    pub(crate) range32: Range32SideNote,
    pub(crate) range128: Range128SideNote,
    pub(crate) range256: Range256SideNote,
    pub(crate) register_mem_check: RegisterMemCheckSideNote,
}

impl<'a> SideNote<'a> {
    pub fn new(program_traces: &'a ProgramTraces) -> Self {
        Self {
            program_mem_check: ProgramMemCheckSideNote {
                program_trace: program_traces,
                last_access_counter: BTreeMap::new(),
            },
            range32: Range32SideNote::default(),
            range128: Range128SideNote::default(),
            range256: Range256SideNote::default(),
            register_mem_check: RegisterMemCheckSideNote::default(),
        }
    }
}
