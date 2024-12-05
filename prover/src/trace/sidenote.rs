// This file defines the side note structures for main trace filling

use std::collections::BTreeMap;

use super::regs::RegisterMemCheckSideNote;

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Range256SideNote {
    pub(crate) global_multiplicity: u32,
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Range32SideNote {
    pub(crate) global_multiplicity: u32,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ProgramMemCheckSideNote {
    /// For each Pc, the number of accesses to that Pc so far (None if never)
    pub(crate) last_access_counter: BTreeMap<u32, u32>,
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Range128SideNote {
    pub(crate) global_multiplicity: u32,
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct SideNote {
    pub(crate) program_mem_check: ProgramMemCheckSideNote,
    pub(crate) range32: Range32SideNote,
    pub(crate) range128: Range128SideNote,
    pub(crate) range256: Range256SideNote,
    pub(crate) register_mem_check: RegisterMemCheckSideNote,
}
