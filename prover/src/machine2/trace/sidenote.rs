// This file defines the side note structures for main trace filling

use super::regs::RegisterMemCheckSideNote;

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Range256SideNote {
    pub(crate) global_multiplicity: u32,
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Range32SideNote {
    pub(crate) global_multiplicity: u32,
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct SideNote {
    pub(crate) range32: Range32SideNote,
    pub(crate) range256: Range256SideNote,
    pub(crate) register_mem_check: RegisterMemCheckSideNote,
}
