use std::{collections::BTreeMap, ops::Deref};

use stwo::core::fields::m31;

use crate::components::{ProgramMemorySideNote, ReadWriteMemorySideNote, RegisterMemorySideNote};

/// Side note for tracking address access for reads/writes.
#[derive(Debug, Default, Clone)]
pub struct AddressAccessSideNote(BTreeMap<u32, u32>);

impl AddressAccessSideNote {
    pub fn add_access(&mut self, addr: u32) {
        let mult = self.0.entry(addr).or_default();

        assert!(*mult < m31::P - 1);
        *mult += 1;
    }
}

impl Deref for AddressAccessSideNote {
    type Target = BTreeMap<u32, u32>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

#[derive(Debug, Default)]
pub struct MemorySideNote {
    pub(crate) register_memory: RegisterMemorySideNote,
    pub(crate) read_write_memory: ReadWriteMemorySideNote,
    pub(crate) program_memory: ProgramMemorySideNote,
    pub(crate) read_access: AddressAccessSideNote,
    pub(crate) write_access: AddressAccessSideNote,
}
