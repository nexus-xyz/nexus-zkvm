use crate::components::{ProgramMemorySideNote, ReadWriteMemorySideNote, RegisterMemorySideNote};

#[derive(Debug, Default)]
pub struct MemorySideNote {
    pub(crate) register_memory: RegisterMemorySideNote,
    pub(crate) read_write_memory: ReadWriteMemorySideNote,
    pub(crate) program_memory: ProgramMemorySideNote,
}
