// This file defines the side note structures for main trace filling

use std::collections::BTreeMap;

use nexus_vm::{
    emulator::{InternalView, MemoryInitializationEntry, PublicOutputEntry, View},
    WORD_SIZE,
};

use super::{program_trace::ProgramTracesBuilder, regs::RegisterMemCheckSideNote};

pub(crate) mod keccak;

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
    /// Public output with the exit code.
    pub(crate) public_output: BTreeMap<u32, u8>,
}

impl ReadWriteMemCheckSideNote {
    /// Create a new side note for read write memory checking
    ///
    /// The side note will be used for keeping track of the latest value and access counter for each address, to be put under memory checking.
    /// * `public_output` - addresses and values of public output
    pub fn new(
        init_memory: &[MemoryInitializationEntry],
        public_output: &[PublicOutputEntry],
        exit_code: &[PublicOutputEntry],
    ) -> Self {
        let mut ret: Self = Default::default();
        for MemoryInitializationEntry { address, value } in init_memory {
            let old = ret.last_access.insert(*address, (0, *value));
            assert!(old.is_none(), "Duplicate memory initialization entry");
        }
        let mut public_output: BTreeMap<u32, u8> = public_output
            .iter()
            .map(|PublicOutputEntry { address, value }| (*address, *value))
            .collect();
        for PublicOutputEntry { address, value } in exit_code {
            if let Some(val) = public_output.insert(*address, *value) {
                panic!("exit code overlaps with public output at address={address} value={val}")
            }
        }
        ret.public_output = public_output;
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

/// Side note for Range check {0,.., LEN - 1}
pub struct RangeCheckSideNote<const LEN: usize> {
    /// `multiplicity[i]` is the number how many times value `i` is checked
    pub(crate) multiplicity: [u32; LEN],
}

impl<const LEN: usize> Default for RangeCheckSideNote<LEN> {
    fn default() -> Self {
        Self {
            multiplicity: [0; LEN],
        }
    }
}

/// Side note for bitwise operations. Each multiplicity counter stores (b * 16 + c) as a key.
#[derive(Default)]
pub struct BitOpSideNote {
    pub(crate) multiplicity_and: BTreeMap<u8, u32>,
    pub(crate) multiplicity_or: BTreeMap<u8, u32>,
    pub(crate) multiplicity_xor: BTreeMap<u8, u32>,
}

pub struct SideNote {
    pub program_mem_check: ProgramMemCheckSideNote,
    pub(crate) register_mem_check: RegisterMemCheckSideNote,
    pub(crate) rw_mem_check: ReadWriteMemCheckSideNote,
    pub(crate) bit_op: BitOpSideNote,
    pub(crate) range8: RangeCheckSideNote<{ 1 << 3 }>,
    pub(crate) range16: RangeCheckSideNote<{ 1 << 4 }>,
    pub(crate) range32: RangeCheckSideNote<{ 1 << 5 }>,
    pub(crate) range128: RangeCheckSideNote<{ 1 << 7 }>,
    pub(crate) range256: RangeCheckSideNote<{ 1 << 8 }>,
    pub(crate) keccak: keccak::KeccakSideNote,
}

impl SideNote {
    pub fn new(program_traces: &ProgramTracesBuilder, view: &View) -> Self {
        Self {
            program_mem_check: ProgramMemCheckSideNote {
                last_access_counter: BTreeMap::new(),
                pc_offset: program_traces.pc_offset,
                num_instructions: program_traces.num_instructions,
            },
            register_mem_check: RegisterMemCheckSideNote::default(),
            rw_mem_check: ReadWriteMemCheckSideNote::new(
                &[
                    // preprocessed trace is sensitive to this ordering
                    view.get_ro_initial_memory(),
                    view.get_rw_initial_memory(),
                    view.get_public_input(),
                ]
                .concat(),
                view.get_public_output(),
                view.get_exit_code(),
            ),
            bit_op: BitOpSideNote::default(),
            range8: RangeCheckSideNote::<{ 1 << 3 }>::default(),
            range16: RangeCheckSideNote::<{ 1 << 4 }>::default(),
            range32: RangeCheckSideNote::<{ 1 << 5 }>::default(),
            range128: RangeCheckSideNote::<{ 1 << 7 }>::default(),
            range256: RangeCheckSideNote::<{ 1 << 8 }>::default(),
            keccak: keccak::KeccakSideNote::default(),
        }
    }
}

pub(crate) trait RangeCheckSideNoteGetter<const LEN: usize> {
    fn get_range_check_side_note(&self) -> &RangeCheckSideNote<LEN>;
}

impl RangeCheckSideNoteGetter<{ 1 << 4 }> for SideNote {
    fn get_range_check_side_note(&self) -> &RangeCheckSideNote<{ 1 << 4 }> {
        &self.range16
    }
}

impl RangeCheckSideNoteGetter<{ 1 << 5 }> for SideNote {
    fn get_range_check_side_note(&self) -> &RangeCheckSideNote<{ 1 << 5 }> {
        &self.range32
    }
}

impl RangeCheckSideNoteGetter<{ 1 << 7 }> for SideNote {
    fn get_range_check_side_note(&self) -> &RangeCheckSideNote<{ 1 << 7 }> {
        &self.range128
    }
}

impl RangeCheckSideNoteGetter<{ 1 << 8 }> for SideNote {
    fn get_range_check_side_note(&self) -> &RangeCheckSideNote<{ 1 << 8 }> {
        &self.range256
    }
}
