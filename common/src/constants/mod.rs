pub const ELF_TEXT_START: u32 = 0x1000;
pub const MEMORY_TOP: u32 = 0x80400000;
pub const MEMORY_GAP: u32 = 0x1000;
pub const NUM_REGISTERS: u32 = 32;
pub const WORD_SIZE: usize = 4;
pub const WORD_SIZE_HALVED: usize = WORD_SIZE / 2;
pub const PRECOMPILE_SYMBOL_PREFIX: &str = "PRECOMPILE_";

// TODO: handle built-in custom instructions.
pub const KECCAKF_OPCODE: u8 = 0x5A;
