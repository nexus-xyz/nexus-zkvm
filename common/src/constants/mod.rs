pub const MAX_PUBLIC_INPUT_SIZE: usize = 1 << 31;
pub const MEMORY_TOP: u32 = 0x80400000;
pub const NUM_REGISTERS: u32 = 32;
pub const WORD_SIZE: usize = 4;
pub const WORD_SIZE_HALVED: usize = WORD_SIZE / 2;

// Ensure that the following three constants are consistent with the linker script.
pub const PUBLIC_INPUT_ADDRESS_LOCATION: u32 = NUM_REGISTERS * WORD_SIZE as u32;
pub const PUBLIC_OUTPUT_ADDRESS_LOCATION: u32 = PUBLIC_INPUT_ADDRESS_LOCATION + WORD_SIZE as u32;
pub const ELF_TEXT_START: u32 = PUBLIC_OUTPUT_ADDRESS_LOCATION + WORD_SIZE as u32;

pub const PRECOMPILE_SYMBOL_PREFIX: &str = "PRECOMPILE_";

// TODO: handle built-in custom instructions.
pub const KECCAKF_OPCODE: u8 = 0x5A;
