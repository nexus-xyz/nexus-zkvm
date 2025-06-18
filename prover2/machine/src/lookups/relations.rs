use nexus_common::constants::WORD_SIZE_HALVED;
use nexus_vm::WORD_SIZE;

// (clk, opcode, pc, a-val, b-val, c-val)
//
// Both clk and pc are half words.
const REL_CPU_TO_INST_LOOKUP_SIZE: usize = WORD_SIZE + 1 + WORD_SIZE * 3;
stwo_prover::relation!(CpuToInstLookupElements, REL_CPU_TO_INST_LOOKUP_SIZE);

// (clk-next, pc-next)
//
// Both clk-next and pc-next are half words.
const REL_CONT_PROG_EXEC_LOOKUP_SIZE: usize = WORD_SIZE;
stwo_prover::relation!(
    ProgramExecutionLookupElements,
    REL_CONT_PROG_EXEC_LOOKUP_SIZE
);

// (reg-addr, reg-val, reg-ts)
//
// Address is a single column, value and timestamps are 4-byte words.
const REL_REG_MEMORY_READ_WRITE_LOOKUP_SIZE: usize = WORD_SIZE * 2 + 1;
stwo_prover::relation!(
    RegisterMemoryLookupElements,
    REL_REG_MEMORY_READ_WRITE_LOOKUP_SIZE
);

// (clk, reg3-val, reg1-val, reg2-val, reg1-accessed, reg2-accessed, reg3-accessed, reg3-write)
//
// clk is a half word, values are 4-byte words, the rest are single-column flags.
const REL_INST_TO_REG_MEMORY_LOOKUP_SIZE: usize = WORD_SIZE_HALVED + 3 * WORD_SIZE + 4;
stwo_prover::relation!(
    InstToRegisterMemoryLookupElements,
    REL_INST_TO_REG_MEMORY_LOOKUP_SIZE
);

// (clk, reg3-addr, reg1-addr, reg2-addr)
//
// clk is a half word, addresses are single columns.
const REL_CPU_TO_REG_MEMORY_LOOKUP_SIZE: usize = WORD_SIZE_HALVED + 3;
stwo_prover::relation!(
    CpuToRegisterMemoryLookupElements,
    REL_CPU_TO_REG_MEMORY_LOOKUP_SIZE
);

// (
//     clk,
//     ram-base-addr,
//     ram1-val-cur, ram2-val-cur, ram3-val-cur, ram4-val-cur,
//     ram1-accessed, ram2-accessed, ram3-accessed, ram4-accessed,
//     ram-write
// )
const REL_INST_TO_RAM_LOOKUP_SIZE: usize = WORD_SIZE_HALVED + WORD_SIZE * 3;
stwo_prover::relation!(InstToRamLookupElements, REL_INST_TO_RAM_LOOKUP_SIZE);

// (ram-base-addr, ram-val-prev, ram-ts)
//
// Timestamp is a half word.
const REL_RAM_READ_WRITE_LOOKUP_SIZE: usize = WORD_SIZE * 2 + WORD_SIZE_HALVED;
stwo_prover::relation!(RamReadWriteLookupElements, REL_RAM_READ_WRITE_LOOKUP_SIZE);
