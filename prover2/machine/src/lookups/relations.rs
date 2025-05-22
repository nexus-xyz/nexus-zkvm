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
