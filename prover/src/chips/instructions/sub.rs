use stwo_prover::{constraint_framework::EvalAtRow, core::fields::FieldExpOps};

use nexus_vm::{riscv::BuiltinOpcode, WORD_SIZE};

use crate::{
    column::Column::{self, *},
    components::AllLookupElements,
    extensions::ExtensionsConfig,
    trace::{
        eval::{trace_eval, TraceEval},
        sidenote::SideNote,
        BoolWord, ProgramStep, TracesBuilder, Word,
    },
    traits::{ExecuteChip, MachineChip},
};

// Support SUB opcodes.
pub struct SubChip;

pub struct ExecutionResult {
    pub borrow_bits: [bool; 2], // for 16-bit boundaries
    pub diff_bytes: Word,
}

pub fn subtract_with_borrow(x: Word, y: Word) -> (Word, BoolWord) {
    let mut diff_bytes = [0u8; WORD_SIZE];
    let mut borrow_bits: BoolWord = [false; WORD_SIZE];

    // Step 2. Compute the difference and borrow of each limb.
    let (diff, b0) = x[0].overflowing_sub(y[0]);
    borrow_bits[0] = b0;
    diff_bytes[0] = diff;

    // Process the remaining difference bytes
    for i in 1..WORD_SIZE {
        // Subtract the bytes and the previous borrow
        let (diff, b1) = x[i].overflowing_sub(borrow_bits[i - 1] as u8);
        let (diff, b2) = diff.overflowing_sub(y[i]);

        // There can't be 2 borrow in: a - b - borrow, either b1 or b2 is true.
        borrow_bits[i] = b1 || b2;
        diff_bytes[i] = diff;
    }
    (diff_bytes, borrow_bits)
}

impl ExecuteChip for SubChip {
    type ExecutionResult = ExecutionResult;
    fn execute(program_step: &ProgramStep) -> ExecutionResult {
        // Recompute 32-bit result from 8-bit limbs.

        // Step 1. Break the computation to 8-bit limbs.
        let value_b = program_step.get_value_b();
        let (value_c, _) = program_step.get_value_c();

        let (diff_bytes, borrow_bits) = subtract_with_borrow(value_b, value_c);

        let borrow_bits = [borrow_bits[1], borrow_bits[3]];

        ExecutionResult {
            borrow_bits,
            diff_bytes,
        }
    }
}

impl MachineChip for SubChip {
    fn fill_main_trace(
        traces: &mut TracesBuilder,
        row_idx: usize,
        vm_step: &Option<ProgramStep>,
        _side_note: &mut SideNote,
        _config: &ExtensionsConfig,
    ) {
        let vm_step = match vm_step {
            Some(vm_step) => vm_step,
            None => return,
        };
        if !matches!(
            vm_step.step.instruction.opcode.builtin(),
            Some(BuiltinOpcode::SUB)
        ) {
            return;
        }

        let ExecutionResult {
            borrow_bits,
            diff_bytes,
        } = Self::execute(vm_step);

        // Before filling the trace, we check the result of 8-bit limbs is correct.
        assert_eq!(
            diff_bytes,
            vm_step
                .get_result()
                .expect("SUB instruction must have result")
        );

        traces.fill_columns_bytes(row_idx, &diff_bytes, ValueA);
        traces.fill_columns(row_idx, borrow_bits, CarryFlag);
    }

    fn add_constraints<E: EvalAtRow>(
        eval: &mut E,
        trace_eval: &TraceEval<E>,
        _lookup_elements: &AllLookupElements,
        _config: &ExtensionsConfig,
    ) {
        let is_sub = trace_eval!(trace_eval, IsSub);
        let is_sub = is_sub[0].clone();

        // modulus for 8-bit limbs
        let modulus = E::F::from(256u32.into());

        let borrow_flag = trace_eval!(trace_eval, CarryFlag);
        let value_b = trace_eval!(trace_eval, ValueB);
        let value_c = trace_eval!(trace_eval, ValueC);
        let value_a = trace_eval!(trace_eval, ValueA);

        // rdval[0] + rdval[1] * 256 - h1[0] * 2^{16} = rs1val[0] + rs1val[1] * 256 - rs2val[0] - rs2val[1] * 256
        eval.add_constraint(
            is_sub.clone()
                * (value_a[0].clone() + value_a[1].clone() * modulus.clone()
                    - borrow_flag[0].clone() * modulus.clone().pow(2)
                    - (value_b[0].clone() + value_b[1].clone() * modulus.clone()
                        - value_c[0].clone()
                        - value_c[1].clone() * modulus.clone())),
        );

        // rdval[2] + rdval[3] * 256 - h1[1] * 2^{16} = rs1val[2] + rs1val[3] * 256 - rs2val[2] - rs2val[2] * 256 - h1[0]
        eval.add_constraint(
            is_sub.clone()
                * (value_a[2].clone() + value_a[3].clone() * modulus.clone()
                    - borrow_flag[1].clone() * modulus.clone().pow(2)
                    - (value_b[2].clone() + value_b[3].clone() * modulus.clone()
                        - value_c[2].clone()
                        - value_c[3].clone() * modulus.clone()
                        - borrow_flag[0].clone())),
        );
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::{
        chips::{
            cpu::CpuChip, AddChip, DecodingCheckChip, ProgramMemCheckChip, RegisterMemCheckChip,
        },
        test_utils::assert_chip,
        trace::{
            preprocessed::PreprocessedBuilder, program::iter_program_steps,
            program_trace::ProgramTracesBuilder,
        },
    };
    use nexus_vm::{
        emulator::InternalView,
        riscv::{BasicBlock, BuiltinOpcode, Instruction, Opcode},
        trace::k_trace_direct,
    };

    const LOG_SIZE: u32 = PreprocessedBuilder::MIN_LOG_SIZE;

    fn setup_basic_block_ir() -> Vec<BasicBlock> {
        let basic_block = BasicBlock::new(vec![
            // Set x0 = 0 (default constant), x1 = 1, there is no SUBI instruction
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADDI), 1, 0, 1),
            // x2 = x1 - x0
            // x3 = x2 - x1 ... and so on
            Instruction::new_ir(Opcode::from(BuiltinOpcode::SUB), 2, 1, 0),
            Instruction::new_ir(Opcode::from(BuiltinOpcode::SUB), 3, 2, 1),
            Instruction::new_ir(Opcode::from(BuiltinOpcode::SUB), 4, 3, 2),
            Instruction::new_ir(Opcode::from(BuiltinOpcode::SUB), 5, 4, 3),
            Instruction::new_ir(Opcode::from(BuiltinOpcode::SUB), 6, 5, 4),
            Instruction::new_ir(Opcode::from(BuiltinOpcode::SUB), 7, 6, 5),
            Instruction::new_ir(Opcode::from(BuiltinOpcode::SUB), 8, 7, 6),
            Instruction::new_ir(Opcode::from(BuiltinOpcode::SUB), 9, 8, 7),
            Instruction::new_ir(Opcode::from(BuiltinOpcode::SUB), 10, 9, 8),
            Instruction::new_ir(Opcode::from(BuiltinOpcode::SUB), 11, 10, 9),
            Instruction::new_ir(Opcode::from(BuiltinOpcode::SUB), 12, 11, 10),
            Instruction::new_ir(Opcode::from(BuiltinOpcode::SUB), 13, 12, 11),
            Instruction::new_ir(Opcode::from(BuiltinOpcode::SUB), 14, 13, 12),
            Instruction::new_ir(Opcode::from(BuiltinOpcode::SUB), 15, 14, 13),
            Instruction::new_ir(Opcode::from(BuiltinOpcode::SUB), 16, 15, 14),
            Instruction::new_ir(Opcode::from(BuiltinOpcode::SUB), 17, 16, 15),
            Instruction::new_ir(Opcode::from(BuiltinOpcode::SUB), 18, 17, 16),
            Instruction::new_ir(Opcode::from(BuiltinOpcode::SUB), 19, 18, 17),
            Instruction::new_ir(Opcode::from(BuiltinOpcode::SUB), 20, 19, 18),
            Instruction::new_ir(Opcode::from(BuiltinOpcode::SUB), 21, 20, 19),
            Instruction::new_ir(Opcode::from(BuiltinOpcode::SUB), 22, 21, 20),
            Instruction::new_ir(Opcode::from(BuiltinOpcode::SUB), 23, 22, 21),
            Instruction::new_ir(Opcode::from(BuiltinOpcode::SUB), 24, 23, 22),
            Instruction::new_ir(Opcode::from(BuiltinOpcode::SUB), 25, 24, 23),
            Instruction::new_ir(Opcode::from(BuiltinOpcode::SUB), 26, 25, 24),
            Instruction::new_ir(Opcode::from(BuiltinOpcode::SUB), 27, 26, 25),
            Instruction::new_ir(Opcode::from(BuiltinOpcode::SUB), 28, 27, 26),
            Instruction::new_ir(Opcode::from(BuiltinOpcode::SUB), 29, 28, 27),
            Instruction::new_ir(Opcode::from(BuiltinOpcode::SUB), 30, 29, 28),
            Instruction::new_ir(Opcode::from(BuiltinOpcode::SUB), 31, 30, 29),
        ]);
        vec![basic_block]
    }

    #[test]
    fn test_k_trace_constrained_sub_instructions() {
        type Chips = (
            CpuChip,
            DecodingCheckChip,
            AddChip,
            SubChip,
            RegisterMemCheckChip,
            ProgramMemCheckChip,
        );
        let basic_block = setup_basic_block_ir();
        let k = 1;

        // Get traces from VM K-Trace interface
        let (view, vm_traces) = k_trace_direct(&basic_block, k).expect("Failed to create trace");
        let program_info = view.get_program_memory();

        // Trace circuit
        let mut traces = TracesBuilder::new(LOG_SIZE);
        let program_steps = iter_program_steps(&vm_traces, traces.num_rows());
        let program_traces = ProgramTracesBuilder::new_with_empty_memory(LOG_SIZE, program_info);
        let mut side_note = SideNote::new(&program_traces, &view);

        for (row_idx, program_step) in program_steps.enumerate() {
            Chips::fill_main_trace(
                &mut traces,
                row_idx,
                &program_step,
                &mut side_note,
                &ExtensionsConfig::default(),
            );
        }
        assert_chip::<Chips>(traces, Some(program_traces.finalize()));
    }
}
