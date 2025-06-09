use crate::extensions::ExtensionsConfig;
use crate::{
    column::Column::{self, *},
    trace::eval::trace_eval,
    traits::MachineChip,
};
use nexus_vm::riscv::BuiltinOpcode;
use stwo_prover::core::fields::m31::BaseField;

use super::gadget::constraint_gadget_mul_product;
use super::nexani::mull_limb;

pub struct MulhuChip;

impl MachineChip for MulhuChip {
    fn fill_main_trace(
        traces: &mut crate::trace::TracesBuilder,
        row_idx: usize,
        vm_step: &Option<crate::trace::ProgramStep>, // None for padding
        _side_note: &mut crate::trace::sidenote::SideNote,
        _config: &ExtensionsConfig,
    ) {
        let vm_step = match vm_step {
            Some(vm_step) => vm_step,
            None => return, // padding
        };

        if !matches!(
            vm_step.step.instruction.opcode.builtin(),
            Some(BuiltinOpcode::MULHU)
        ) {
            return;
        }

        let value_b = vm_step.get_value_b();
        let value_c = vm_step.get_value_c().0;

        // MUL main constraint need these intermediate values
        let mul_result = mull_limb(u32::from_le_bytes(value_b), u32::from_le_bytes(value_c));

        // Fill in the intermediate values into traces
        // MUL carry_1 for lower half, in {0, 1, 2, 3}
        traces.fill_columns(row_idx, mul_result.carry_l[1], MulCarry1_0);
        traces.fill_columns(row_idx, mul_result.carry_l[2], MulCarry1_1);

        traces.fill_columns(row_idx, mul_result.carry_h[0], MulCarry2_0);
        traces.fill_columns(row_idx, mul_result.carry_h[1], MulCarry2_1);
        traces.fill_columns(row_idx, mul_result.carry_h[2], MulCarry3);

        // MUL P3', P3'' and P5 in range 0..=2^16 - 1
        traces.fill_columns(row_idx, mul_result.p3_prime, MulP3Prime);
        traces.fill_columns(row_idx, mul_result.p3_prime_prime, MulP3PrimePrime);
        traces.fill_columns(row_idx, mul_result.p5, MulP5);

        // MUL Carry of P3', P3'' and P5 in {0, 1}
        traces.fill_columns(row_idx, mul_result.c3_prime, MulC3Prime);
        traces.fill_columns(row_idx, mul_result.c3_prime_prime, MulC3PrimePrime);
        traces.fill_columns(row_idx, mul_result.c5, MulC5);

        // The output of the multiplication
        traces.fill_columns(
            row_idx,
            vm_step.get_result().expect("MULH must have result"),
            ValueA,
        );
    }

    fn add_constraints<E: stwo_prover::constraint_framework::EvalAtRow>(
        eval: &mut E,
        trace_eval: &crate::trace::eval::TraceEval<E>,
        _lookup_elements: &crate::components::AllLookupElements,
        _config: &ExtensionsConfig,
    ) {
        let [is_mulhu] = trace_eval!(trace_eval, IsMulhu);

        let value_a = trace_eval!(trace_eval, ValueA);
        let value_b = trace_eval!(trace_eval, ValueB);
        let value_c = trace_eval!(trace_eval, ValueC);

        let p3_prime = trace_eval!(trace_eval, MulP3Prime);
        let p3_prime_prime = trace_eval!(trace_eval, MulP3PrimePrime);
        let p5 = trace_eval!(trace_eval, MulP5);
        let [c3_prime] = trace_eval!(trace_eval, MulC3Prime);
        let [c3_prime_prime] = trace_eval!(trace_eval, MulC3PrimePrime);
        let [c5] = trace_eval!(trace_eval, MulC5);

        let z_0 = value_b[0].clone() * value_c[0].clone();
        let z_1 = value_b[1].clone() * value_c[1].clone();
        let z_2 = value_b[2].clone() * value_c[2].clone();
        let z_3 = value_b[3].clone() * value_c[3].clone();

        // is_mulhu * (P3_prime + c3_prime * 2^16 - (|b|_0 + |b|_3) * (|c|_0 + |c|_3) + z_0 + z_3)
        constraint_gadget_mul_product(
            eval,
            is_mulhu.clone(),
            p3_prime.clone(),
            c3_prime.clone(),
            value_b[0].clone(),
            value_b[3].clone(),
            value_c[0].clone(),
            value_c[3].clone(),
            z_0.clone(),
            z_3.clone(),
        );

        // is_mulhu * (P3_prime_prime + c3_prime_prime * 2^16 - (|b|_1 + |b|_2) * (|c|_1 + |c|_2) + z_1 + z_2)
        constraint_gadget_mul_product(
            eval,
            is_mulhu.clone(),
            p3_prime_prime.clone(),
            c3_prime_prime.clone(),
            value_b[1].clone(),
            value_b[2].clone(),
            value_c[1].clone(),
            value_c[2].clone(),
            z_1.clone(),
            z_2.clone(),
        );

        // is_mulhu * (P5 + c5 * 2^16 - (|b|_2 + |b|_3) * (|c|_2 + |c|_3) + z_2 + z_3)
        constraint_gadget_mul_product(
            eval,
            is_mulhu.clone(),
            p5.clone(),
            c5.clone(),
            value_b[2].clone(),
            value_b[3].clone(),
            value_c[2].clone(),
            value_c[3].clone(),
            z_2.clone(),
            z_3.clone(),
        );

        let [mul_carry_1_0] = trace_eval!(trace_eval, MulCarry1_0);
        let [mul_carry_1_1] = trace_eval!(trace_eval, MulCarry1_1);
        let [mul_carry_2_0] = trace_eval!(trace_eval, MulCarry2_0);
        let [mul_carry_2_1] = trace_eval!(trace_eval, MulCarry2_1);
        let [mul_carry_3] = trace_eval!(trace_eval, MulCarry3);

        // is_mulhu * (z_2 + P3_prime_h + P3_prime_prime_h + (b_1 + b_3) * (c_1 + c_3) - z_1 - z_3 +
        // (P5_l + c3_prime_prime + c3_prime) * 2^8 + carry1 - carry2 * 2^16 - |a|_0 - |a|_1 * 2^8)
        eval.add_constraint(
            is_mulhu.clone()
                * (z_2.clone()
                    + p3_prime[1].clone()
                    + p3_prime_prime[1].clone()
                    + (value_b[1].clone() + value_b[3].clone())
                        * (value_c[1].clone() + value_c[3].clone())
                    - z_1.clone()
                    - z_3.clone()
                    + (p5[0].clone() + c3_prime_prime.clone() + c3_prime.clone())
                        * BaseField::from(1 << 8)
                    + mul_carry_1_0.clone()
                    + mul_carry_1_1.clone() * BaseField::from(1 << 1)
                    - mul_carry_2_0.clone() * BaseField::from(1 << 16)
                    - mul_carry_2_1.clone() * BaseField::from(1 << 17)
                    - value_a[0].clone()
                    - value_a[1].clone() * BaseField::from(1 << 8)),
        );

        // is_mulhu * (z_3 + P5_h + c5 * 2^8 + carry2 - carry3 * 2^16 - |a|_2 - |a|_3 * 2^8)
        eval.add_constraint(
            is_mulhu.clone()
                * (z_3.clone()
                    + p5[1].clone()
                    + c5.clone() * BaseField::from(1 << 8)
                    + mul_carry_2_0
                    + mul_carry_2_1 * BaseField::from(1 << 1)
                    - mul_carry_3 * BaseField::from(1 << 16)
                    - value_a[2].clone()
                    - value_a[3].clone() * BaseField::from(1 << 8)),
        );
    }
}

#[cfg(test)]
mod test {
    use crate::{
        chips::{
            AddChip, CpuChip, DecodingCheckChip, LuiChip, MulhuChip, ProgramMemCheckChip,
            RangeCheckChip, RegisterMemCheckChip, SrlChip, SubChip,
        },
        test_utils::assert_chip,
        trace::{
            program::iter_program_steps, program_trace::ProgramTracesBuilder, sidenote::SideNote,
            PreprocessedTraces, TracesBuilder,
        },
    };

    use super::*;
    use nexus_vm::{
        emulator::InternalView,
        riscv::{BasicBlock, BuiltinOpcode, Instruction, Opcode},
        trace::k_trace_direct,
    };

    const LOG_SIZE: u32 = PreprocessedTraces::MIN_LOG_SIZE;

    fn setup_basic_block_ir() -> Vec<BasicBlock> {
        let basic_block = BasicBlock::new(vec![
            // Setup registers with various unsigned values
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADDI), 30, 0, 1), // x30 = 1
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADDI), 1, 0, 5), // x1 = 5 (small positive)
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADDI), 2, 0, 7), // x2 = 7 (small positive)
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADDI), 3, 0, 0), // x3 = 0
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADDI), 4, 0, 1), // x4 = 1
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADDI), 5, 0, 2), // x5 = 2
            Instruction::new_ir(Opcode::from(BuiltinOpcode::LUI), 6, 0, 0xFFFFF), // x6 = 0xFFFFF000
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADDI), 6, 6, 0xFFF), // x6 = 0xFFFFFFFF (max u32)
            Instruction::new_ir(Opcode::from(BuiltinOpcode::LUI), 7, 0, 0x80000), // x7 = 0x80000000 (msb set)
            Instruction::new_ir(Opcode::from(BuiltinOpcode::LUI), 8, 0, 1),       // x8 = 0x10000
            Instruction::new_ir(Opcode::from(BuiltinOpcode::SUB), 9, 0, 30), // x9 = 0xFFFFFFFF (max u32, alt)
            Instruction::new_ir(Opcode::from(BuiltinOpcode::SRLI), 9, 9, 16), // x9 = 0x0000FFFF
            // --- MULHU Tests ---
            // Small positive * Small positive (result fits in lower 32 bits)
            // 5 * 7 = 35 = 0x23. Upper bits = 0.
            Instruction::new_ir(Opcode::from(BuiltinOpcode::MULHU), 10, 1, 2), // x10 = mulhu(5, 7) = 0
            // Max u32 * Max u32
            // 0xFFFFFFFF * 0xFFFFFFFF = 0xFFFFFFFE00000001. Upper bits = 0xFFFFFFFE.
            Instruction::new_ir(Opcode::from(BuiltinOpcode::MULHU), 11, 6, 6), // x11 = mulhu(max_u32, max_u32) = 0xFFFFFFFE
            // Max u32 * Small positive
            // 0xFFFFFFFF * 7 = 0x6FFFFFF9. Upper bits = 6.
            Instruction::new_ir(Opcode::from(BuiltinOpcode::MULHU), 12, 6, 2), // x12 = mulhu(max_u32, 7) = 6
            // Small positive * Max u32
            // 5 * 0xFFFFFFFF = 0x4FFFFFFB. Upper bits = 4.
            Instruction::new_ir(Opcode::from(BuiltinOpcode::MULHU), 13, 1, 6), // x13 = mulhu(5, max_u32) = 4
            // Multiplication by zero
            Instruction::new_ir(Opcode::from(BuiltinOpcode::MULHU), 14, 1, 3), // x14 = mulhu(5, 0) = 0
            Instruction::new_ir(Opcode::from(BuiltinOpcode::MULHU), 15, 6, 3), // x15 = mulhu(max_u32, 0) = 0
            Instruction::new_ir(Opcode::from(BuiltinOpcode::MULHU), 16, 3, 3), // x16 = mulhu(0, 0) = 0
            // Multiplication by one
            Instruction::new_ir(Opcode::from(BuiltinOpcode::MULHU), 17, 6, 4), // x17 = mulhu(max_u32, 1) = 0
            Instruction::new_ir(Opcode::from(BuiltinOpcode::MULHU), 18, 1, 4), // x18 = mulhu(5, 1) = 0
            // MSB set * 2 (causes carry into upper half)
            // 0x80000000 * 2 = 0x100000000. Upper bits = 1.
            Instruction::new_ir(Opcode::from(BuiltinOpcode::MULHU), 19, 7, 5), // x19 = mulhu(0x80000000, 2) = 1
            // MSB set * MSB set
            // 0x80000000 * 0x80000000 = 0x4000000000000000. Upper bits = 0x40000000.
            Instruction::new_ir(Opcode::from(BuiltinOpcode::MULHU), 20, 7, 7), // x20 = mulhu(0x80000000, 0x80000000) = 0x40000000
            // --- Additional Edge Cases ---
            // 0x10000 * 0x10000 (boundary case for lower/upper half)
            // 0x10000 * 0x10000 = 0x100000000. Upper bits = 1.
            Instruction::new_ir(Opcode::from(BuiltinOpcode::MULHU), 21, 8, 8), // x21 = mulhu(0x10000, 0x10000) = 1
            // 0x0000FFFF * 0x0000FFFF (max 16-bit * max 16-bit)
            // 0xFFFF * 0xFFFF = 0xFFFE0001. Upper bits = 0.
            Instruction::new_ir(Opcode::from(BuiltinOpcode::MULHU), 22, 9, 9), // x22 = mulhu(0xFFFF, 0xFFFF) = 0
            // 0x10000 * 0xFFFF (boundary * near boundary)
            // 0x10000 * 0xFFFF = 0xFFFF0000. Upper bits = 0.
            Instruction::new_ir(Opcode::from(BuiltinOpcode::MULHU), 23, 8, 9), // x23 = mulhu(0x10000, 0xFFFF) = 0
            // MSB set * 1
            // 0x80000000 * 1 = 0x80000000. Upper bits = 0.
            Instruction::new_ir(Opcode::from(BuiltinOpcode::MULHU), 24, 7, 4), // x24 = mulhu(0x80000000, 1) = 0
            // 1 * MSB set
            // 1 * 0x80000000 = 0x80000000. Upper bits = 0.
            Instruction::new_ir(Opcode::from(BuiltinOpcode::MULHU), 25, 4, 7), // x25 = mulhu(1, 0x80000000) = 0
            // Max u32 * Max u32 (using alternative register for max u32)
            // 0xFFFFFFFF * 0xFFFFFFFF = 0xFFFFFFFE00000001. Upper bits = 0xFFFFFFFE.
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADDI), 26, 0, 30), // x26 = 0xFFFFFFFF
            Instruction::new_ir(Opcode::from(BuiltinOpcode::MULHU), 27, 6, 26), // x27 = mulhu(max_u32, max_u32) = 0xFFFFFFFE
        ]);
        vec![basic_block]
    }

    #[test]
    fn test_k_trace_constrained_mulhu_instructions() {
        type Chips = (
            CpuChip,
            DecodingCheckChip,
            AddChip,
            SubChip,
            MulhuChip,
            LuiChip,
            SrlChip,
            RegisterMemCheckChip,
            ProgramMemCheckChip,
            RangeCheckChip,
        );
        let basic_block = setup_basic_block_ir();
        let k = 1;

        // Get traces from VM K-Trace interface
        let (view, vm_traces) = k_trace_direct(&basic_block, k).expect("Failed to create trace");
        let program_info = view.get_program_memory();

        // Trace circuit
        let mut traces = TracesBuilder::new(LOG_SIZE);
        let program_traces = ProgramTracesBuilder::new_with_empty_memory(LOG_SIZE, program_info);
        let mut side_note = SideNote::new(&program_traces, &view);
        let program_steps = iter_program_steps(&vm_traces, traces.num_rows());

        // We iterate each block in the trace for each instruction
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
