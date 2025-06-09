use crate::extensions::ExtensionsConfig;
use nexus_vm::riscv::BuiltinOpcode;
use stwo_prover::core::fields::m31::BaseField;

use crate::{
    column::Column::{self, *},
    trace::eval::trace_eval,
    traits::MachineChip,
};

use super::{gadget::constrain_mul_partial_product, nexani::mull_limb};

pub struct MulChip;

impl MachineChip for MulChip {
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
            Some(BuiltinOpcode::MUL)
        ) {
            return;
        }

        let value_b = vm_step.get_value_b();
        let value_c = vm_step.get_value_c().0;

        // MUL main constraint need these intermediate values
        let mul_result = mull_limb(u32::from_le_bytes(value_b), u32::from_le_bytes(value_c));

        // Fill in the intermediate values into traces
        // MUL carry_0 for lower half, in {0, 1}
        traces.fill_columns(row_idx, mul_result.carry_l[0], MulCarry0);
        // MUL carry_1 for lower half, in {0, 1, 2, 3}
        traces.fill_columns(row_idx, mul_result.carry_l[1], MulCarry1_0);
        traces.fill_columns(row_idx, mul_result.carry_l[2], MulCarry1_1);

        // MUL P1, P3' and P3'' in range [0, 2^16 - 1]
        traces.fill_columns(row_idx, mul_result.p1, MulP1);
        traces.fill_columns(row_idx, mul_result.p3_prime, MulP3Prime);
        traces.fill_columns(row_idx, mul_result.p3_prime_prime, MulP3PrimePrime);

        // MUL Carry of P1, P3' and P3'' in {0, 1}
        traces.fill_columns(row_idx, mul_result.c1, MulC1);
        traces.fill_columns(row_idx, mul_result.c3_prime, MulC3Prime);
        traces.fill_columns(row_idx, mul_result.c3_prime_prime, MulC3PrimePrime);

        // The output of the multiplication
        traces.fill_columns(
            row_idx,
            vm_step.get_result().expect("MUL must have result"),
            ValueA,
        );
    }

    fn add_constraints<E: stwo_prover::constraint_framework::EvalAtRow>(
        eval: &mut E,
        trace_eval: &crate::trace::eval::TraceEval<E>,
        _lookup_elements: &crate::components::AllLookupElements,
        _config: &ExtensionsConfig,
    ) {
        let [is_mul] = trace_eval!(trace_eval, IsMul);
        let value_a = trace_eval!(trace_eval, ValueA);
        let value_b = trace_eval!(trace_eval, ValueB);
        let value_c = trace_eval!(trace_eval, ValueC);

        let p1 = trace_eval!(trace_eval, MulP1);
        let p3_prime = trace_eval!(trace_eval, MulP3Prime);
        let p3_prime_prime = trace_eval!(trace_eval, MulP3PrimePrime);
        let [c1] = trace_eval!(trace_eval, MulC1);
        let [c3_prime] = trace_eval!(trace_eval, MulC3Prime);
        let [c3_prime_prime] = trace_eval!(trace_eval, MulC3PrimePrime);

        let z_0 = value_b[0].clone() * value_c[0].clone();
        let z_1 = value_b[1].clone() * value_c[1].clone();
        let z_2 = value_b[2].clone() * value_c[2].clone();
        let z_3 = value_b[3].clone() * value_c[3].clone();

        // is_mul * (P3_prime + c3_prime * 2^16 - (|b|_0 + |b|_3) * (|c|_0 + |c|_3) + z_0 + z_3)
        constrain_mul_partial_product(
            eval,
            is_mul.clone(),
            p3_prime.clone(),
            c3_prime.clone(),
            value_b[0].clone(),
            value_b[3].clone(),
            value_c[0].clone(),
            value_c[3].clone(),
            z_0.clone(),
            z_3.clone(),
        );

        // is_mul * (P3_prime_prime + c3_prime_prime * 2^16 - (|b|_1 + |b|_2) * (|c|_1 + |c|_2) + z_1 + z_2)
        constrain_mul_partial_product(
            eval,
            is_mul.clone(),
            p3_prime_prime.clone(),
            c3_prime_prime.clone(),
            value_b[1].clone(),
            value_b[2].clone(),
            value_c[1].clone(),
            value_c[2].clone(),
            z_1.clone(),
            z_2.clone(),
        );

        // is_mul * (P1 + c1 * 2^16 - (|b|_0 + |b|_1) * (|c|_0 + |c|_1) + z_0 + z_1)
        constrain_mul_partial_product(
            eval,
            is_mul.clone(),
            p1.clone(),
            c1.clone(),
            value_b[0].clone(),
            value_b[1].clone(),
            value_c[0].clone(),
            value_c[1].clone(),
            z_0.clone(),
            z_1.clone(),
        );

        let [mul_carry_0] = trace_eval!(trace_eval, MulCarry0);
        let [mul_carry_1_0] = trace_eval!(trace_eval, MulCarry1_0);
        let [mul_carry_1_1] = trace_eval!(trace_eval, MulCarry1_1);

        // is_mul * (z_0 + P1_l * 2^8 - carry0 * 2^16 - |a|_0 - |a|_1 * 2^8)
        eval.add_constraint(
            is_mul.clone()
                * (z_0.clone() + p1[0].clone() * BaseField::from(1 << 8)
                    - mul_carry_0.clone() * BaseField::from(1 << 16)
                    - value_a[0].clone()
                    - value_a[1].clone() * BaseField::from(1 << 8)),
        );

        // is_mul ⋅
        // [z_1 + P_1h + (b_0 + b_2) * (c_0 + c_2) - z_0 - z_2 + (P'_3l + P''_3l + c_1) * 2^8 + carry_0 - carry_1 * 2^16 - carry_1 * 2^17 - |a|_2 - |a|_3 * 2^8]
        eval.add_constraint(
            is_mul.clone()
                * (z_1.clone()
                    + p1[1].clone()
                    + (value_b[0].clone() + value_b[2].clone())
                        * (value_c[0].clone() + value_c[2].clone())
                    - z_0.clone()
                    - z_2.clone()
                    + mul_carry_0.clone()
                    - mul_carry_1_0.clone() * BaseField::from(1 << 16)
                    - mul_carry_1_1.clone() * BaseField::from(1 << 17)
                    + (p3_prime[0].clone() + p3_prime_prime[0].clone() + c1.clone())
                        * BaseField::from(1 << 8)
                    - value_a[2].clone()
                    - value_a[3].clone() * BaseField::from(1 << 8)),
        );
    }
}

#[cfg(test)]
mod test {
    use crate::{
        chips::{
            AddChip, CpuChip, DecodingCheckChip, LuiChip, ProgramMemCheckChip, RangeCheckChip,
            RegisterMemCheckChip, SubChip,
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
            // Test multiplication with various inputs
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADDI), 1, 0, 5), // x1 = 5
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADDI), 2, 0, 7), // x2 = 7
            Instruction::new_ir(Opcode::from(BuiltinOpcode::MUL), 3, 2, 1),  // x3 = x1 * x2 = 35
            // Test multiplication with negative values
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADDI), 4, 0, 3), // x4 = 3
            Instruction::new_ir(Opcode::from(BuiltinOpcode::SUB), 4, 0, 4),  // x4 = -3 (0xFFFFFFFD)
            Instruction::new_ir(Opcode::from(BuiltinOpcode::MUL), 5, 4, 2), // x5 = x4 * x2 = -21 (0xFFFFFFEB)
            Instruction::new_ir(Opcode::from(BuiltinOpcode::MUL), 6, 1, 4), // x6 = x1 * x4 = -15 (0xFFFFFFF1)
            Instruction::new_ir(Opcode::from(BuiltinOpcode::MUL), 7, 4, 4), // x7 = x4 * x4 = 9 (negative * negative = positive)
            // Test multiplication with zero
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADDI), 8, 0, 0), // x8 = 0
            Instruction::new_ir(Opcode::from(BuiltinOpcode::MUL), 9, 8, 1),  // x9 = x8 * x1 = 0
            Instruction::new_ir(Opcode::from(BuiltinOpcode::MUL), 10, 4, 8), // x10 = x4 * x8 = 0
            // Test multiplication with larger values
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADDI), 11, 0, 100), // x11 = 100
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADDI), 12, 0, 200), // x12 = 200
            Instruction::new_ir(Opcode::from(BuiltinOpcode::MUL), 13, 11, 12), // x13 = x11 * x12 = 20000
            // Test overflow cases (positive * positive)
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADDI), 14, 0, 65535), // x14 = 65535 (0xFFFF)
            Instruction::new_ir(Opcode::from(BuiltinOpcode::MUL), 15, 14, 14), // x15 = x14 * x14 = 0xFFFE0001 (-131071)
            // --- Edge Cases ---
            // Load constants: 0x7FFFFFFF (max_pos), 0x80000000 (min_neg), -1 (max_neg), 1 (min_pos)
            Instruction::new_ir(Opcode::from(BuiltinOpcode::LUI), 16, 0, 0x7FFFF), // x16 = 0x7FFFF000
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADDI), 16, 16, 0xFFF), // x16 = 0x7FFFFFFF (max_pos)
            Instruction::new_ir(Opcode::from(BuiltinOpcode::LUI), 17, 0, 0x80000), // x17 = 0x80000000 (min_neg)
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADDI), 18, 0, 1),      // x18 = 1
            Instruction::new_ir(Opcode::from(BuiltinOpcode::SUB), 18, 0, 18), // x18 = -1 (0xFFFFFFFF)
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADDI), 19, 0, 1), // x19 = 1
            // Test max_pos * max_pos
            Instruction::new_ir(Opcode::from(BuiltinOpcode::MUL), 20, 16, 16), // x20 = 0x7FFFFFFF * 0x7FFFFFFF = 0x00000001
            // Test min_neg * min_neg
            Instruction::new_ir(Opcode::from(BuiltinOpcode::MUL), 22, 17, 17), // x22 = 0x80000000 * 0x80000000 = 0x00000000
            // Test max_pos * 1
            Instruction::new_ir(Opcode::from(BuiltinOpcode::MUL), 23, 16, 19), // x23 = 0x7FFFFFFF * 1 = 0x7FFFFFFF
            // Test -1 * -1
            Instruction::new_ir(Opcode::from(BuiltinOpcode::MUL), 27, 18, 18), // x27 = -1 * -1 = 1
            // Test -1 * 1
            Instruction::new_ir(Opcode::from(BuiltinOpcode::MUL), 28, 18, 19), // x28 = -1 * 1 = -1
            // Test multiplication resulting in 0x80000000
            Instruction::new_ir(Opcode::from(BuiltinOpcode::LUI), 29, 0, 0x40000), // x29 = 0x40000000
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADDI), 30, 0, 2),      // x30 = 2
            Instruction::new_ir(Opcode::from(BuiltinOpcode::MUL), 31, 29, 30), // x31 = 0x40000000 * 2 = 0x7FFFFFFF
            //    Test max_pos * min_neg
            Instruction::new_ir(Opcode::from(BuiltinOpcode::MUL), 21, 16, 17), // x21 = 0x7FFFFFFF * 0x80000000 = 0x80000000
            //    Test min_neg * 1
            Instruction::new_ir(Opcode::from(BuiltinOpcode::MUL), 24, 17, 19), // x24 = 0x80000000 * 1 = 0x80000000
            //    Test max_pos * -1
            Instruction::new_ir(Opcode::from(BuiltinOpcode::MUL), 25, 16, 18), // x25 = 0x7FFFFFFF * -1 = 0x80000001
            //    Test min_neg * -1
            Instruction::new_ir(Opcode::from(BuiltinOpcode::MUL), 26, 17, 18), // x26 = 0x80000000 * -1 = 0x80000000
        ]);
        vec![basic_block]
    }

    #[test]
    fn test_k_trace_constrained_mul_instructions() {
        type Chips = (
            CpuChip,
            DecodingCheckChip,
            AddChip,
            SubChip,
            MulChip,
            LuiChip,
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
