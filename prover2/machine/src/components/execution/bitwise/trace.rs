use std::collections::BTreeMap;

use nexus_vm::WORD_SIZE;
use nexus_vm_prover_trace::{
    builder::TraceBuilder,
    program::{ProgramStep, Word},
};

use super::{
    columns::Column, Bitwise, BitwiseOp, ExecutionResult, AND_LOOKUP_IDX, OR_LOOKUP_IDX,
    XOR_LOOKUP_IDX,
};
use crate::components::utils::{add_16bit_with_carry, u32_to_16bit_parts_le};

/// Multiplicities accumulator for bitwise instructions that require lookups.
#[derive(Debug, Default)]
pub struct BitwiseMultiplicities {
    pub(super) accum: BTreeMap<u8, u32>,
}

impl BitwiseMultiplicities {
    pub fn multiplicities(&self) -> &BTreeMap<u8, u32> {
        &self.accum
    }
}

impl<B: BitwiseOp> Bitwise<B> {
    fn execute_step(program_step: ProgramStep) -> ExecutionResult {
        let value_b = program_step.get_value_b();
        let (value_c, _) = program_step.get_value_c();

        let value_a = std::array::from_fn(|i| {
            let b = value_b[i];
            let c = value_c[i];
            match B::BITWISE_LOOKUP_IDX {
                idx if idx == AND_LOOKUP_IDX => b & c,
                idx if idx == OR_LOOKUP_IDX => b | c,
                idx if idx == XOR_LOOKUP_IDX => b ^ c,
                _ => panic!("invalid lookup idx"),
            }
        });

        let (_value_a_0_3, value_a_4_7) = split_limbs(&value_a);
        let (value_b_0_3, value_b_4_7) = split_limbs(&value_b);
        let (value_c_0_3, value_c_4_7) = split_limbs(&value_c);

        ExecutionResult {
            out_bytes: value_a,
            value_a_4_7,
            value_b_0_3,
            value_b_4_7,
            value_c_0_3,
            value_c_4_7,
        }
    }

    pub(super) fn generate_trace_row(
        &self,
        trace: &mut TraceBuilder<Column>,
        row_idx: usize,
        program_step: ProgramStep,
        accum: &mut BitwiseMultiplicities,
    ) {
        let step = &program_step.step;
        assert_eq!(step.instruction.opcode.builtin(), Some(B::OPCODE));

        let pc = step.pc;
        let pc_parts = u32_to_16bit_parts_le(pc);
        let (pc_next, pc_carry) = add_16bit_with_carry(pc_parts, WORD_SIZE as u16);

        let clk = step.timestamp;
        let clk_parts = u32_to_16bit_parts_le(clk);
        let (clk_next, clk_carry) = add_16bit_with_carry(clk_parts, 1u16);

        let value_b = program_step.get_value_b();
        let (value_c, _) = program_step.get_value_c();
        let ExecutionResult {
            out_bytes,
            value_a_4_7,
            value_b_0_3,
            value_b_4_7,
            value_c_0_3,
            value_c_4_7,
        } = Self::execute_step(program_step);

        trace.fill_columns(row_idx, pc_parts, Column::Pc);
        trace.fill_columns(row_idx, pc_next, Column::PcNext);
        trace.fill_columns(row_idx, pc_carry, Column::PcCarry);

        trace.fill_columns(row_idx, clk_parts, Column::Clk);
        trace.fill_columns(row_idx, clk_next, Column::ClkNext);
        trace.fill_columns(row_idx, clk_carry, Column::ClkCarry);

        trace.fill_columns_bytes(row_idx, &value_b, Column::BVal);
        trace.fill_columns_bytes(row_idx, &value_c, Column::CVal);
        trace.fill_columns_bytes(row_idx, &out_bytes, Column::AVal);

        trace.fill_columns(row_idx, value_a_4_7, Column::AValHigh);
        trace.fill_columns(row_idx, value_b_4_7, Column::BValHigh);
        trace.fill_columns(row_idx, value_c_4_7, Column::CValHigh);

        for i in 0..WORD_SIZE {
            let looked_up_row = value_b_0_3[i] * 16 + value_c_0_3[i];
            *accum.accum.entry(looked_up_row).or_default() += 1;

            let looked_up_row = value_b_4_7[i] * 16 + value_c_4_7[i];
            *accum.accum.entry(looked_up_row).or_default() += 1;
        }
    }
}

/// Splits each 8-bit limb of a word into two 4-bit components. The results are combined back into two words (less-significant, more-significant).
fn split_limbs(word: &Word) -> (Word, Word) {
    let mut low_bits = Word::default();
    let mut high_bits = Word::default();
    for i in 0..WORD_SIZE {
        low_bits[i] = word[i] & 0b1111;
        high_bits[i] = word[i] >> 4;
    }
    (low_bits, high_bits)
}
