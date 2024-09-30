// TODO: move more of these into chips

use num_traits::One;
use rand::Rng;
use stwo_prover::core::{
    backend::simd::SimdBackend,
    fields::m31::BaseField,
    poly::{circle::CircleEvaluation, BitReversedOrder},
};

use crate::utils::{self, write_u32, write_word, ColumnNameMap, MachineChip, WORD_SIZE};

use super::{
    consts::NUM_REGISTERS,
    register_file::AddMachineRegisterFile,
    types::{ColumnName, Instruction},
};

use ColumnName::*;

fn clk_on_row(row_idx: usize) -> u32 {
    assert!(row_idx + 1 < 1 << 30); // Overflow check
    4 * (row_idx + 1) as u32
}
fn r1_timestamp(row_idx: usize) -> u32 {
    clk_on_row(row_idx)
}
fn r2_timestamp(row_idx: usize) -> u32 {
    clk_on_row(row_idx) + 1
}
fn rd_timestamp(row_idx: usize) -> u32 {
    clk_on_row(row_idx) + 2
}

fn fill_carry_flags(
    row_idx: usize,
    prev_val: [u8; 4],
    increment: u32,
    filled_column: &ColumnName,
    cols: &mut [&mut [BaseField]],
    col_names: &ColumnNameMap<ColumnName>,
) {
    assert!(increment < 256);
    if row_idx != 0 {
        let mut pc_carry: u32 = increment;
        for i in 0..WORD_SIZE {
            pc_carry = (pc_carry + prev_val[i] as u32) / 256;
            cols[col_names.nth_col(filled_column, i)][row_idx] = BaseField::from(pc_carry);
        }
    }
}

pub fn main_trace<Chips: MachineChip<ColumnName>>(
    rng: &mut impl Rng,
    regs: &mut AddMachineRegisterFile,
    rows_log2: u32,
    col_names: &ColumnNameMap<ColumnName>,
) -> (
    Vec<CircleEvaluation<SimdBackend, BaseField, BitReversedOrder>>,
    Vec<Vec<BaseField>>,
) {
    let mut ret_vv = Vec::new();
    let ret_vc = utils::generate_trace(
        std::iter::repeat(rows_log2).take(col_names.num_columns()),
        |cols| {
            // Fill Clk column
            for row_idx in 0..1 << rows_log2 {
                let clk_val: [u8; WORD_SIZE] = clk_on_row(row_idx).to_le_bytes();
                for i in 0..WORD_SIZE {
                    cols[col_names.nth_col(&Clk, i)][row_idx] = BaseField::from(clk_val[i] as u32);
                }
            }
            // Fill ClkCarryFlag column
            for row_idx in 1..1 << rows_log2 {
                // Start from 1 because it's about incrementin previous value
                let prev_clk_val: [u8; WORD_SIZE] = clk_on_row(row_idx - 1).to_le_bytes();
                fill_carry_flags(row_idx, prev_clk_val, 4, &ClkCarryFlag, cols, col_names);
            }
            let mut pc: u32 = 0;
            let mut prev_pc_val: [u8; WORD_SIZE] = [0; WORD_SIZE];
            for row_idx in 0..1 << rows_log2 {
                // Fill r1_idx, r2_idx, and rd_idx randomly
                // TODO: parse instruction
                let r1_idx: usize = rng.gen_range(0..NUM_REGISTERS as usize);
                let r2_idx: usize = rng.gen_range(0..NUM_REGISTERS as usize);
                let rd_idx: usize = rng.gen_range(0..NUM_REGISTERS as usize);
                // Read input values
                // TODO: add register memory checking
                let (r1_val, r1_read_event) = regs.read(r1_idx, r1_timestamp(row_idx));
                write_u32(
                    r1_read_event.timestamp,
                    &R1PrevTimeStamp,
                    cols,
                    col_names,
                    row_idx,
                );
                write_word(r1_read_event.value, &R1PrevValue, cols, col_names, row_idx);
                let (r2_val, r2_read_event) = regs.read(r2_idx, r2_timestamp(row_idx));
                write_u32(
                    r2_read_event.timestamp,
                    &R2PrevTimeStamp,
                    cols,
                    col_names,
                    row_idx,
                );
                write_word(r2_read_event.value, &R2PrevValue, cols, col_names, row_idx);
                let mut rd_val: [u8; WORD_SIZE] = [0; WORD_SIZE];
                let pc_val: [u8; WORD_SIZE] = pc.to_le_bytes();
                pc += 4;
                let instruction: Instruction = rng.gen();
                let is_add = instruction == Instruction::ADD;
                let is_sub = instruction == Instruction::SUB;
                let is_xor = instruction == Instruction::XOR;
                // set is_add flag or is_sub flag
                if is_add {
                    cols[col_names.nth_col(&IsAdd, 0)][row_idx] = BaseField::one();
                }
                if is_sub {
                    cols[col_names.nth_col(&IsSub, 0)][row_idx] = BaseField::one();
                }
                if is_xor {
                    cols[col_names.nth_col(&IsXor, 0)][row_idx] = BaseField::one();
                }
                // fill pc carry flags, trying to compute prev_pc_val + 4
                fill_carry_flags(row_idx, prev_pc_val, 4, &PcCarryFlag, cols, col_names);
                // Fill register indices
                cols[col_names.nth_col(&R1Idx, 0)][row_idx] = BaseField::from(r1_idx);
                cols[col_names.nth_col(&R2Idx, 0)][row_idx] = BaseField::from(r2_idx);
                cols[col_names.nth_col(&RdIdx, 0)][row_idx] = BaseField::from(rd_idx);
                write_word(pc_val, &Pc, cols, col_names, row_idx);
                write_word(r1_val, &R1Val, cols, col_names, row_idx);
                write_word(r2_val, &R2Val, cols, col_names, row_idx);
                Chips::fill_main_trace(
                    r1_val,
                    r2_val,
                    &mut rd_val,
                    rd_idx,
                    cols,
                    row_idx,
                    col_names,
                );
                // Fill RdValWritten
                let rd_val_written = if rd_idx == 0 { [0; WORD_SIZE] } else { rd_val };
                write_word(rd_val_written, &RdValWritten, cols, col_names, row_idx);
                let prev_rd = regs.write(rd_idx, rd_val_written, rd_timestamp(row_idx));
                write_u32(
                    prev_rd.timestamp,
                    &RdPrevTimeStamp,
                    cols,
                    col_names,
                    row_idx,
                );
                write_word(prev_rd.value, &RdPrevValue, cols, col_names, row_idx);
                cols[col_names.nth_col(&RdIdxNonzero, 0)][row_idx] =
                    BaseField::from(if rd_idx == 0 { 0 } else { 1 });
                cols[col_names.nth_col(&RdIdxNonzeroW, 0)][row_idx] = if rd_idx == 0 {
                    BaseField::one()
                } else {
                    BaseField::one() / cols[col_names.nth_col(&RdIdx, 0)][row_idx]
                };
                cols[col_names.nth_col(&RdIdxNonzeroZ, 0)][row_idx] = if rd_idx == 0 {
                    BaseField::one()
                } else {
                    BaseField::one() / cols[col_names.nth_col(&RdIdxNonzeroW, 0)][row_idx]
                };
                prev_pc_val = pc_val;
            }
            ret_vv = cols.iter().map(|c| c.to_vec()).collect();
        },
    );
    (ret_vc, ret_vv)
}
