// Simple addition machine
// This machine performs only additions. It has a STARK-trace with
// numbers in [0, 32): 'r1_idx', 'r2_idx', and 'rd_idx'.
// and 32-bit numbers: 'r1_val', 'r2_val', and 'rd_val'.
// r1_idx and r2_idx are indices of input registers (they can be the same).
// rd_idx is the index of the output register.
// r1_val and r2_val are the values of the input registers before the addition is executed.
// rd_val is the value of the output register after the addition is executed.
// Each 32-bit number is represented by four columns, one for each byte.
// TODO: These columns WILL BE range-checked to be an 8-bit integer.
// TODO: Memory-checking for register values WILL BE added.

use clap::{arg, command, Parser};
use nexus_vm_prover::utils::{self, ColumnNameMap, EvalAtRowExtra, PermElements};
use num_traits::{One, Zero};
use rand::{
    distributions::{Distribution, Standard},
    rngs, Rng,
};
use strum::IntoEnumIterator;
use stwo_prover::{
    constraint_framework::{
        assert_constraints, EvalAtRow, FrameworkComponent, FrameworkEval, TraceLocationAllocator,
    },
    core::{
        air::Component,
        backend::simd::SimdBackend,
        channel::Blake2sChannel,
        fields::{m31::BaseField, qm31::SecureField, FieldExpOps},
        pcs::{CommitmentSchemeProver, CommitmentSchemeVerifier, PcsConfig},
        poly::{
            circle::{CanonicCoset, CircleEvaluation, PolyOps},
            BitReversedOrder,
        },
        prover::{prove, verify},
        vcs::blake2_merkle::Blake2sMerkleChannel,
    },
};

const WORD_SIZE: usize = 4;
const NUM_REGISTERS: usize = 32;

// TODO: Register memory checking
// Clock for Register Memory Checking
// 0 is used for initializing the register file.
// 4 is used for reading the rs_1 for the first instruction.
// 5 is used for reading the rs_2 for the first instruction.
// 6 is used for writing the rd for the first instruction.
// 8..11 is used for reading the rs_1, rs_2, and writing the rd for the second instruction.
// and so on.

// CLK column will contain (4,8,12,16,...).
// For reading rs_1 value, the timestamp CLK will be used.
// For reading rs_2 value, the timestamp CLK+1 will be used.
// For writing rd value, the timestamp CLK+2 will be used.

// Reading from a register idx i. If i is zero, no events are recorded. If i is nonzero, we look at the register file to determine the last time stamp and the value of the register.
// Then we record a ReadSetElement(register_index=i, prev_timestamp, prev_value).
// We also record a WriteSetElement(register_index=i, current_timestamp, prev_value). The prev_value is reused because reading the register does not change the value.
// Writing to a register idx i. The index i should not be zero. We look at the register file to determine the last time stamp and the value of the register.
// We record a ReadSetElement(register_index=i, prev_timestamp, prev_value).
// We also record a WriteSetElement(register_index=i, current_timestamp, new_value). The prev_value is reused because reading the register does not change the value.
// In both cases prev_timestamp < current_timestamp must be constrained. This should be implemented with lookups on limbs.
// For that, the technique used for "xor with lookups" will be useful.

// TODO: write somewhere in the trace, the initial values of registers.
// TODO: write somewhere in the trace, the final values and timestamps of registers.
// TODO: calculate register memory check logup sum

#[derive(Clone, Copy, Debug, PartialEq)]
enum Instruction {
    ADD,
    SUB,
    XOR,
}

impl Distribution<Instruction> for Standard {
    fn sample<R: Rng + ?Sized>(&self, rng: &mut R) -> Instruction {
        match rng.gen_range(0..3) {
            0 => Instruction::ADD,
            1 => Instruction::SUB,
            _ => Instruction::XOR,
        }
    }
}

struct PrevRegister {
    timestamp: u32,
    value: [u8; WORD_SIZE],
}

// Forcing all access to register file modifiy the timestamp.
mod register_file {
    use rand::Rng;

    use crate::{PrevRegister, NUM_REGISTERS, WORD_SIZE};

    #[derive(Clone, Copy, Debug)]
    pub struct AddMachineRegisterFile {
        // TODO: add timestamp for register memory checking
        vals: [[u8; WORD_SIZE]; NUM_REGISTERS],
        _timestamps: [u32; NUM_REGISTERS], // TODO: force all access to modify timestamp
    }

    impl AddMachineRegisterFile {
        pub fn new(rng: &mut impl Rng) -> Self {
            let mut vals: [[u8; WORD_SIZE]; NUM_REGISTERS] = rng.gen();
            vals[0] = [0; WORD_SIZE]; // r0 is always zero
            let timestamps: [u32; NUM_REGISTERS] = [0; NUM_REGISTERS]; // timestamp 0 is reserved for initialization
            Self {
                vals,
                _timestamps: timestamps,
            }
        }
        pub fn read(&mut self, idx: usize, timestamp: u32) -> ([u8; WORD_SIZE], PrevRegister) {
            assert!(idx < NUM_REGISTERS);
            let prev = PrevRegister {
                timestamp: self._timestamps[idx],
                value: self.vals[idx],
            };
            self._timestamps[idx] = timestamp;
            (self.vals[idx], prev)
        }
        pub fn write(&mut self, idx: usize, val: [u8; WORD_SIZE], timestamp: u32) -> PrevRegister {
            assert!(idx < NUM_REGISTERS);
            let prev = PrevRegister {
                timestamp: self._timestamps[idx],
                value: self.vals[idx],
            };
            self._timestamps[idx] = timestamp;
            self.vals[idx] = val;
            prev
        }
    }
}

use strum_macros::EnumIter;

#[derive(Clone, Copy, Debug, EnumIter, Eq, PartialEq, Hash)]
enum ColumnName {
    Clk, // start from 4, increments by 4
    ClkCarryFlag,
    Pc,
    PcCarryFlag,
    IsAdd,
    IsSub,
    IsXor,
    R1Idx,
    R2Idx,
    RdIdx,
    RdIdxNonzero,
    RdIdxNonzeroW,
    RdIdxNonzeroZ,
    R1Val,
    R2Val,
    RdVal,
    RdValWritten, // RdIdxNonZero * RdVal
    R1PrevValue,
    R1PrevTimeStamp,
    R2PrevValue,
    R2PrevTimeStamp,
    RdPrevValue,
    RdPrevTimeStamp,
    CarryFlag,
    XorMultiplicity,
}
use ColumnName::*;

#[derive(Clone, Debug)]
pub struct AddMachine {
    rows_log2: u32,
    cols: ColumnNameMap<ColumnName>,
    xor_perm_element: PermElements<{ Self::N_XOR_TUPLE }>,
}

impl FrameworkEval for AddMachine {
    fn log_size(&self) -> u32 {
        self.rows_log2
    }
    fn max_constraint_log_degree_bound(&self) -> u32 {
        self.log_size() + 1
    }
    fn evaluate<E: stwo_prover::constraint_framework::EvalAtRow>(&self, mut eval: E) -> E {
        // TODO: range check columns. All most all columns need rangechecks for soundness
        let [prev_cols, cols] = eval.lookup_trace_masks_with_offsets(&self.cols, 0, [-1, 0]);
        // TODO: constrain interaction masks from interaction trace
        let use_dom: [_; WORD_SIZE] = eval.next_extension_interaction_masks_cur_row(1);
        let use_dom_inv: [_; WORD_SIZE] = eval.next_extension_interaction_masks_cur_row(1);
        let [table_denom] = eval.next_extension_interaction_mask(1, [0]);
        let [table_denom_inv] = eval.next_extension_interaction_mask(1, [0]);
        let [table_denom_inv_m] = eval.next_extension_interaction_mask(1, [0]);
        let [sum, prev_sum] = eval.next_extension_interaction_mask(1, [0, -1]);
        let [is_first, is_last] = eval.next_interaction_mask(2, [0, 1]);
        let [xor_a] = eval.next_interaction_mask(2, [0]);
        let [xor_b] = eval.next_interaction_mask(2, [0]);
        let [xor_result] = eval.next_interaction_mask(2, [0]);

        let f_of = |x: u32| -> E::F {
            let b: BaseField = x.into();
            E::F::from(b)
        };

        // Constraint initial values
        for i in 0..WORD_SIZE {
            eval.add_constraint(is_first * cols[&Pc][i]);
            eval.add_constraint(
                is_first
                    * if i == 0 {
                        cols[&Clk][i] - f_of(4)
                    } else {
                        cols[&Clk][i]
                    },
            ); // Clk starts from four
        }
        // Constraint pc increment
        constraint_increment(
            f_of,
            4,
            &PcCarryFlag,
            &Pc,
            &cols,
            &mut eval,
            is_first,
            &prev_cols,
        );
        // Constraint Clk increment
        constraint_increment(
            f_of,
            4,
            &ClkCarryFlag,
            &Clk,
            &cols,
            &mut eval,
            is_first,
            &prev_cols,
        );

        // Constraint "rd_idx_nonzero"
        // TODO: add range checking on rd_idx_nonzero in {0, 1}
        eval.add_constraint(cols[&RdIdx][0] * cols[&RdIdxNonzeroW][0] - cols[&RdIdxNonzero][0]);
        eval.add_constraint(cols[&RdIdxNonzeroW][0] * cols[&RdIdxNonzeroZ][0] - E::F::one());

        // Constraint, only one opcode is chosen
        eval.add_constraint(cols[&IsAdd][0] + cols[&IsSub][0] + cols[&IsXor][0] - E::F::one());

        // Constraint addition
        (0..WORD_SIZE).for_each(|i| {
            // It is enough the constraint for each i is a low-degree polynomial.
            let carry = if i == 0 {
                E::F::zero()
            } else {
                cols[&CarryFlag][i - 1]
            };
            // constrain rd_val when is_add and rd_idx is not zero
            eval.add_constraint(
                cols[&IsAdd][0]
                    * cols[&RdIdxNonzero][0]
                    * (carry + cols[&R1Val][i] + cols[&R2Val][i]
                        - (cols[&RdVal][i] + f_of(256) * cols[&CarryFlag][i])),
            );
            // TODO: constrain when rd_idx is zero
            eval.add_constraint((E::F::one() - cols[&RdIdxNonzero][0]) * cols[&RdVal][i]);
        });

        // Constraint subtraction
        (0..WORD_SIZE).for_each(|i| {
            // It is enough the constraint for each i is a low-degree polynomial.
            let carry = if i == 0 {
                E::F::zero()
            } else {
                cols[&CarryFlag][i - 1]
            };
            // constrain rd_val when is_sub and rd_idx is not zero
            eval.add_constraint(
                cols[&IsSub][0]
                    * cols[&RdIdxNonzero][0]
                    * (carry + cols[&R1Val][i]
                        - cols[&R2Val][i]
                        - (cols[&RdVal][i] + f_of(256) * cols[&CarryFlag][i])),
            );
        });

        // Constraint RdValWritten
        for i in 0..WORD_SIZE {
            eval.add_constraint(cols[&RdIdxNonzero][0] * cols[&RdVal][i] - cols[&RdValWritten][i]);
        }

        // constraint use_dom
        for i in 0..WORD_SIZE {
            eval.add_constraint(
                E::EF::from(cols[&IsXor][0])
                    * E::EF::from(cols[&RdIdxNonzero][0])
                    * (self.xor_perm_element.combine::<E::F, E::EF, _>([
                        cols[&R1Val][i],
                        cols[&R2Val][i],
                        cols[&RdVal][i],
                    ]) - use_dom[i]),
            );
            // constraint use_dom_inv
            eval.add_constraint(use_dom[i] * (use_dom[i] * use_dom_inv[i] - E::EF::one()));
            eval.add_constraint(use_dom_inv[i] * (use_dom[i] * use_dom_inv[i] - E::EF::one()));
        }

        // constraint table_denom
        eval.add_constraint(
            table_denom_inv_m
                * (self
                    .xor_perm_element
                    .combine::<E::F, E::EF, _>([xor_a, xor_b, xor_result])
                    - table_denom),
        );
        // constraint table_denom_inv
        eval.add_constraint(table_denom_inv_m * (table_denom * table_denom_inv - E::EF::one()));
        // constraint table_denom_inv_m
        eval.add_constraint(
            table_denom_inv_m * (table_denom_inv_m - table_denom_inv * cols[&XorMultiplicity][0]),
        );

        // constraint sum
        // on the first row
        eval.add_constraint(
            E::EF::from(is_first)
                * (sum - use_dom_inv.iter().fold(E::EF::zero(), |acc, &x| acc + x)
                    + table_denom_inv_m),
        );
        // on the other rows
        eval.add_constraint(
            (E::EF::one() - E::EF::from(is_first))
                * (sum - prev_sum - use_dom_inv.iter().fold(E::EF::zero(), |acc, &x| acc + x)
                    + table_denom_inv_m),
        );

        // logup check for xor
        eval.add_constraint(E::EF::from(is_last) * sum);

        eval
    }
}

fn constraint_increment<E: stwo_prover::constraint_framework::EvalAtRow>(
    f_of: impl Fn(u32) -> <E as EvalAtRow>::F,
    increment: u32,
    carry_flag: &ColumnName,
    incremented: &ColumnName,
    cols: &std::collections::HashMap<ColumnName, Vec<<E as EvalAtRow>::F>>,
    eval: &mut E,
    is_first: <E as EvalAtRow>::F,
    prev_cols: &std::collections::HashMap<ColumnName, Vec<<E as EvalAtRow>::F>>,
) {
    assert!(increment < 256);
    (0..WORD_SIZE).for_each(|i| {
        let pc_carry: E::F = if i == 0 {
            f_of(increment) // Increment
        } else {
            cols[carry_flag][i - 1]
        };
        eval.add_constraint(
            (E::F::one() - is_first)
                * (pc_carry + prev_cols[incremented][i]
                    - (cols[incremented][i] + f_of(256) * cols[carry_flag][i])),
        );
    });
}

use register_file::AddMachineRegisterFile;

fn main_trace(
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
        |cols, _| {
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
                let mut prev_carry: i32 = 0;
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
                for i in 0..WORD_SIZE {
                    if is_add {
                        fill_add(
                            i,
                            &mut prev_carry,
                            r1_val,
                            r2_val,
                            &mut rd_val,
                            rd_idx,
                            cols,
                            row_idx,
                            col_names,
                        );
                    } else if is_sub {
                        fill_sub(
                            i,
                            &mut prev_carry,
                            r1_val,
                            r2_val,
                            &mut rd_val,
                            rd_idx,
                            cols,
                            row_idx,
                            col_names,
                        );
                    } else if is_xor {
                        fill_xor(
                            i,
                            r1_val,
                            r2_val,
                            &mut rd_val,
                            rd_idx,
                            cols,
                            row_idx,
                            col_names,
                        );
                    }
                }
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
        (),
    );
    (ret_vc, ret_vv)
}

fn write_word(
    val: [u8; WORD_SIZE],
    dst: &ColumnName,
    cols: &mut [&mut [BaseField]],
    col_names: &ColumnNameMap<ColumnName>,
    row_idx: usize,
) {
    for i in 0..WORD_SIZE {
        cols[col_names.nth_col(dst, i)][row_idx] = BaseField::from(val[i] as u32);
    }
}

fn write_u32(
    val: u32,
    dst: &ColumnName,
    cols: &mut [&mut [BaseField]],
    col_names: &ColumnNameMap<ColumnName>,
    row_idx: usize,
) {
    let val: [u8; WORD_SIZE] = val.to_le_bytes();
    write_word(val, dst, cols, col_names, row_idx);
}

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

fn fill_add(
    i: usize,
    prev_carry: &mut i32,
    r1_val: [u8; 4],
    r2_val: [u8; 4],
    rd_val: &mut [u8; 4],
    rd_idx: usize,
    cols: &mut [&mut [BaseField]],
    row_idx: usize,
    col_names: &ColumnNameMap<ColumnName>,
) {
    // set rd_val[i] = (carry + r1_val[j] + r2_val[j]) % 256
    rd_val[i] = (*prev_carry + r1_val[i] as i32 + r2_val[i] as i32) as u8;
    if rd_idx != 0 {
        cols[col_names.nth_col(&RdVal, i)][row_idx] = BaseField::from(rd_val[i] as u32);
    }
    let carry: i32 = (*prev_carry + r1_val[i] as i32 + r2_val[i] as i32) / 256;
    debug_assert!(carry == 0 || carry == 1);
    // set carry_flag[i] = (carry + r1_val[i] + r2_val[i]) / 256
    cols[col_names.nth_col(&CarryFlag, i)][row_idx] = BaseField::from(carry);
    match rd_idx {
        0 => {
            // r0 is always zero
            debug_assert_eq!(
                cols[col_names.nth_col(&RdVal, i)][row_idx],
                BaseField::zero()
            );
        }
        _ => {
            debug_assert_eq!(
                BaseField::from(*prev_carry)
                    + cols[col_names.nth_col(&R1Val, i)][row_idx]
                    + cols[col_names.nth_col(&R2Val, i)][row_idx],
                cols[col_names.nth_col(&RdVal, i)][row_idx]
                    + BaseField::from(256) * cols[col_names.nth_col(&CarryFlag, i)][row_idx]
            );
        }
    }
    *prev_carry = carry;
}
fn fill_sub(
    i: usize,
    prev_carry: &mut i32,
    r1_val: [u8; 4],
    r2_val: [u8; 4],
    rd_val: &mut [u8; 4],
    rd_idx: usize,
    cols: &mut [&mut [BaseField]],
    row_idx: usize,
    col_names: &ColumnNameMap<ColumnName>,
) {
    // set rd_val[i] = (prev_carry + r1_val[j] - r2_val[j]) % 256
    rd_val[i] = (*prev_carry + r1_val[i] as i32 - r2_val[i] as i32) as u8;
    if rd_idx != 0 {
        cols[col_names.nth_col(&RdVal, i)][row_idx] = BaseField::from(rd_val[i] as u32);
    }
    let carry: i32 = if 0 > (*prev_carry + r1_val[i] as i32 - r2_val[i] as i32) {
        -1
    } else {
        0
    };
    // set carry_flag[i]
    if carry == -1 {
        cols[col_names.nth_col(&CarryFlag, i)][row_idx] = -BaseField::one();
    }
    match rd_idx {
        0 => {
            // r0 is always zero
            debug_assert_eq!(
                cols[col_names.nth_col(&RdVal, i)][row_idx],
                BaseField::zero()
            );
        }
        _ => {
            debug_assert_eq!(
                BaseField::from(if *prev_carry < 0 {
                    -BaseField::from(-*prev_carry)
                } else {
                    BaseField::from(*prev_carry)
                }) + cols[col_names.nth_col(&R1Val, i)][row_idx]
                    - cols[col_names.nth_col(&R2Val, i)][row_idx],
                cols[col_names.nth_col(&RdVal, i)][row_idx]
                    + BaseField::from(256) * cols[col_names.nth_col(&CarryFlag, i)][row_idx]
            );
        }
    }
    *prev_carry = carry;
}
fn fill_xor(
    i: usize,
    r1_val: [u8; 4],
    r2_val: [u8; 4],
    rd_val: &mut [u8; 4],
    rd_idx: usize,
    cols: &mut [&mut [BaseField]],
    row_idx: usize,
    col_names: &ColumnNameMap<ColumnName>,
) {
    rd_val[i] = r1_val[i] ^ r2_val[i];
    if rd_idx != 0 {
        cols[col_names.nth_col(&RdVal, i)][row_idx] = BaseField::from(rd_val[i] as u32);
        cols[col_names.nth_col(&XorMultiplicity, 0)]
            [r1_val[i] as usize * 256 + r2_val[i] as usize] += BaseField::one();
    }
    match rd_idx {
        0 => {
            // r0 is always zero
            debug_assert_eq!(
                cols[col_names.nth_col(&RdVal, i)][row_idx],
                BaseField::zero()
            );
        }
        _ => {
            // TODO: look this up in the answer sheet
        }
    }
}

impl AddMachine {
    const N_XOR_TUPLE: usize = 3;

    fn constant_trace(&self) -> Vec<CircleEvaluation<SimdBackend, BaseField, BitReversedOrder>> {
        utils::generate_trace(
            [self.rows_log2; 1 /* is_first */ + 3 /* xor(a,b,result) */],
            |cols, ()| {
                cols[0][0] = 1.into(); // is_first
                for a in 0..256 {
                    for b in 0..256 {
                        let result = a ^ b;
                        cols[1][a * 256 + b] = a.into();
                        cols[2][a * 256 + b] = b.into();
                        cols[3][a * 256 + b] = result.into();
                    }
                }
            },
            (),
        )
    }
    fn interaction_trace(
        &self,
        base_trace: &Vec<Vec<BaseField>>,
    ) -> Vec<CircleEvaluation<SimdBackend, BaseField, BitReversedOrder>> {
        utils::generate_secure_field_trace(
            [self.rows_log2; 12 /* TODO: automate column counting */],
            |cols, ()| {
                // Split cols into single SecureField columns
                // use_denom_inv needs to be four columns for each limb
                let (use_denom, cols) = cols.split_at_mut(4);
                let (use_denom_inv, cols) = cols.split_at_mut(4);
                let [table_denom, table_denom_inv, table_denom_inv_m, sum] = cols else {
                    assert!(false, "unexpected column count");
                    return; // Not reached, silencing compiler
                };
                let n_rows: usize = 1 << self.rows_log2;
                // Fill use_denom
                // Every time is_xor is seen in the base trace, the three columns are combned, using the challenge.
                (0..n_rows).for_each(|row_idx| {
                    if base_trace[self.cols.nth_col(&IsXor, 0)][row_idx] == BaseField::one()
                        && base_trace[self.cols.nth_col(&RdIdxNonzero, 0)][row_idx]
                            == BaseField::one()
                    {
                        for i in 0..WORD_SIZE {
                            use_denom[i][row_idx] = self.xor_perm_element.combine([
                                base_trace[self.cols.nth_col(&R1Val, i)][row_idx],
                                base_trace[self.cols.nth_col(&R2Val, i)][row_idx],
                                base_trace[self.cols.nth_col(&RdVal, i)][row_idx],
                            ]);
                            // Fill use_denom_inv
                            use_denom_inv[i][row_idx] = use_denom[i][row_idx].inverse();
                        }
                    };
                });
                // Fill table_denom
                (0..256).for_each(|a| {
                    (0..256).for_each(|b| {
                        let result = a ^ b;
                        let idx = a * 256 + b;
                        table_denom[idx] = self.xor_perm_element.combine([
                            BaseField::from(a),
                            BaseField::from(b),
                            BaseField::from(result),
                        ]);
                        // Fill use_denom_inv by batch-inverse
                        table_denom_inv[idx] = table_denom[idx].inverse();
                    });
                });
                // Fill table_denom_invM using multiplicity
                (0..256).for_each(|a| {
                    (0..256).for_each(|b| {
                        let idx = a * 256 + b;
                        table_denom_inv_m[idx] = table_denom_inv[idx]
                            * base_trace[self.cols.nth_col(&XorMultiplicity, 0)][idx];
                    });
                });
                // Fill sums
                // use_denom_inv are added, table_denom_inv_m are subtracted
                // The first row already contains the numbers from the first row.
                // The last row will contain the whole sum.
                (0..n_rows).for_each(|row_idx| {
                    if 0 < row_idx {
                        sum[row_idx] = sum[row_idx - 1];
                    }
                    (0..WORD_SIZE).for_each(|i| {
                        sum[row_idx] += use_denom_inv[i][row_idx];
                    });
                    sum[row_idx] -= table_denom_inv_m[row_idx];
                });
                // Assert zero on the last row
                debug_assert_eq!(sum[n_rows - 1], SecureField::zero());
            },
            (),
        )
    }
}

#[derive(Parser)]
#[command(version, about, long_about = None)]
pub struct Cli {
    // Trace height 2^16 is needed to hold the XOR lookup table
    #[arg(short, long, default_value = "16", help = "Number of trace rows in log2", value_parser = clap::value_parser!(u32).range(16..=28))]
    pub rows_log2: u32,
}

fn column_sizes(column_name: &ColumnName) -> usize {
    match column_name {
        Clk => WORD_SIZE,
        ClkCarryFlag => WORD_SIZE,
        Pc => WORD_SIZE,
        PcCarryFlag => WORD_SIZE,
        IsAdd => 1,
        IsSub => 1,
        IsXor => 1,
        R1Idx => 1,
        R2Idx => 1,
        RdIdx => 1,
        RdIdxNonzero => 1,
        RdIdxNonzeroW => 1,
        RdIdxNonzeroZ => 1,
        R1Val => WORD_SIZE,
        R2Val => WORD_SIZE,
        RdVal => WORD_SIZE,
        RdValWritten => WORD_SIZE,
        R1PrevTimeStamp => WORD_SIZE,
        R1PrevValue => WORD_SIZE,
        R2PrevTimeStamp => WORD_SIZE,
        R2PrevValue => WORD_SIZE,
        RdPrevValue => WORD_SIZE,
        RdPrevTimeStamp => WORD_SIZE,
        CarryFlag => WORD_SIZE,
        XorMultiplicity => 1,
        // Avoid _ and let the compiler detect missing entries.
    }
}

fn main() {
    let cli = Cli::parse();
    let column_names: ColumnNameMap<ColumnName> = ColumnNameMap::new()
        .allocate_bulk(ColumnName::iter().map(|x| (x, column_sizes(&x))))
        .finalize();

    let config = PcsConfig::default();
    let coset = CanonicCoset::new(cli.rows_log2 + 1 + config.fri_config.log_blowup_factor)
        .circle_domain()
        .half_coset;
    let twiddles = SimdBackend::precompute_twiddles(coset);
    let allocator = &mut TraceLocationAllocator::default();
    let prover_channel = &mut Blake2sChannel::default();
    let prover_commitment_scheme =
        &mut CommitmentSchemeProver::<_, Blake2sMerkleChannel>::new(config, &twiddles);

    let mut rng = rngs::OsRng;
    let mut reg_file = AddMachineRegisterFile::new(&mut rng);
    let (main_trace, basic_trace) =
        main_trace(&mut rng, &mut reg_file, cli.rows_log2, &column_names);
    let mut tree_builder = prover_commitment_scheme.tree_builder();
    tree_builder.extend_evals(main_trace);
    tree_builder.commit(prover_channel);

    // Draw permutation element
    let xor_perm_element = PermElements::draw(prover_channel);
    let machine = AddMachine {
        rows_log2: cli.rows_log2,
        cols: column_names,
        xor_perm_element,
    };

    // Interaction trace.
    let interaction_trace = machine.interaction_trace(&basic_trace);
    let mut tree_builder = prover_commitment_scheme.tree_builder();
    tree_builder.extend_evals(interaction_trace);
    tree_builder.commit(prover_channel);

    // Constraint trace.
    let constant_trace = machine.constant_trace();
    let mut tree_builder = prover_commitment_scheme.tree_builder();
    tree_builder.extend_evals(constant_trace);
    tree_builder.commit(prover_channel);

    // Sanity check

    let traces = prover_commitment_scheme
        .trees
        .as_ref()
        .map(|t| t.polynomials.to_vec());

    assert_constraints(&traces, CanonicCoset::new(cli.rows_log2), |evaluator| {
        machine.evaluate(evaluator);
    });

    let component = FrameworkComponent::new(allocator, machine);
    let proof =
        prove(&[&component], prover_channel, prover_commitment_scheme).expect("failed to prove");

    // verifier
    let verifier_channel = &mut Blake2sChannel::default();
    let verifier_commitment_scheme =
        &mut CommitmentSchemeVerifier::<Blake2sMerkleChannel>::new(config);
    let verifier_component_sizes = component.trace_log_degree_bounds();

    for i in 0..3 {
        verifier_commitment_scheme.commit(
            proof.commitments[i],
            &verifier_component_sizes[i],
            verifier_channel,
        )
    }
    verify(
        &[&component],
        verifier_channel,
        verifier_commitment_scheme,
        proof,
    )
    .expect("proof verification failed");

    println!("{} machine cycles proved and verified", 1 << cli.rows_log2);
}
