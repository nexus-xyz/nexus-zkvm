use std::{collections::HashMap, hash};

use num_traits::{One, Zero};
use stwo_prover::{
    constraint_framework::{EvalAtRow, FrameworkEval},
    core::{
        backend::simd::SimdBackend,
        fields::{m31::BaseField, qm31::SecureField, FieldExpOps},
        poly::{circle::CircleEvaluation, BitReversedOrder},
    },
};

use crate::utils::{self, ColumnNameMap, MachineChip, PermElements};

use super::{consts::N_XOR_TUPLE, types::ColumnName};

use crate::utils::{EvalAtRowExtra, WORD_SIZE};

use ColumnName::*;

/// Enforces the column to be an increment of the provided delta.
///
/// Here is a valid table example assuming a word size and increment delta of 4
/// ```text
/// (incremented, carry)
/// ([00,00,00,00],[00,00,00,00])
/// ([04,00,00,00],[00,00,00,00])
/// ([08,00,00,00],[00,00,00,00])
/// ...
/// ([fc,00,00,00],[00,00,00,00])
/// ([00,01,00,00],[01,00,00,00])
/// ([04,01,00,00],[00,00,00,00])
/// ...
/// ([fc,ff,00,00],[00,00,00,00])
/// ([00,00,01,00],[01,01,00,00])
/// ([04,00,01,00],[00,00,00,00])
/// ```
///
/// This is a wrapping addition. For the example above:
/// ```text
/// (incremented, carry)
/// ([fc,ff,ff,ff],[00,00,00,00])
/// ([00,00,00,00],[01,01,01,01])
/// ([04,00,00,00],[00,00,00,00])
/// ```
pub fn constraint_increment<E, K>(
    delta: u8,
    carry: &K,
    incremented: &K,
    current_row: &HashMap<K, Vec<<E as EvalAtRow>::F>>,
    eval: &mut E,
    is_first_row: <E as EvalAtRow>::F,
    previous_row: &HashMap<K, Vec<<E as EvalAtRow>::F>>,
) where
    E: EvalAtRow,
    K: Eq + hash::Hash,
{
    let one = E::F::one();
    let value = BaseField::from_u32_unchecked(delta as u32);
    let value = E::F::from(value);
    let overflow = BaseField::from_u32_unchecked(256);
    let overflow = E::F::from(overflow);

    for i in 0..WORD_SIZE {
        // assert the first row carry is zeroed
        eval.add_constraint(is_first_row * current_row[carry][i]);

        // assert the carry column is boolean
        eval.add_constraint(current_row[carry][i] * (current_row[carry][i] - one));
    }

    // first row should be incremented
    eval.add_constraint(
        (one - is_first_row)
            * (current_row[incremented][0] - value - previous_row[incremented][0]
                + overflow * current_row[carry][0]),
    );

    // the other columns should add the carry of the previous iteration
    for i in 1..WORD_SIZE {
        eval.add_constraint(
            (one - is_first_row)
                * (current_row[incremented][i]
                    - current_row[carry][i - 1]
                    - previous_row[incremented][i]
                    + overflow * current_row[carry][i]),
        );
    }
}

#[derive(Clone, Debug)]
pub struct EvalMachine<C: MachineChip<ColumnName>> {
    pub rows_log2: u32,
    pub cols: ColumnNameMap<ColumnName>,
    pub xor_perm_element: PermElements<{ N_XOR_TUPLE }>,
    pub _phantom: std::marker::PhantomData<C>,
}

impl<Chips: MachineChip<ColumnName>> FrameworkEval for EvalMachine<Chips> {
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
        constraint_increment(4, &PcCarryFlag, &Pc, &cols, &mut eval, is_first, &prev_cols);

        // Constraint Clk increment
        constraint_increment(
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

        Chips::add_constraints(&cols, &mut eval);

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
impl<C: MachineChip<ColumnName>> EvalMachine<C> {
    pub fn constant_trace(
        &self,
    ) -> Vec<CircleEvaluation<SimdBackend, BaseField, BitReversedOrder>> {
        utils::generate_trace(
            [self.rows_log2; 1 /* is_first */ + 3 /* xor(a,b,result) */],
            |cols| {
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
        )
    }
    pub fn interaction_trace(
        &self,
        base_trace: &Vec<Vec<BaseField>>,
    ) -> Vec<CircleEvaluation<SimdBackend, BaseField, BitReversedOrder>> {
        utils::generate_secure_field_trace(
            [self.rows_log2; 12 /* TODO: automate column counting */],
            |cols| {
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
        )
    }
}
