use std::collections::HashMap;

use num_traits::{One as _, Zero as _};
use stwo_prover::{constraint_framework::EvalAtRow, core::fields::m31::BaseField};

use crate::{
    machine::types::RegisterMachineColumns,
    utils::{ColumnNameMap, MachineChip, WORD_SIZE},
};

use RegisterMachineColumns::*;

pub struct AddChip;
impl MachineChip<RegisterMachineColumns> for AddChip {
    fn fill_main_trace(
        r1_val: [u8; WORD_SIZE],
        r2_val: [u8; WORD_SIZE],
        rd_val: &mut [u8; WORD_SIZE],
        rd_idx: usize,
        cols: &mut [&mut [BaseField]],
        row_idx: usize,
        col_names: &ColumnNameMap<RegisterMachineColumns>,
    ) {
        if cols[col_names.nth_col(&IsAdd, 0)][row_idx] == BaseField::zero() {
            return;
        }
        let mut prev_carry: i32 = 0;
        for i in 0..WORD_SIZE {
            // set rd_val[i] = (carry + r1_val[j] + r2_val[j]) % 256
            rd_val[i] = (prev_carry + r1_val[i] as i32 + r2_val[i] as i32) as u8;
            if rd_idx != 0 {
                cols[col_names.nth_col(&RdVal, i)][row_idx] = BaseField::from(rd_val[i] as u32);
            }
            let carry: i32 = (prev_carry + r1_val[i] as i32 + r2_val[i] as i32) / 256;
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
                        BaseField::from(prev_carry)
                            + cols[col_names.nth_col(&R1Val, i)][row_idx]
                            + cols[col_names.nth_col(&R2Val, i)][row_idx],
                        cols[col_names.nth_col(&RdVal, i)][row_idx]
                            + BaseField::from(256)
                                * cols[col_names.nth_col(&CarryFlag, i)][row_idx]
                    );
                }
            }
            prev_carry = carry;
        }
    }

    fn add_constraints<E: stwo_prover::constraint_framework::EvalAtRow>(
        cols: &HashMap<RegisterMachineColumns, Vec<<E as EvalAtRow>::F>>,
        eval: &mut E,
    ) {
        let f_of = |x: u32| -> E::F {
            let b: BaseField = x.into();
            E::F::from(b)
        };

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
    }
}
