use crate::{
    machine::types::ColumnName,
    utils::{ColumnNameMap, MachineChip, WORD_SIZE},
};

use num_traits::{One as _, Zero as _};
use stwo_prover::{constraint_framework::EvalAtRow, core::fields::m31::BaseField};
use ColumnName::*;

pub struct XorChip;

impl MachineChip<ColumnName> for XorChip {
    fn fill_main_trace(
        r1_val: [u8; WORD_SIZE],
        r2_val: [u8; WORD_SIZE],
        rd_val: &mut [u8; WORD_SIZE],
        rd_idx: usize,
        cols: &mut [&mut [BaseField]],
        row_idx: usize,
        col_names: &ColumnNameMap<ColumnName>,
    ) {
        if cols[col_names.nth_col(&IsXor, 0)][row_idx] == BaseField::zero() {
            return;
        }
        for i in 0..WORD_SIZE {
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
    }

    fn add_constraints<E: stwo_prover::constraint_framework::EvalAtRow>(
        _cols: &std::collections::HashMap<ColumnName, Vec<<E as EvalAtRow>::F>>,
        _eval: &mut E,
    ) {
        // Currently dealt with directly in the main evaluate() function.
        // TODO: adjust the signature of add_constraints() so that it can access the interaction trace.
    }
}
