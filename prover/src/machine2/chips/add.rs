use std::collections::HashMap;

use num_traits::{One as _, Zero as _};
use stwo_prover::{constraint_framework::EvalAtRow, core::fields::m31::BaseField};

use crate::{
    machine2::types::RegisterMachineColumns,
    utils::{ColumnNameMap, MachineChip, WORD_SIZE},
};

use RegisterMachineColumns::*;

pub struct AddChip;
impl MachineChip<RegisterMachineColumns> for AddChip {
    // TODO(now): change the signature of the trait method to reflect new doc.
    fn fill_main_trace(
        r1_val: [u8; WORD_SIZE],
        r2_val: [u8; WORD_SIZE],
        rd_val: &mut [u8; WORD_SIZE],
        rd_idx: usize,
        cols: &mut [&mut [BaseField]],
        row_idx: usize,
        col_names: &ColumnNameMap<RegisterMachineColumns>,
    ) {
        unimplemented!()
    }

    fn add_constraints<E: stwo_prover::constraint_framework::EvalAtRow>(
        cols: &HashMap<RegisterMachineColumns, Vec<<E as EvalAtRow>::F>>,
        eval: &mut E,
    ) {
        unimplemented!()
        // let f_of = |x: u32| -> E::F {
        //     let b: BaseField = x.into();
        //     E::F::from(b)
        // };

        // (0..WORD_SIZE).for_each(|i| {
        //     // It is enough the constraint for each i is a low-degree polynomial.
        //     let carry = if i == 0 {
        //         E::F::zero()
        //     } else {
        //         cols[&CarryFlag][i - 1]
        //     };
        //     // constrain rd_val when is_add and rd_idx is not zero
        //     eval.add_constraint(
        //         cols[&IsAdd][0]
        //             * cols[&RdIdxNonzero][0]
        //             * (carry + cols[&R1Val][i] + cols[&R2Val][i]
        //                 - (cols[&RdVal][i] + f_of(256) * cols[&CarryFlag][i])),
        //     );
        //     // TODO: constrain when rd_idx is zero
        //     eval.add_constraint((E::F::one() - cols[&RdIdxNonzero][0]) * cols[&RdVal][i]);
        // });
    }
}
