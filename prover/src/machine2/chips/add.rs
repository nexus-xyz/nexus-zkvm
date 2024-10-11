use std::collections::HashMap;

use num_traits::Zero as _;
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
        assert!(rd_idx != 0);

        if cols[col_names.nth_col(&IsAdd, 0)][row_idx] == BaseField::zero() {
            return;
        }
        let mut prev_carry: i32 = 0;
        for i in 0..WORD_SIZE {
            // set rd_val[i] = (carry + r1_val[j] + r2_val[j]) % 256
            rd_val[i] = (prev_carry + r1_val[i] as i32 + r2_val[i] as i32) as u8;
            cols[col_names.nth_col(&ValueA, i)][row_idx] = BaseField::from(rd_val[i] as u32);
            let carry: i32 = (prev_carry + r1_val[i] as i32 + r2_val[i] as i32) / 256;
            assert!(carry == 0 || carry == 1);
            // set carry_flag[i] = (carry + r1_val[i] + r2_val[i]) / 256
            cols[col_names.nth_col(&CarryFlag, i)][row_idx] = BaseField::from(carry);

            prev_carry = carry;
        }
    }

    fn add_constraints<E: stwo_prover::constraint_framework::EvalAtRow>(
        cols: &HashMap<RegisterMachineColumns, Vec<<E as EvalAtRow>::F>>,
        eval: &mut E,
    ) {
        let is_add = cols[&IsAdd][0];
        // modulus for 8-bit limbs
        let modulus = E::F::from(256u32.into());

        for i in 0..WORD_SIZE {
            let carry = if i == 0 {
                // previous carry is zero for first limbs
                E::F::zero()
            } else {
                cols[&CarryFlag][i - 1]
            };

            // ADD a, b, c
            // rdval[i] + h1[i] * 2^8 = rs1val[i] + rs2val[i] + h1[i - 1]
            eval.add_constraint(
                is_add
                    * (cols[&ValueA][i] + cols[&CarryFlag][i] * modulus
                        - (cols[&ValueB][i] + cols[&ValueC][i] + carry)),
            );
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use num_traits::One;

    fn gen_trace(rs1val: u32, rs2val: u32) -> [[u8; WORD_SIZE]; 3] {
        let output = rs1val.wrapping_add(rs2val);
        let a = rs1val.to_le_bytes();
        let b = rs2val.to_le_bytes();
        let output = output.to_le_bytes();

        [a, b, output]
    }

    #[test]
    fn add_chip_trace() {
        let vals = [
            (0u32, 0u32),
            (u32::MAX, 0),
            (u32::MAX, u32::MAX),
            (u32::MAX - 1, u32::MAX / 2),
            (1 << 16, 10),
        ];

        const ROW_IDX: usize = 0;
        const RD_IDX: usize = 1;

        for (rs1val, rs2val) in vals {
            let [r1_val, r2_val, output] = gen_trace(rs1val, rs2val);

            let mut rd_val = [0; WORD_SIZE];

            let col_names = ColumnNameMap::new();
            // TODO: remove double allocation interface.
            let mut cols = vec![vec![BaseField::zero()]; col_names.total_columns()];
            let mut cols: Vec<_> = cols.iter_mut().map(Vec::as_mut_slice).collect();

            cols[col_names.nth_col(&IsAdd, 0)][0] = BaseField::one();
            AddChip::fill_main_trace(
                r1_val,
                r2_val,
                &mut rd_val,
                RD_IDX,
                cols.as_mut_slice(),
                ROW_IDX,
                &col_names,
            );

            assert_eq!(output, rd_val, "r1_val: {rs1val} r2_val: {rs2val}");
        }
    }

    #[test]
    fn add_chip_constraints() {
        // TODO
    }
}
