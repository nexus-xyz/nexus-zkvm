use num_traits::One;
use stwo_prover::{constraint_framework::EvalAtRow, core::fields::m31::BaseField};

use nexus_common::constants::WORD_SIZE_HALVED;
use nexus_vm_prover_air_column::{AirColumn, PreprocessedAirColumn};
use nexus_vm_prover_trace::eval::TraceEval;

/// Helper struct for constraining clock increments.
pub struct ClkIncrement<C> {
    /// Binary value to indicate if the row is a padding row
    pub is_local_pad: C,
    /// The current execution time represented by two 16-bit limbs
    pub clk: C,
    /// The next execution time represented by two 16-bit limbs
    pub clk_next: C,
    /// The helper bit to compute the next clock value
    pub clk_carry: C,
}

impl<C: AirColumn> ClkIncrement<C> {
    pub fn constrain<E: EvalAtRow, P: PreprocessedAirColumn>(
        self,
        eval: &mut E,
        trace_eval: &TraceEval<P, C, E>,
    ) {
        let [is_local_pad] = trace_eval.column_eval(self.is_local_pad);

        let clk: [E::F; WORD_SIZE_HALVED] = trace_eval.column_eval(self.clk);
        let clk_next: [E::F; WORD_SIZE_HALVED] = trace_eval.column_eval(self.clk_next);
        let [clk_carry] = trace_eval.column_eval(self.clk_carry);

        // (1 − is-local-pad) · (
        //     clk-next(1) + clk-carry(1) · 2^16
        //     − clk(1) − 1
        // ) = 0
        eval.add_constraint(
            (E::F::one() - is_local_pad.clone())
                * (clk_next[0].clone() + clk_carry.clone() * BaseField::from(1 << 16)
                    - clk[0].clone()
                    - E::F::one()),
        );
        // (1 − is-local-pad) · (clk-next(2) − clk(2) − clk-carry(1)) = 0
        eval.add_constraint(
            (E::F::one() - is_local_pad.clone())
                * (clk_next[1].clone() - clk[1].clone() - clk_carry.clone()),
        );

        // (clk-carry) · (1 − clk-carry) = 0
        eval.add_constraint(clk_carry.clone() * (E::F::one() - clk_carry.clone()));
    }
}

/// Helper struct for constraining program counter increments.
pub struct PcIncrement<C> {
    /// Binary value to indicate if the row is a padding row
    pub is_local_pad: C,
    /// The current value of the program counter register
    pub pc: C,
    /// The next value of the program counter register after the execution
    pub pc_next: C,
    /// The helper bits to compute the program counter update
    pub pc_carry: C,
}

impl<C: AirColumn> PcIncrement<C> {
    pub fn constrain<E: EvalAtRow, P: PreprocessedAirColumn>(
        self,
        eval: &mut E,
        trace_eval: &TraceEval<P, C, E>,
    ) {
        let [is_local_pad] = trace_eval.column_eval(self.is_local_pad);

        let pc: [E::F; WORD_SIZE_HALVED] = trace_eval.column_eval(self.pc);
        let pc_next: [E::F; WORD_SIZE_HALVED] = trace_eval.column_eval(self.pc_next);
        let [pc_carry] = trace_eval.column_eval(self.pc_carry);

        // (1 − is-local-pad) · (
        //     pc-next(1) + pc-carry(1) · 2^16
        //     − pc(1) − 4
        // ) = 0
        eval.add_constraint(
            (E::F::one() - is_local_pad.clone())
                * (pc_next[0].clone() + pc_carry.clone() * BaseField::from(1 << 16)
                    - pc[0].clone()
                    - E::F::from(4.into())),
        );
        // (1 − is-local-pad) · (pc-next(2) − pc(2) − pc-carry(1)) = 0
        eval.add_constraint(
            (E::F::one() - is_local_pad.clone())
                * (pc_next[1].clone() - pc[1].clone() - pc_carry.clone()),
        );
        // (pc-carry) · (1 − pc-carry) = 0
        eval.add_constraint(pc_carry.clone() * (E::F::one() - pc_carry.clone()));
    }
}
