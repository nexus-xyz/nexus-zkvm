use num_traits::One;
use stwo_prover::{constraint_framework::EvalAtRow, core::fields::m31::BaseField};

use nexus_common::constants::WORD_SIZE_HALVED;
use nexus_vm_prover_air_column::{AirColumn, PreprocessedAirColumn};
use nexus_vm_prover_trace::eval::TraceEval;

/// Helper struct for constraining clock increments.
pub struct ClkIncrement<C> {
    /// The current execution time represented by two 16-bit limbs
    pub clk: C,
    /// The helper bit to compute the next clock value
    pub clk_carry: C,
}

impl<C: AirColumn> ClkIncrement<C> {
    pub fn eval<E: EvalAtRow, P: PreprocessedAirColumn>(
        self,
        eval: &mut E,
        trace_eval: &TraceEval<P, C, E>,
    ) -> [E::F; WORD_SIZE_HALVED] {
        let clk: [E::F; WORD_SIZE_HALVED] = trace_eval.column_eval(self.clk);
        let [clk_carry] = trace_eval.column_eval(self.clk_carry);

        // (clk-carry) · (1 − clk-carry) = 0
        eval.add_constraint(clk_carry.clone() * (E::F::one() - clk_carry.clone()));

        let clk_next_0 = clk[0].clone() + E::F::one() - clk_carry.clone();
        let clk_next_1 = clk[1].clone() + clk_carry;
        [clk_next_0, clk_next_1]
    }
}

/// Helper struct for constraining program counter increments.
pub struct PcIncrement<C> {
    /// The current value of the program counter register
    pub pc: C,
    /// The helper bits to compute the program counter update
    pub pc_carry: C,
}

impl<C: AirColumn> PcIncrement<C> {
    pub fn eval<E: EvalAtRow, P: PreprocessedAirColumn>(
        self,
        eval: &mut E,
        trace_eval: &TraceEval<P, C, E>,
    ) -> [E::F; WORD_SIZE_HALVED] {
        let pc: [E::F; WORD_SIZE_HALVED] = trace_eval.column_eval(self.pc);
        let [pc_carry] = trace_eval.column_eval(self.pc_carry);

        // (pc-carry) · (1 − pc-carry) = 0
        eval.add_constraint(pc_carry.clone() * (E::F::one() - pc_carry.clone()));

        let pc_next_0 = pc[0].clone() + E::F::from(BaseField::from(4)) - pc_carry.clone();
        let pc_next_1 = pc[1].clone() + pc_carry;
        [pc_next_0, pc_next_1]
    }
}
