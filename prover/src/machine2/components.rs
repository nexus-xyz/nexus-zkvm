use std::marker::PhantomData;

use stwo_prover::constraint_framework::{EvalAtRow, FrameworkComponent, FrameworkEval};

use super::{trace::eval::TraceEval, traits::MachineChip};

pub(super) const LOG_CONSTRAINT_DEGREE: u32 = 1;

pub type MachineComponent<C> = FrameworkComponent<MachineEval<C>>;

pub struct MachineEval<C> {
    log_n_rows: u32,
    _phantom_data: PhantomData<C>,
}

impl<C> MachineEval<C> {
    pub(crate) fn new(log_n_rows: u32) -> Self {
        Self {
            log_n_rows,
            _phantom_data: PhantomData,
        }
    }
}

impl<C: MachineChip> FrameworkEval for MachineEval<C> {
    fn log_size(&self) -> u32 {
        self.log_n_rows
    }

    fn max_constraint_log_degree_bound(&self) -> u32 {
        self.log_n_rows + LOG_CONSTRAINT_DEGREE
    }

    fn evaluate<E: EvalAtRow>(&self, mut eval: E) -> E {
        let trace_eval = TraceEval::new(&mut eval);
        C::add_constraints(&mut eval, &trace_eval);

        eval
    }
}
