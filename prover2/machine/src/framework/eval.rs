use stwo_prover::constraint_framework::FrameworkEval;

use nexus_vm_prover_trace::eval::TraceEval;

use crate::framework::traits::builtin::BuiltInComponent;

pub struct BuiltInComponentEval<'a, C: BuiltInComponent> {
    pub(crate) component: &'a C,
    pub(crate) log_size: u32,
    pub(crate) lookup_elements: C::LookupElements,
}

impl<C: BuiltInComponent> BuiltInComponentEval<'_, C> {
    pub(crate) const fn max_constraint_log_degree_bound(log_size: u32) -> u32 {
        log_size + C::LOG_CONSTRAINT_DEGREE_BOUND
    }
}

impl<C: BuiltInComponent> FrameworkEval for BuiltInComponentEval<'_, C> {
    fn log_size(&self) -> u32 {
        self.log_size
    }

    fn max_constraint_log_degree_bound(&self) -> u32 {
        Self::max_constraint_log_degree_bound(self.log_size)
    }

    fn evaluate<E: stwo_prover::constraint_framework::EvalAtRow>(&self, mut eval: E) -> E {
        let trace_eval = TraceEval::new(&mut eval);
        C::add_constraints(self.component, &mut eval, trace_eval, &self.lookup_elements);
        eval
    }
}

pub type FrameworkComponent<'a, C> =
    stwo_prover::constraint_framework::FrameworkComponent<BuiltInComponentEval<'a, C>>;
