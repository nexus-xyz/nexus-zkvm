use num_traits::Zero;
use stwo::prover::backend::{
    simd::{
        column::BaseColumn,
        m31::{PackedBaseField, LOG_N_LANES},
    },
    Column,
};

use nexus_vm_prover_air_column::{AirColumn, PreprocessedAirColumn};
use stwo_constraint_framework::EvalAtRow;

use crate::{
    component::{ComponentTrace, FinalizedColumn},
    eval::TraceEval,
};

/// A linear or higher degree polynomial expression.
///
/// Polynomial degree must be aligned with the maximum constraint degree bound of the component.
pub trait VirtualColumn {
    type Column: AirColumn;

    fn eval<E: EvalAtRow, P: PreprocessedAirColumn>(
        &self,
        trace_eval: &TraceEval<P, Self::Column, E>,
    ) -> E::F;

    fn combine_at_row(&self, component_trace: &ComponentTrace, vec_idx: usize) -> PackedBaseField;

    fn combine_from_finalized_trace<'a>(
        &self,
        component_trace: &'a ComponentTrace,
    ) -> FinalizedColumn<'a> {
        let log_size = component_trace.log_size();
        let mut column = BaseColumn::zeros(1 << log_size);

        for vec_idx in 0..1 << (log_size - LOG_N_LANES) {
            column.data[vec_idx] = self.combine_at_row(component_trace, vec_idx);
        }

        FinalizedColumn::new_virtual(column)
    }
}

/// Sum of columns, each is expected to be of size 1.
pub struct ColumnSum<C: 'static>(&'static [C]);

impl<C: 'static> ColumnSum<C> {
    pub const fn new(columns: &'static [C]) -> Self {
        Self(columns)
    }
}

impl<C: AirColumn> VirtualColumn for ColumnSum<C> {
    type Column = C;

    fn eval<E: EvalAtRow, P: PreprocessedAirColumn>(
        &self,
        trace_eval: &TraceEval<P, Self::Column, E>,
    ) -> E::F {
        let mut result = E::F::zero();
        for col in self.0 {
            result += trace_eval.column_eval::<1>(*col)[0].clone();
        }
        result
    }

    fn combine_at_row(&self, component_trace: &ComponentTrace, vec_idx: usize) -> PackedBaseField {
        self.0.iter().fold(PackedBaseField::zero(), |acc, &col| {
            let val = component_trace.original_base_column::<1, C>(col)[0].at(vec_idx);
            acc + val
        })
    }
}
