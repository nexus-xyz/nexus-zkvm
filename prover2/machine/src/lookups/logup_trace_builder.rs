//! Interaction trace builder for component framework.

use stwo::{
    core::fields::{m31::BaseField, qm31::SecureField},
    prover::{
        backend::simd::{
            m31::{PackedBaseField, LOG_N_LANES},
            qm31::PackedSecureField,
            SimdBackend,
        },
        poly::{circle::CircleEvaluation, BitReversedOrder},
    },
};
use stwo_constraint_framework::{LogupTraceGenerator, Relation};

use super::RegisteredLookupBound;
use nexus_vm_prover_trace::component::FinalizedColumn;

type LogUpFrac = (PackedSecureField, PackedSecureField);

/// Helper struct for generating logup trace in pairs.
pub struct LogupTraceBuilder {
    pub log_size: u32,
    pub logup_trace_gen: LogupTraceGenerator,
    pub pending_logup: Vec<LogUpFrac>,
}

impl LogupTraceBuilder {
    pub fn new(log_size: u32) -> Self {
        assert!(log_size >= LOG_N_LANES);
        Self {
            log_size,
            logup_trace_gen: LogupTraceGenerator::new(log_size),
            pending_logup: Vec::with_capacity(1 << (log_size - LOG_N_LANES)),
        }
    }
}

impl LogupTraceBuilder {
    fn iter_logup_fractions<'a, const N: usize, R, F>(
        log_size: u32,
        relation: &'a R,
        mult_columns: &'a [FinalizedColumn<'a>; N],
        mult_expr: F,
        tuple: &'a [FinalizedColumn<'a>],
    ) -> impl Iterator<Item = LogUpFrac> + 'a
    where
        R: RegisteredLookupBound,
        F: Fn([PackedBaseField; N]) -> PackedSecureField + 'a,
    {
        (0..1 << (log_size - LOG_N_LANES)).map(move |vec_idx| {
            let mult_vals = mult_columns.clone().map(|col| col.at(vec_idx));
            let p0 = mult_expr(mult_vals);

            let tuple: Vec<PackedBaseField> = tuple.iter().map(|col| col.at(vec_idx)).collect();
            let p1: PackedSecureField = relation.as_relation_ref().combine(&tuple);

            (p0, p1)
        })
    }

    #[allow(unused)]
    pub fn add_to_relation<'a, T, R>(
        &mut self,
        relation: &'a R,
        mult: T,
        tuple: &'a [FinalizedColumn<'a>],
    ) where
        T: Into<FinalizedColumn<'a>>,
        R: RegisteredLookupBound,
    {
        let mult = mult.into();
        self.add_to_relation_with(relation, [mult], |[col]| col.into(), tuple);
    }

    pub fn add_to_relation_with<'a, const N: usize, R, F>(
        &mut self,
        relation: &R,
        mult_columns: [FinalizedColumn<'a>; N],
        mult_expr: F,
        tuple: &'a [FinalizedColumn<'a>],
    ) where
        R: RegisteredLookupBound,
        F: Fn([PackedBaseField; N]) -> PackedSecureField,
    {
        let frac_iter =
            Self::iter_logup_fractions(self.log_size, relation, &mult_columns, mult_expr, tuple);

        if self.pending_logup.is_empty() {
            self.pending_logup = frac_iter.collect();
        } else {
            let mut logup_col_gen = self.logup_trace_gen.new_col();

            for (vec_row, (a, b)) in frac_iter.enumerate() {
                let (c, d) = self.pending_logup[vec_row];

                logup_col_gen.write_frac(vec_row, a * d + b * c, b * d);
            }

            logup_col_gen.finalize_col();
            self.pending_logup.clear();
        }
    }

    pub fn finalize(
        mut self,
    ) -> (
        Vec<CircleEvaluation<SimdBackend, BaseField, BitReversedOrder>>,
        SecureField,
    ) {
        if !self.pending_logup.is_empty() {
            // write last column
            let mut logup_col_gen = self.logup_trace_gen.new_col();
            for (vec_row, (a, b)) in self.pending_logup.into_iter().enumerate() {
                logup_col_gen.write_frac(vec_row, a, b);
            }
            logup_col_gen.finalize_col();
        }

        self.logup_trace_gen.finalize_last()
    }
}
