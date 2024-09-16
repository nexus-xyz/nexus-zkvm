use std::ops::Deref;

use num_traits::One as _;
use stwo_prover::constraint_framework::EvalAtRow;

/// Type safe representation of a boolean value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BooleanValue<E: EvalAtRow>(E::F);

impl<E: EvalAtRow> Deref for BooleanValue<E> {
    type Target = E::F;

    fn deref(&self) -> &E::F {
        &self.0
    }
}

impl<E: EvalAtRow> BooleanValue<E> {
    /// Assert the value is a boolean.
    pub fn new(eval: &mut E, v: E::F) -> Self {
        eval.add_constraint(v * (v - E::F::one()));

        Self(v)
    }

    /// Asserts the boolean value is `1` if, and only if, eval is at the first row.
    pub fn is_first_row(&self, _eval: &mut E) {
        // TODO implement
    }

    /// Enforces `self v rhs`
    pub fn or(&self, eval: &mut E, rhs: &Self) {
        eval.add_constraint(self.0 + rhs.0 - self.0 * rhs.0 - E::F::one());
    }

    /// Enforces `self = !rhs`
    pub fn neg(&self, eval: &mut E, rhs: &Self) {
        eval.add_constraint(self.0 + rhs.0 - E::F::one());
    }
}
