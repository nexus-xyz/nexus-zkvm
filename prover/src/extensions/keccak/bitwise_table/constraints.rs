use std::marker::PhantomData;

use stwo_prover::{
    constraint_framework::{EvalAtRow, RelationEntry},
    core::fields::m31::BaseField,
};

use super::{preprocessed_columns::BitwiseTable, BitwiseOp};
use crate::components::RegisteredLookupBound;

pub(super) struct BitwiseTableEvalAtRow<
    'a,
    const ELEM_BITS: u32,
    const EXPAND_BITS: u32,
    E: EvalAtRow,
    R: RegisteredLookupBound,
    B: BitwiseOp,
> {
    pub eval: E,
    pub lookup_elements: &'a R,
    pub _phantom_data: PhantomData<B>,
}

impl<
        const ELEM_BITS: u32,
        const EXPAND_BITS: u32,
        E: EvalAtRow,
        R: RegisteredLookupBound,
        B: BitwiseOp,
    > BitwiseTableEvalAtRow<'_, ELEM_BITS, EXPAND_BITS, E, R, B>
{
    pub fn eval(mut self) -> E {
        // al, bl are the constant columns for the inputs: All pairs of elements in [0,
        // 2^LIMB_BITS).
        // cl is the constant column for the result: e.g. al ^ bl.
        let al = self
            .eval
            .get_preprocessed_column(BitwiseTable::new(ELEM_BITS, EXPAND_BITS, 0).id());

        let bl = self
            .eval
            .get_preprocessed_column(BitwiseTable::new(ELEM_BITS, EXPAND_BITS, 1).id());

        let cl = self.eval.get_preprocessed_column(
            BitwiseTable::new(ELEM_BITS, EXPAND_BITS, B::C_COL_INDEX).id(),
        );

        for i in 0..(1 << (2 * EXPAND_BITS)) {
            let (i, j) = ((i >> EXPAND_BITS) as u32, (i % (1 << EXPAND_BITS)) as u32);
            let multiplicity = self.eval.next_trace_mask();

            let a = al.clone()
                + E::F::from(BaseField::from_u32_unchecked(
                    i << BitwiseTable::new(ELEM_BITS, EXPAND_BITS, 0).limb_bits(),
                ));
            let b = bl.clone()
                + E::F::from(BaseField::from_u32_unchecked(
                    j << BitwiseTable::new(ELEM_BITS, EXPAND_BITS, 1).limb_bits(),
                ));
            let high = B::call(i, j);
            let c = cl.clone()
                + E::F::from(BaseField::from_u32_unchecked(
                    high << BitwiseTable::new(ELEM_BITS, EXPAND_BITS, B::C_COL_INDEX).limb_bits(),
                ));

            self.eval.add_to_relation(RelationEntry::new(
                <R as RegisteredLookupBound>::as_relation_ref(self.lookup_elements),
                -E::EF::from(multiplicity),
                &[a, b, c],
            ));
        }

        self.eval.finalize_logup_in_pairs();
        self.eval
    }
}
