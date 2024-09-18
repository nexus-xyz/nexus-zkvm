use num_traits::Zero as _;
use stwo_prover::core::{
    backend::simd::{column::BaseColumn, SimdBackend},
    fields::{m31::BaseField, Field},
    poly::{
        circle::{CanonicCoset, CircleEvaluation},
        BitReversedOrder,
    },
    utils::bit_reverse,
    ColumnVec,
};

fn coset_order_to_circle_domain_order<F: Field>(values: &[F]) -> Vec<F> {
    let mut circle_domain_order = Vec::with_capacity(values.len());
    let n = values.len();

    let half_len = n / 2;

    for i in 0..half_len {
        circle_domain_order.push(values[i << 1]);
    }

    for i in 0..half_len {
        circle_domain_order.push(values[n - 1 - (i << 1)]);
    }

    circle_domain_order
}

pub fn generate_trace<L, F, A>(
    log_sizes: L,
    execution: F,
    args: A,
) -> ColumnVec<CircleEvaluation<SimdBackend, BaseField, BitReversedOrder>>
where
    L: IntoIterator<Item = u32>,
    F: FnOnce(&mut [&mut [BaseField]], A),
{
    let (mut columns, domains): (Vec<_>, Vec<_>) = log_sizes
        .into_iter()
        .map(|log_size| {
            let rows = 1 << log_size as usize;
            (
                vec![BaseField::zero(); rows],
                CanonicCoset::new(log_size).circle_domain(),
            )
        })
        .unzip();

    // asserts the user cannot mutate the number of rows
    let mut cols: Vec<_> = columns.iter_mut().map(|c| c.as_mut_slice()).collect();

    execution(cols.as_mut_slice(), args);

    columns
        .into_iter()
        .zip(domains)
        .map(|(col, domain)| {
            let mut col = coset_order_to_circle_domain_order(col.as_slice());

            bit_reverse(&mut col);

            let col = BaseColumn::from_iter(col);

            CircleEvaluation::new(domain, col)
        })
        .collect()
}
