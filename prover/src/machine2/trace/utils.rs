use stwo_prover::core::fields::Field;

pub use stwo_prover::core::utils::bit_reverse;

// TODO: patch upstream to make it public and remove / or use pub methods from tests.
pub fn coset_order_to_circle_domain_order<F: Field>(values: &[F]) -> Vec<F> {
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

#[cfg(test)]
mod tests {
    use super::*;
    use stwo_prover::core::{
        fields::m31::M31,
        utils::{bit_reverse, bit_reverse_index, coset_index_to_circle_domain_index},
    };

    #[test]
    fn test_order() {
        let log_size = 3;
        let vals: Vec<M31> = (0..1 << log_size).map(M31::from).collect();
        let mut reordered = coset_order_to_circle_domain_order(&vals);
        bit_reverse(&mut reordered);

        for i in 0..1 << log_size {
            let idx = bit_reverse_index(coset_index_to_circle_domain_index(i, log_size), log_size);
            assert_eq!(reordered[i], vals[idx]);
        }
    }
}
