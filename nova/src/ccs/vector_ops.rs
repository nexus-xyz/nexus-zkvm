use ark_ff::PrimeField;
use ark_std::iter::zip;

/// Multiply two vectors element wise (hadamard product).
pub fn elem_mul<F: PrimeField>(us: &Vec<F>, vs: &Vec<F>) -> Vec<F> {
    assert_eq!(us.len(), vs.len());

    elem_mul_unchecked(us, vs)
}

/// Multiply two vectors element wise (hadamard product).
/// This does not check that the vector shapes are compatible.
pub fn elem_mul_unchecked<F: PrimeField>(us: &Vec<F>, vs: &Vec<F>) -> Vec<F> {
    zip(us, vs).map(|(u, v)| *u * v).collect()
}

/// Multiply a vector by a scalar.
pub fn scalar_mul<F: PrimeField>(us: &[F], c: &F) -> Vec<F> {
    us.iter().map(|u| *u * c).collect()
}

/// Add two vectors together element wise.
pub fn elem_add<F: PrimeField>(us: &Vec<F>, vs: &Vec<F>) -> Vec<F> {
    assert_eq!(us.len(), vs.len());

    elem_add_unchecked(us, vs)
}

/// Add two vectors together element wise
/// This does not check that the vector shapes are compatible.
pub fn elem_add_unchecked<F: PrimeField>(us: &Vec<F>, vs: &Vec<F>) -> Vec<F> {
    zip(us, vs).map(|(u, v)| *u + v).collect()
}
