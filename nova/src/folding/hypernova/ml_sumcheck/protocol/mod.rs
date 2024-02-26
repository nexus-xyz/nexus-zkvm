//! Interactive Proof Protocol used for Multilinear Sumcheck
use ark_std::marker::PhantomData;

pub mod prover;
pub mod verifier;

pub use super::data_structures::{ListOfProductsOfPolynomials, PolynomialInfo};

/// Interactive Proof for Multilinear Sumcheck
pub struct IPForMLSumcheck<F, RO> {
    #[doc(hidden)]
    _marker: PhantomData<(F, RO)>,
}
