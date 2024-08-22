//! A `Path` represent a proof that a CacheLine is present
//! at a given address.

// Note: this code (loosly) based on the ArkWorks implementation
// https://github.com/arkworks-rs/crypto-primitives

use ark_crypto_primitives::{
    crh::{poseidon, CRHScheme, CRHSchemeGadget, TwoToOneCRHScheme, TwoToOneCRHSchemeGadget},
    sponge::poseidon::{find_poseidon_ark_and_mds, PoseidonConfig},
};
use ark_r1cs_std::{alloc::AllocVar, boolean::Boolean, fields::fp::FpVar, prelude::*};
use ark_relations::r1cs::{ConstraintSystemRef, SynthesisError};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};

use crate::circuit::F;
use crate::error::NexusVMError;

use super::{cacheline::*, MemoryProof};
use NexusVMError::HashError;

pub type CS = ConstraintSystemRef<F>;

pub type Digest = F;
pub type Params = PoseidonConfig<F>;
pub type LeafHash = poseidon::CRH<F>;
pub type TwoToOneHash = poseidon::TwoToOneCRH<F>;

pub type DigestVar = FpVar<F>;
pub type ParamsVar = poseidon::constraints::CRHParametersVar<F>;
pub type LeafHashG = poseidon::constraints::CRHGadget<F>;
pub type TwoToOneHashG = poseidon::constraints::TwoToOneCRHGadget<F>;

/// Generate configuration for poseidon hash
/// suitable for hashing field elements associated with the BN254 curve.
pub fn poseidon_config() -> PoseidonConfig<F> {
    const FULL_ROUNDS: usize = 8;
    const PARTIAL_ROUNDS: usize = 57;
    const ALPHA: u64 = 5;
    const RATE: usize = 2;
    const CAPACITY: usize = 1;
    const MODULUS_BITS: u64 = 254;

    let (ark, mds) = find_poseidon_ark_and_mds::<F>(
        MODULUS_BITS,
        RATE,
        FULL_ROUNDS as u64,
        PARTIAL_ROUNDS as u64,
        0,
    );
    PoseidonConfig {
        full_rounds: FULL_ROUNDS,
        partial_rounds: PARTIAL_ROUNDS,
        alpha: ALPHA,
        ark,
        mds,
        rate: RATE,
        capacity: CAPACITY,
    }
}

pub fn hash_leaf(params: &Params, leaf: &[F]) -> Result<Digest, NexusVMError> {
    match LeafHash::evaluate(params, leaf) {
        Ok(d) => Ok(d),
        Err(e) => Err(HashError(e.to_string())),
    }
}

pub fn compress(params: &Params, left: &Digest, right: &Digest) -> Result<Digest, NexusVMError> {
    match TwoToOneHash::compress(params, left, right) {
        Ok(d) => Ok(d),
        Err(e) => Err(HashError(e.to_string())),
    }
}

pub fn hash_memory(params: &Params, cl: &CacheLine) -> Result<Digest, NexusVMError> {
    hash_leaf(params, &cl.scalars())
}

/// Calculate a hash chain of length `CACHE_LOG`, starting from
/// a default `CacheLine`. This is used to construct paths for
/// missing elements in the memory.
pub fn compute_zeros(params: &Params) -> Result<Vec<Digest>, NexusVMError> {
    fn f(params: &Params, v: &mut Vec<Digest>, n: usize) -> Result<Digest, NexusVMError> {
        if n == 0 {
            return hash_memory(params, &CacheLine::default());
        }
        let d = f(params, v, n - 1)?;
        v.push(d);
        compress(params, &d, &d)
    }

    let mut v = Vec::new();
    let root = f(params, &mut v, CACHE_LOG)?;
    v.push(root);
    v.reverse();
    Ok(v)
}

/// Holds a proof of a particular path from leaf to root
/// For example, if we have the tree:
///```text
///         [A]
///        /   \
///      [B]    C
///     / \   /  \
///    D [E] F    H
///      / \
///    [I] J
///```
/// and we want to prove I, then `auth` is:
///   `[(true,J), (false,D), (true,C)]` ,
/// root is A, and leaf is I.
#[derive(Debug, Default, Clone, PartialEq, CanonicalSerialize, CanonicalDeserialize)]
pub struct Path {
    pub root: Digest,
    pub leaf: [F; 2],
    pub auth: Vec<(bool, Digest)>,
}

impl Path {
    pub fn new(root: Digest, leaf: [F; 2], auth: Vec<(bool, Digest)>) -> Self {
        Path { root, leaf, auth }
    }

    /// Verify a `Path` by checking hashes
    pub fn verify(&self, params: &Params) -> Result<bool, NexusVMError> {
        let mut hash = hash_leaf(params, &self.leaf)?;
        for (is_left, s) in &self.auth {
            if *is_left {
                hash = compress(params, &hash, s)?;
            } else {
                hash = compress(params, s, &hash)?;
            }
        }
        Ok(self.root == hash)
    }

    /// In-circuit version of `verify`.
    pub fn verify_circuit(
        &self,
        cs: CS,
        params: &ParamsVar,
        root: &DigestVar,
        leaf: &[FpVar<F>],
    ) -> Result<(), SynthesisError> {
        let mode = AllocationMode::Witness;
        let mut hash = LeafHashG::evaluate(params, &leaf[0..2])?;
        for (b, d) in &self.auth {
            let b = Boolean::new_variable(cs.clone(), || Ok(b), mode)?;
            let d = DigestVar::new_variable(cs.clone(), || Ok(d), mode)?;

            let l = b.select(&hash, &d)?;
            let r = b.select(&d, &hash)?;

            hash = TwoToOneHashG::compress(params, &l, &r)?;
        }
        hash.enforce_equal(root)
    }
}

impl MemoryProof for Path {
    type Params = ParamsVar;

    fn params(cs: CS) -> Result<Self::Params, SynthesisError> {
        ParamsVar::new_constant(cs.clone(), poseidon_config())
    }

    fn circuit(
        &self,
        cs: ConstraintSystemRef<F>,
        params: &Self::Params,
        root: &FpVar<F>,
        data: &[FpVar<F>],
    ) -> Result<(), SynthesisError> {
        self.verify_circuit(cs, params, root, data)
    }

    fn commit(&self) -> F {
        self.root
    }

    fn data(&self) -> [F; 2] {
        self.leaf
    }
}

#[cfg(test)]
pub mod test {
    use super::*;
    use ark_ff::{Field, UniformRand};
    use ark_relations::r1cs::ConstraintSystem;

    #[test]
    fn hash_sizes() {
        let mut rng = ark_std::test_rng();
        let f1 = F::rand(&mut rng);
        let f2 = F::rand(&mut rng);
        let params = poseidon_config();

        let hash1 = hash_leaf(&params, &[f1, f2]).unwrap();
        let hash2 = compress(&params, &f1, &f2).unwrap();

        let cs = ConstraintSystem::<F>::new_ref();
        let f1v = FpVar::new_input(cs.clone(), || Ok(f1)).unwrap();
        let f2v = FpVar::new_input(cs.clone(), || Ok(f2)).unwrap();
        let params_var = ParamsVar::new_constant(cs.clone(), &params).unwrap();

        let hash = LeafHashG::evaluate(&params_var, &[f1v, f2v]).unwrap();
        assert_eq!(hash1, hash.value().unwrap());
        assert!(cs.is_satisfied().unwrap());
        println!(
            "hash constraints vars:{} + {}, constraints:{}",
            cs.num_instance_variables(),
            cs.num_witness_variables(),
            cs.num_constraints()
        );

        let cs = ConstraintSystem::<F>::new_ref();
        let f1 = FpVar::new_input(cs.clone(), || Ok(f1)).unwrap();
        let f2 = FpVar::new_input(cs.clone(), || Ok(f2)).unwrap();
        let params_var = ParamsVar::new_constant(cs.clone(), &params).unwrap();

        let hash = TwoToOneHashG::compress(&params_var, &f1, &f2).unwrap();
        assert_eq!(hash2, hash.value().unwrap());
        assert!(cs.is_satisfied().unwrap());
        println!(
            "hash constraints vars:{} + {}, constraints:{}",
            cs.num_instance_variables(),
            cs.num_witness_variables(),
            cs.num_constraints()
        );
    }

    pub fn verify_circuit_sat(path: &Path) {
        let params = poseidon_config();
        assert!(path.verify(&params).unwrap());

        let cs = ConstraintSystem::<F>::new_ref();
        let params = ParamsVar::new_constant(cs.clone(), params).unwrap();
        let root = FpVar::new_input(cs.clone(), || Ok(path.root)).unwrap();
        let leaf = [
            FpVar::new_input(cs.clone(), || Ok(path.leaf[0])).unwrap(),
            FpVar::new_input(cs.clone(), || Ok(path.leaf[1])).unwrap(),
        ];
        path.verify_circuit(cs.clone(), &params, &root, &leaf)
            .unwrap();
        assert!(cs.is_satisfied().unwrap());
    }

    pub fn verify_circuit_unsat(path: &Path) {
        let params = poseidon_config();
        assert!(!path.verify(&params).unwrap());

        let cs = ConstraintSystem::<F>::new_ref();
        let params = ParamsVar::new_constant(cs.clone(), params).unwrap();
        let root = FpVar::new_input(cs.clone(), || Ok(path.root)).unwrap();
        let leaf = [
            FpVar::new_input(cs.clone(), || Ok(path.leaf[0])).unwrap(),
            FpVar::new_input(cs.clone(), || Ok(path.leaf[1])).unwrap(),
        ];
        path.verify_circuit(cs.clone(), &params, &root, &leaf)
            .unwrap();
        assert!(!cs.is_satisfied().unwrap());
    }

    // the auth path for an empty tree is the same as the zeros array
    fn empty_path(params: &Params) -> Path {
        let zeros = compute_zeros(params).unwrap();
        let auth = zeros[1..].iter().rev().map(|f| (true, *f)).collect();
        let leaf = CacheLine::default().scalars();
        Path {
            root: zeros[0],
            leaf,
            auth,
        }
    }

    #[test]
    fn path_verify() {
        let params = poseidon_config();
        let mut path = empty_path(&params);
        assert!(path.verify(&params).unwrap());

        path.root += F::ONE;
        assert!(!path.verify(&params).unwrap());
    }

    #[test]
    fn path_verify_circuit() {
        let params = poseidon_config();
        let path = empty_path(&params);
        verify_circuit_sat(&path);
    }

    #[test]
    fn path_verify_circuit_unsat() {
        let params = poseidon_config();
        let mut path = empty_path(&params);

        path.root += F::ONE;
        verify_circuit_unsat(&path);
    }
}
