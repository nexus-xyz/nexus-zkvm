use ark_crypto_primitives::sponge::poseidon::{find_poseidon_ark_and_mds, PoseidonConfig};
use ark_ff::PrimeField;

pub use ark_crypto_primitives::sponge::poseidon::{constraints::PoseidonSpongeVar, PoseidonSponge};

/// Returns config for poseidon sponge with 128-bit security.
pub fn poseidon_config<F: PrimeField>() -> PoseidonConfig<F> {
    const FULL_ROUNDS: usize = 8;
    const PARTIAL_ROUNDS: usize = 57;
    const ALPHA: u64 = 5;
    const RATE: usize = 2;
    const CAPACITY: usize = 1;

    let (ark, mds) = find_poseidon_ark_and_mds::<F>(
        F::MODULUS_BIT_SIZE as u64,
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
