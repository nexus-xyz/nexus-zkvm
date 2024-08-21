use ark_crypto_primitives::sponge::poseidon::PoseidonSponge;
use ark_pallas::{Fr as CF, PallasConfig as G1};
use ark_vesta::VestaConfig as G2;
use criterion::{criterion_group, criterion_main, Criterion};
use nexus_nova::{nova::sequential::PublicParams, pedersen::PedersenCommitment, poseidon_config};

mod shared;
use shared::NonTrivialTestCircuit;

type C1 = PedersenCommitment<ark_pallas::Projective>;
type C2 = PedersenCommitment<ark_vesta::Projective>;

fn nova_public_parameter_generation() {
    let step_circuit = NonTrivialTestCircuit::new(0);
    PublicParams::<G1, G2, C1, C2, PoseidonSponge<CF>, NonTrivialTestCircuit<CF>>::setup(
        poseidon_config(),
        &step_circuit,
        &(),
        &(),
    )
    .unwrap();
}

fn bench_nova_public_parameter(c: &mut Criterion) {
    c.bench_function("nova_public_parameter", |b| {
        b.iter(nova_public_parameter_generation)
    });
}

criterion_group! {
    name = benches;
    config = Criterion::default().significance_level(0.1).sample_size(10);
    targets = bench_nova_public_parameter
}

criterion_main!(benches);
