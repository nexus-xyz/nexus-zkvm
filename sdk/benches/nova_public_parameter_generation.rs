use criterion::{criterion_group, criterion_main, Criterion};
use nexus_sdk::nova;
use nexus_sdk::Parameters;

fn nova_public_parameter_generation() {
    nova::seq::PP::generate_for_testing().expect("Failed to generate Nova public parameters");
}

fn bench_nova_public_parameter(c: &mut Criterion) {
    c.bench_function("nova_public_parameter", |b| {
        b.iter(|| nova_public_parameter_generation())
    });
}

criterion_group!(
    name = benches;
    config = Criterion::default().significance_level(0.1).sample_size(10);
    targets = bench_nova_public_parameter);

criterion_main!(benches);
