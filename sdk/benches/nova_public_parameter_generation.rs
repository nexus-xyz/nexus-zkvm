use iai_callgrind::{library_benchmark, library_benchmark_group, main};
use nexus_sdk::nova;
use nexus_sdk::Parameters;

fn nova_public_parameter_generation() {
    nova::seq::PP::generate_for_testing().expect("Failed to generate Nova public parameters");
}

#[library_benchmark]
fn bench_nova_public_parameter() -> () {
    nova_public_parameter_generation()
}

library_benchmark_group!(
    name = nova_public_parameter;
    benchmarks = bench_nova_public_parameter
);

main!(library_benchmark_groups = nova_public_parameter);
