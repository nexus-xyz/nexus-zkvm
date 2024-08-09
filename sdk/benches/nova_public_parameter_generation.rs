use divan::AllocProfiler;
use nexus_sdk::nova;
use nexus_sdk::Parameters;

#[global_allocator]
static ALLOC: AllocProfiler = AllocProfiler::system();

fn nova_public_parameter_generation() {
    nova::seq::PP::generate_for_testing().expect("Failed to generate Nova public parameters");
}

#[divan::bench]
fn bench_nova_public_parameter() {
    nova_public_parameter_generation();
}

fn main() {
    divan::main();
}
