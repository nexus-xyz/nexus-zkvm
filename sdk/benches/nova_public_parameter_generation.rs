use divan::AllocProfiler;
use nexus_sdk::nova;
use nexus_sdk::Parameters;

#[global_allocator]
static ALLOC: AllocProfiler = AllocProfiler::system();

fn nova_public_parameter_generation(k: usize) {
    nova::seq::PP::generate_for_testing(k).expect("Failed to generate Nova public parameters");
}

#[divan::bench(args = [1, 2, 4], max_time = 10)]
fn bench_nova_public_parameter(k: usize) {
    nova_public_parameter_generation(k);
}

fn main() {
    divan::main();
}
