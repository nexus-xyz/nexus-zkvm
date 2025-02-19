#![feature(test)]
#![cfg(test)]

extern crate test;

use nexus_benchmarks::{runner::run_benchmark, utils::get_timestamped_filename};
use nexus_common_testing::emulator::EmulatorType;
use postcard::to_allocvec_cobs;
use test::Bencher;

#[test]
#[ignore]
fn test_benchmark_fib_simple() {
    let results_file = get_timestamped_filename("benchmark_results");
    run_benchmark::<u32>(
        "../examples/src/bin/fib",
        "-C opt-level=3",
        EmulatorType::TwoPass,
        Vec::new(),
        Vec::new(),
        &results_file,
        20,
    );
}

#[test]
#[ignore]
fn test_benchmark_fib_powers() {
    // Inputs corresponding to step count powers of 2 from 2^12 to 2^19.
    let inputs = vec![6, 16, 37, 77, 121, 262, 489, 999];
    let results_file = get_timestamped_filename("fib_powers");
    for mut input in inputs {
        let public_input_bytes = to_allocvec_cobs(&mut input).unwrap();
        run_benchmark::<u32>(
            "../examples/src/bin/fib_input",
            "-C opt-level=3",
            EmulatorType::TwoPass,
            public_input_bytes,
            Vec::new(),
            &results_file,
            20,
        );
    }
}

#[test]
#[ignore]
fn test_benchmark_keccak_powers() {
    // Inputs corresponding to step count powers of 2 from 2^15 to 2^19.
    let inputs = vec![0, 1, 3, 7, 15];
    let results_file = get_timestamped_filename("keccak_powers");
    for mut input in inputs {
        let public_input_bytes = to_allocvec_cobs(&mut input).unwrap();
        run_benchmark::<u32>(
            "../examples/src/bin/keccak_input",
            "-C opt-level=3",
            EmulatorType::TwoPass,
            public_input_bytes,
            Vec::new(),
            &results_file,
            20,
        );
    }
}

/// Benchmark Harvard emulator performance.
#[bench]
fn bench_harvard_fib1000(b: &mut Bencher) {
    let results_file = get_timestamped_filename("benchmark_results");
    b.iter(|| {
        run_benchmark::<u32>(
            "../examples/src/bin/fib1000",
            "-C opt-level=3",
            EmulatorType::Harvard,
            Vec::new(),
            Vec::new(),
            &results_file,
            20,
        );
    });
}

/// Benchmark Linear emulator performance.
#[bench]
fn bench_linear_fib1000(b: &mut Bencher) {
    let results_file = get_timestamped_filename("benchmark_results");
    b.iter(|| {
        run_benchmark::<u32>(
            "../examples/src/bin/fib1000",
            "-C opt-level=3",
            EmulatorType::default_linear(),
            Vec::new(),
            Vec::new(),
            &results_file,
            20,
        );
    });
}

/// Benchmark Two-Pass emulator performance.
#[bench]
fn bench_twopass_fib1000(b: &mut Bencher) {
    let results_file = get_timestamped_filename("benchmark_results");
    b.iter(|| {
        run_benchmark::<u32>(
            "../examples/src/bin/fib1000",
            "-C opt-level=3",
            EmulatorType::TwoPass,
            Vec::new(),
            Vec::new(),
            &results_file,
            20,
        );
    });
}
