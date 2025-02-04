#![feature(test)]
#![cfg(test)]

extern crate test;

use libc::{getrusage, rusage, RUSAGE_CHILDREN, RUSAGE_SELF};
use nexus_common_testing::emulator::{
    compile_to_elf, create_tmp_dir, emulate, setup_project, EmulatorType,
};
use nexus_vm::elf::ElfFile;
use std::{
    fs::OpenOptions,
    io::Write,
    path::PathBuf,
    process::Command,
    time::{Duration, Instant},
};
use test::Bencher;

/// Performance metrics collected during benchmarking.
#[derive(Debug)]
struct BenchmarkMetrics {
    /// Guest CPU cycles per second in MHz.
    cycle_mega_hz: f32,
    /// Ratio of emulation time to native execution time.
    overhead: f32,
    /// Time taken by native execution.
    native_duration: Duration,
    /// Time taken by emulated execution.
    emulation_duration: Duration,
    /// Native execution system CPU time.
    native_sys_time: Duration,
    /// Native execution user CPU time.
    native_user_time: Duration,
    /// Emulation system CPU time.
    emulation_sys_time: Duration,
    /// Emulation user CPU time.
    emulation_user_time: Duration,
}

/// Executes and measures the native execution speed of a Rust program.
fn measure_native_execution(path: &PathBuf) -> (Duration, Duration, Duration) {
    // Build with release optimizations.
    let output = Command::new("cargo")
        .current_dir(path)
        .arg("build")
        .arg("--release")
        .output()
        .expect("Failed to build project");

    assert!(output.status.success(), "Native build failed");

    let start_usage = start_timer(RUSAGE_CHILDREN);
    let start = Instant::now();

    let output = Command::new("cargo")
        .current_dir(path)
        .arg("run")
        .arg("--release")
        .output()
        .expect("Failed to run project");

    assert!(output.status.success(), "Native execution failed");

    let total_time = start.elapsed();
    let (user_time, sys_time) = stop_timer(&start_usage, RUSAGE_CHILDREN);

    (total_time, user_time, sys_time)
}

/// Records benchmark results to a CSV file for analysis.
fn record_benchmark_results(metrics: &BenchmarkMetrics, test: &str, emulator_type: EmulatorType) {
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open("benchmark_results.csv")
        .expect("Failed to open benchmark_results.csv");

    // Write header if file is empty.
    if file.metadata().unwrap().len() == 0 {
        writeln!(
            file,
            "cycle_mega_hz,overhead,native_duration,emulation_duration,native_sys_time,native_user_time,emulation_sys_time,emulation_user_time,test,emulator_type,timestamp"
        )
        .expect("Failed to write CSV header");
    }

    // Record results with emulator-specific naming.
    let emulator_name = match emulator_type {
        EmulatorType::Harvard => "Harvard",
        EmulatorType::Linear(_, _, _) => "Linear",
        EmulatorType::TwoPass => "TwoPass",
    };

    writeln!(
        file,
        "{},{},{},{},{},{},{},{},{},{},{}",
        metrics.cycle_mega_hz,
        metrics.overhead,
        metrics.native_duration.as_secs_f32(),
        metrics.emulation_duration.as_secs_f32(),
        metrics.native_sys_time.as_secs_f32(),
        metrics.native_user_time.as_secs_f32(),
        metrics.emulation_sys_time.as_secs_f32(),
        metrics.emulation_user_time.as_secs_f32(),
        test,
        emulator_name,
        chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string()
    )
    .expect("Failed to write benchmark results");
}

/// Benchmarks a test program using specified emulator configuration.
fn run_benchmark(
    test: &str,
    compile_flags: &str,
    emulator_type: EmulatorType,
    public_input: Vec<u8>,
    private_input: Vec<u8>,
    output: Vec<u8>,
) {
    // Set up temporary project directory.
    let tmp_dir = create_tmp_dir();
    let tmp_project_path = tmp_dir.path().join("integration");

    // Compile test to RISC-V ELF.
    let test_dir_path = "../integration-tests";
    let test_path = format!("{test_dir_path}/{test}.rs");
    setup_project(&tmp_project_path, &test_path);
    let elf_contents = compile_to_elf(&tmp_project_path, compile_flags);

    // Measure native execution time.
    let (native_duration, native_user_time, native_sys_time) =
        measure_native_execution(&tmp_project_path);

    // Parse and prepare ELF for emulation.
    let elf = ElfFile::from_bytes(&elf_contents).expect("Failed to parse ELF file");

    // Measure emulation time.
    let start_usage = start_timer(RUSAGE_SELF);
    let start = Instant::now();
    let (cycles, _, _) = emulate(
        vec![elf],
        public_input,
        private_input,
        output.len(),
        emulator_type.clone(),
    );
    let emulation_duration = start.elapsed();
    let (emulation_user_time, emulation_sys_time) = stop_timer(&start_usage, RUSAGE_SELF);

    // Calculate performance metrics.
    let metrics = BenchmarkMetrics {
        cycle_mega_hz: (cycles[0] as f32 / emulation_duration.as_secs_f32()) / 1_000_000.0,
        overhead: emulation_duration.as_secs_f32() / native_duration.as_secs_f32(),
        native_duration,
        emulation_duration,
        native_sys_time,
        native_user_time,
        emulation_sys_time,
        emulation_user_time,
    };

    record_benchmark_results(&metrics, test, emulator_type);
}

#[test]
fn test_benchmark_harvard() {
    // Delete any existing benchmark results file.
    if let Ok(_) = OpenOptions::new().write(true).open("benchmark_results.csv") {
        std::fs::remove_file("benchmark_results.csv")
            .expect("Failed to delete benchmark results file");
    }
    run_benchmark(
        "../../examples/src/fib1000",
        "-C opt-level=3",
        EmulatorType::Harvard,
        Vec::new(),
        Vec::new(),
        Vec::new(),
    );
}

/// Benchmark Harvard emulator performance.
#[bench]
fn bench_harvard_fib1000(b: &mut Bencher) {
    b.iter(|| {
        run_benchmark(
            "../../examples/src/fib1000",
            "-C opt-level=3",
            EmulatorType::Harvard,
            Vec::new(),
            Vec::new(),
            Vec::new(),
        );
    });
}

/// Benchmark Linear emulator performance.
#[bench]
fn bench_linear_fib1000(b: &mut Bencher) {
    b.iter(|| {
        run_benchmark(
            "../../examples/src/fib1000",
            "-C opt-level=3",
            EmulatorType::default_linear(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
        );
    });
}

/// Benchmark Two-Pass emulator performance.
#[bench]
fn bench_twopass_fib1000(b: &mut Bencher) {
    b.iter(|| {
        run_benchmark(
            "../../examples/src/fib1000",
            "-C opt-level=3",
            EmulatorType::TwoPass,
            Vec::new(),
            Vec::new(),
            Vec::new(),
        );
    });
}

/// Start timing and return resource usage
fn start_timer(usage_type: i32) -> rusage {
    let mut usage: rusage = unsafe { std::mem::zeroed() };
    unsafe { getrusage(usage_type, &mut usage) };
    usage
}

/// Stop timing and return user and system time differences
fn stop_timer(start_usage: &rusage, usage_type: i32) -> (Duration, Duration) {
    let mut end_usage: rusage = unsafe { std::mem::zeroed() };
    unsafe { getrusage(usage_type, &mut end_usage) };
    calculate_time_diff(start_usage, &end_usage)
}

/// Calculate user and system time differences between two rusage measurements
fn calculate_time_diff(start_usage: &rusage, end_usage: &rusage) -> (Duration, Duration) {
    let user_sec_diff = end_usage.ru_utime.tv_sec - start_usage.ru_utime.tv_sec;
    let user_usec_diff = end_usage.ru_utime.tv_usec - start_usage.ru_utime.tv_usec;

    let sys_sec_diff = end_usage.ru_stime.tv_sec - start_usage.ru_stime.tv_sec;
    let sys_usec_diff = end_usage.ru_stime.tv_usec - start_usage.ru_stime.tv_usec;

    // Handle negative microsecond differences by borrowing from seconds
    let (user_sec, user_usec) = if user_usec_diff < 0 {
        (user_sec_diff - 1, user_usec_diff + 1_000_000)
    } else {
        (user_sec_diff, user_usec_diff)
    };

    let (sys_sec, sys_usec) = if sys_usec_diff < 0 {
        (sys_sec_diff - 1, sys_usec_diff + 1_000_000)
    } else {
        (sys_sec_diff, sys_usec_diff)
    };

    let user_time = Duration::from_secs(user_sec as u64) + Duration::from_micros(user_usec as u64);
    let sys_time = Duration::from_secs(sys_sec as u64) + Duration::from_micros(sys_usec as u64);

    (user_time, sys_time)
}
