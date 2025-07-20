use chrono;
use nexus_common::memory::traits::MemoryRecord;
use nexus_common_testing::emulator::{
    compile_guest_project, setup_guest_project, write_guest_source_code, EmulatorType,
};
use nexus_vm::elf::ElfFile;
use nexus_vm::trace::{k_trace, Trace};
use nexus_vm_prover::{prove, verify};
use num_cpus;
use postcard;
use serde::{de::DeserializeOwned, Serialize};
use std::{path::PathBuf, process::Command, time::Duration};
use sys_info;
use sysinfo::System;

use crate::{
    models::{BenchmarkResult, StageStats},
    utils::{phase_end, phase_start, record_benchmark_results, PhasesTracker},
};

const K: usize = 1;

/// Executes and measures the native execution speed of a Rust program.
fn measure_native_execution<T>(
    path: &PathBuf,
    public_input_bytes: &[u8],
) -> (Duration, Duration, Duration)
where
    T: DeserializeOwned + Serialize + std::fmt::Display,
{
    // Build with release optimizations.
    let output = Command::new("cargo")
        .current_dir(path)
        .arg("build")
        .arg("--release")
        .output()
        .expect("Failed to build project");

    assert!(
        output.status.success(),
        "Native build failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let timing_state = phase_start();

    // Simpler run process when no inputs are provided.
    let output = if public_input_bytes.is_empty() {
        Command::new("cargo")
            .current_dir(path)
            .arg("run")
            .arg("--release")
            .output()
            .expect("Failed to spawn process")
    } else {
        let mut child = Command::new("cargo")
            .current_dir(path)
            .arg("run")
            .arg("--release")
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .spawn()
            .expect("Failed to spawn process");

        // Pipe in input as stdin.
        let input: T = postcard::from_bytes_cobs(&mut public_input_bytes.to_owned())
            .expect("Failed to deserialize input");
        let input_str = format!("{}\n", input);
        if let Some(mut stdin) = child.stdin.take() {
            use std::io::Write;
            stdin
                .write_all(input_str.as_bytes())
                .expect("Failed to write to stdin");
        }

        child.wait_with_output().expect("Failed to wait on child")
    };

    assert!(output.status.success(), "Native execution failed");

    let (total_time, user_time, sys_time, _) =
        phase_end(timing_state);

    (total_time, user_time, sys_time)
}

/// Benchmarks a test program using specified emulator configuration.
pub fn run_benchmark<T>(
    test: &str,
    compile_flags: &str,
    emulator_type: EmulatorType,
    public_input: Vec<u8>,
    private_input: Vec<u8>,
    results_file: &str,
    iters: u32,
) where
    T: DeserializeOwned + Serialize + std::fmt::Display,
{
    // Get system info at start.
    let cpu_cores = num_cpus::get();
    let total_ram_gb = sys_info::mem_info()
        .map(|m| (m.total as f64) / (1024.0 * 1024.0))
        .unwrap_or(0.0);

    // Initialize system monitoring.
    let mut sys = System::new_all();
    sys.refresh_all();

    // Set up temporary project directory.
    let runtime_path = PathBuf::from("../runtime");
    let tmp_dir = setup_guest_project(&runtime_path);
    let tmp_project_path = tmp_dir.path().join("integration");

    // Compile test to RISC-V ELF.
    write_guest_source_code(&tmp_project_path, &format!("{}.rs", test));
    let elf_contents = compile_guest_project(
        &tmp_project_path,
        &runtime_path.join("linker-scripts/default.x"),
        compile_flags,
    );

    // Measure native execution.
    let mut native_tracker = PhasesTracker::default();
    for _ in 0..iters {
        let timing_state = phase_start();
        let native_duration = measure_native_execution::<T>(&tmp_project_path, &public_input).0;
        let (_, native_user_time, native_sys_time, native_metrics) =
            phase_end(timing_state);

        native_tracker.update(
            &native_duration,
            &native_user_time,
            &native_sys_time,
            &native_metrics,
        );
    }

    // Parse and prepare ELF for emulation.
    let elf = ElfFile::from_bytes(&elf_contents).expect("Failed to parse ELF file");

    // Measure emulation.
    let (mut view, mut execution_trace) =
        k_trace(elf.clone(), &[], &public_input, &private_input, K)
            .expect("error generating trace"); // warm up and make sure we work

    let mut emulation_tracker = PhasesTracker::default();
    for _ in 0..iters {
        let iter_elf = elf.clone();

        let timing_state = phase_start();
        (view, execution_trace) = k_trace(iter_elf, &[], &public_input, &private_input, K)
            .expect("error generating trace");
        let (emulation_duration, emulation_user_time, emulation_sys_time, emulation_metrics) =
            phase_end(timing_state);

        emulation_tracker.update(
            &emulation_duration,
            &emulation_user_time,
            &emulation_sys_time,
            &emulation_metrics,
        );
    }

    // Measure proving.
    let mut proof = prove(&execution_trace, &view).unwrap(); // warm up and make sure we work

    let mut proving_tracker = PhasesTracker::default();
    for _ in 0..iters {
        let timing_state = phase_start();
        proof = prove(&execution_trace, &view).unwrap();
        let (proving_duration, proving_user_time, proving_sys_time, proving_metrics) =
            phase_end(timing_state);

        proving_tracker.update(
            &proving_duration,
            &proving_user_time,
            &proving_sys_time,
            &proving_metrics,
        );
    }

    // Measure verification.
    let mut verification_tracker = PhasesTracker::default();
    for _ in 0..iters {
        let iter_proof = proof.clone();

        let timing_state = phase_start();
        verify(iter_proof, &view).unwrap();
        let (
            verification_duration,
            verification_user_time,
            verification_sys_time,
            verification_metrics,
        ) = phase_end(timing_state);

        verification_tracker.update(
            &verification_duration,
            &verification_user_time,
            &verification_sys_time,
            &verification_metrics,
        );
    }

    let total_steps = execution_trace.get_num_steps();

    let piecewise_min_total_duration =
        emulation_tracker.duration.min + proving_tracker.duration.min;
    let piecewise_min_total_overhead =
        piecewise_min_total_duration.div_duration_f32(native_tracker.duration.max); // min over max for min overhead
    let piecewise_min_total_peak_cpu_percentage = f64::max(
        f64::max(
            native_tracker.metrics.min.peak_cpu,
            emulation_tracker.metrics.min.peak_cpu,
        ),
        proving_tracker.metrics.min.peak_cpu,
    );
    let piecewise_min_total_peak_memory_gb = f64::max(
        f64::max(
            native_tracker.metrics.min.peak_memory_gb,
            emulation_tracker.metrics.min.peak_memory_gb,
        ),
        proving_tracker.metrics.min.peak_memory_gb,
    );

    let avg_total_duration = emulation_tracker.duration.avg + proving_tracker.duration.avg;
    let avg_total_overhead = avg_total_duration.div_duration_f32(native_tracker.duration.avg);
    let avg_total_peak_cpu_percentage = f64::max(
        f64::max(
            native_tracker.metrics.avg.peak_cpu,
            emulation_tracker.metrics.avg.peak_cpu,
        ),
        proving_tracker.metrics.avg.peak_cpu,
    );
    let avg_total_peak_memory_gb = f64::max(
        f64::max(
            native_tracker.metrics.avg.peak_memory_gb,
            emulation_tracker.metrics.avg.peak_memory_gb,
        ),
        proving_tracker.metrics.avg.peak_memory_gb,
    );

    let piecewise_max_total_duration =
        emulation_tracker.duration.max + proving_tracker.duration.max;
    let piecewise_max_total_overhead =
        piecewise_max_total_duration.div_duration_f32(native_tracker.duration.min); // max over min for max overhead
    let piecewise_max_total_peak_cpu_percentage = f64::max(
        f64::max(
            native_tracker.metrics.max.peak_cpu,
            emulation_tracker.metrics.max.peak_cpu,
        ),
        proving_tracker.metrics.max.peak_cpu,
    );
    let piecewise_max_total_peak_memory_gb = f64::max(
        f64::max(
            native_tracker.metrics.max.peak_memory_gb,
            emulation_tracker.metrics.max.peak_memory_gb,
        ),
        proving_tracker.metrics.max.peak_memory_gb,
    );

    // Count loads and stores.
    let (num_loads, num_stores) = execution_trace
        .blocks
        .iter()
        .flat_map(|block| block.steps.iter())
        .fold((0, 0), |(loads, stores), step| {
            step.memory_records
                .iter()
                .fold((loads, stores), |(loads, stores), record| match record {
                    MemoryRecord::LoadRecord(..) => (loads + 1, stores),
                    MemoryRecord::StoreRecord(..) => (loads, stores + 1),
                })
        });

    // Calculate stack and heap sizes.
    let stack_size = execution_trace.get_memory_layout().stack_top()
        - execution_trace.get_memory_layout().stack_bottom();
    let heap_size = execution_trace.get_memory_layout().heap_end()
        - execution_trace.get_memory_layout().heap_start();

    // Get emulator name.
    let emulator_name = match emulator_type {
        EmulatorType::Harvard => "Harvard",
        EmulatorType::Linear(_, _, _) => "Linear",
        EmulatorType::TwoPass => "TwoPass",
    };

    let result = BenchmarkResult {
        timestamp: chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string(),
        test: test.to_string(),
        emulator_type: emulator_name.to_string(),
        piecewise_min_total_speed_khz: (total_steps as f32
            / piecewise_min_total_duration.as_secs_f32())
            / 1_000.0,
        piecewise_min_total_duration,
        piecewise_min_total_overhead,
        avg_total_speed_khz: (total_steps as f32 / avg_total_duration.as_secs_f32()) / 1_000.0,
        avg_total_duration,
        avg_total_overhead,
        piecewise_max_total_speed_khz: (total_steps as f32
            / piecewise_max_total_duration.as_secs_f32())
            / 1_000.0,
        piecewise_max_total_duration,
        piecewise_max_total_overhead,
        total_steps: total_steps as u32,
        cpu_cores,
        total_ram_gb,
        piecewise_min_total_peak_cpu_percentage,
        piecewise_min_total_peak_memory_gb,
        avg_total_peak_cpu_percentage,
        avg_total_peak_memory_gb,
        piecewise_max_total_peak_cpu_percentage,
        piecewise_max_total_peak_memory_gb,
        num_loads,
        num_stores,
        stack_size,
        heap_size,
        native_mins: StageStats {
            duration: native_tracker.duration.min,
            sys_time: native_tracker.sys.min,
            user_time: native_tracker.user.min,
            peak_cpu_percentage: native_tracker.metrics.min.peak_cpu,
            peak_memory_gb: native_tracker.metrics.min.peak_memory_gb,
            speed_khz: (total_steps as f32 / native_tracker.duration.min.as_secs_f32()) / 1_000.0,
            overhead: 1.0,
        },
        native_avgs: StageStats {
            duration: native_tracker.duration.avg,
            sys_time: native_tracker.sys.avg,
            user_time: native_tracker.user.avg,
            peak_cpu_percentage: native_tracker.metrics.avg.peak_cpu,
            peak_memory_gb: native_tracker.metrics.avg.peak_memory_gb,
            speed_khz: (total_steps as f32 / native_tracker.duration.avg.as_secs_f32()) / 1_000.0,
            overhead: 1.0,
        },
        native_maxs: StageStats {
            duration: native_tracker.duration.max,
            sys_time: native_tracker.sys.max,
            user_time: native_tracker.user.max,
            peak_cpu_percentage: native_tracker.metrics.max.peak_cpu,
            peak_memory_gb: native_tracker.metrics.max.peak_memory_gb,
            speed_khz: (total_steps as f32 / native_tracker.duration.max.as_secs_f32()) / 1_000.0,
            overhead: 1.0,
        },
        emulation_mins: StageStats {
            duration: emulation_tracker.duration.min,
            sys_time: emulation_tracker.sys.min,
            user_time: emulation_tracker.user.min,
            peak_cpu_percentage: emulation_tracker.metrics.min.peak_cpu,
            peak_memory_gb: emulation_tracker.metrics.min.peak_memory_gb,
            speed_khz: (total_steps as f32 / emulation_tracker.duration.min.as_secs_f32())
                / 1_000.0,
            overhead: emulation_tracker.duration.min.as_secs_f32()
                / native_tracker.duration.max.as_secs_f32(), // min over max for min overhead
        },
        emulation_avgs: StageStats {
            duration: emulation_tracker.duration.avg,
            sys_time: emulation_tracker.sys.avg,
            user_time: emulation_tracker.user.avg,
            peak_cpu_percentage: emulation_tracker.metrics.avg.peak_cpu,
            peak_memory_gb: emulation_tracker.metrics.avg.peak_memory_gb,
            speed_khz: (total_steps as f32 / emulation_tracker.duration.avg.as_secs_f32())
                / 1_000.0,
            overhead: emulation_tracker.duration.avg.as_secs_f32()
                / native_tracker.duration.avg.as_secs_f32(),
        },
        emulation_maxs: StageStats {
            duration: emulation_tracker.duration.max,
            sys_time: emulation_tracker.sys.max,
            user_time: emulation_tracker.user.max,
            peak_cpu_percentage: emulation_tracker.metrics.max.peak_cpu,
            peak_memory_gb: emulation_tracker.metrics.max.peak_memory_gb,
            speed_khz: (total_steps as f32 / emulation_tracker.duration.max.as_secs_f32())
                / 1_000.0,
            overhead: emulation_tracker.duration.max.as_secs_f32()
                / native_tracker.duration.min.as_secs_f32(), // max over min for max overhead
        },
        proving_mins: StageStats {
            duration: proving_tracker.duration.min,
            sys_time: proving_tracker.sys.min,
            user_time: proving_tracker.user.min,
            peak_cpu_percentage: proving_tracker.metrics.min.peak_cpu,
            peak_memory_gb: proving_tracker.metrics.min.peak_memory_gb,
            speed_khz: (total_steps as f32 / proving_tracker.duration.min.as_secs_f32()) / 1_000.0,
            overhead: f32::NAN,
        },
        proving_avgs: StageStats {
            duration: proving_tracker.duration.avg,
            sys_time: proving_tracker.sys.avg,
            user_time: proving_tracker.user.avg,
            peak_cpu_percentage: proving_tracker.metrics.avg.peak_cpu,
            peak_memory_gb: proving_tracker.metrics.avg.peak_memory_gb,
            speed_khz: (total_steps as f32 / proving_tracker.duration.avg.as_secs_f32()) / 1_000.0,
            overhead: f32::NAN,
        },
        proving_maxs: StageStats {
            duration: proving_tracker.duration.max,
            sys_time: proving_tracker.sys.max,
            user_time: proving_tracker.user.max,
            peak_cpu_percentage: proving_tracker.metrics.max.peak_cpu,
            peak_memory_gb: proving_tracker.metrics.max.peak_memory_gb,
            speed_khz: (total_steps as f32 / proving_tracker.duration.max.as_secs_f32()) / 1_000.0,
            overhead: f32::NAN,
        },
        verification_mins: StageStats {
            duration: verification_tracker.duration.min,
            sys_time: verification_tracker.sys.min,
            user_time: verification_tracker.user.min,
            peak_cpu_percentage: verification_tracker.metrics.min.peak_cpu,
            peak_memory_gb: verification_tracker.metrics.min.peak_memory_gb,
            speed_khz: (total_steps as f32 / verification_tracker.duration.min.as_secs_f32())
                / 1_000.0,
            overhead: f32::NAN,
        },
        verification_avgs: StageStats {
            duration: verification_tracker.duration.avg,
            sys_time: verification_tracker.sys.avg,
            user_time: verification_tracker.user.avg,
            peak_cpu_percentage: verification_tracker.metrics.avg.peak_cpu,
            peak_memory_gb: verification_tracker.metrics.avg.peak_memory_gb,
            speed_khz: (total_steps as f32 / verification_tracker.duration.avg.as_secs_f32())
                / 1_000.0,
            overhead: f32::NAN,
        },
        verification_maxs: StageStats {
            duration: verification_tracker.duration.max,
            sys_time: verification_tracker.sys.max,
            user_time: verification_tracker.user.max,
            peak_cpu_percentage: verification_tracker.metrics.max.peak_cpu,
            peak_memory_gb: verification_tracker.metrics.max.peak_memory_gb,
            speed_khz: (total_steps as f32 / verification_tracker.duration.max.as_secs_f32())
                / 1_000.0,
            overhead: f32::NAN,
        },
    };

    record_benchmark_results(&result, results_file);
}
