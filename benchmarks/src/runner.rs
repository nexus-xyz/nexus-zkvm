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
    utils::{phase_end, phase_start, record_benchmark_results},
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

    let (start_time, initial_self, initial_children) = phase_start();

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
        phase_end(start_time, initial_self, initial_children);

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
    let (start_time, initial_self, initial_children) = phase_start();
    let native_duration = measure_native_execution::<T>(&tmp_project_path, &public_input).0;
    let (_, native_user_time, native_sys_time, native_metrics) =
        phase_end(start_time, initial_self, initial_children);

    // Parse and prepare ELF for emulation.
    let elf = ElfFile::from_bytes(&elf_contents).expect("Failed to parse ELF file");

    // Measure emulation.
    let (start_time, initial_self, initial_children) = phase_start();
    let (view, execution_trace) =
        k_trace(elf, &[], &public_input, &private_input, K).expect("error generating trace");
    let (emulation_duration, emulation_user_time, emulation_sys_time, emulation_metrics) =
        phase_end(start_time, initial_self, initial_children);

    // Measure proving.
    let (start_time, initial_self, initial_children) = phase_start();
    let proof = prove(&execution_trace, &view).unwrap();
    let (proving_duration, proving_user_time, proving_sys_time, proving_metrics) =
        phase_end(start_time, initial_self, initial_children);

    // Measure verification.
    let (start_time, initial_self, initial_children) = phase_start();
    verify(proof, &view).unwrap();
    let (
        verification_duration,
        verification_user_time,
        verification_sys_time,
        verification_metrics,
    ) = phase_end(start_time, initial_self, initial_children);

    let total_steps = execution_trace.get_num_steps();
    let total_duration = emulation_duration + proving_duration + verification_duration;
    let total_peak_cpu_percentage = f64::max(
        f64::max(native_metrics.peak_cpu, emulation_metrics.peak_cpu),
        f64::max(proving_metrics.peak_cpu, verification_metrics.peak_cpu),
    );
    let total_peak_memory_gb = f64::max(
        f64::max(
            native_metrics.peak_memory_gb,
            emulation_metrics.peak_memory_gb,
        ),
        f64::max(
            proving_metrics.peak_memory_gb,
            verification_metrics.peak_memory_gb,
        ),
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
                    MemoryRecord::LoadRecord(.., _) => (loads + 1, stores),
                    MemoryRecord::StoreRecord(.., _) => (loads, stores + 1),
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
        total_speed_khz: (total_steps as f32 / total_duration.as_secs_f32()) / 1_000.0,
        total_duration,
        total_steps: total_steps as u32,
        cpu_cores,
        total_ram_gb,
        total_peak_cpu_percentage,
        total_peak_memory_gb,
        num_loads,
        num_stores,
        stack_size,
        heap_size,
        native: StageStats {
            duration: native_duration,
            sys_time: native_sys_time,
            user_time: native_user_time,
            peak_cpu_percentage: native_metrics.peak_cpu,
            peak_memory_gb: native_metrics.peak_memory_gb,
            speed_khz: (total_steps as f32 / native_duration.as_secs_f32()) / 1_000.0,
            overhead: 1.0,
        },
        emulation: StageStats {
            duration: emulation_duration,
            sys_time: emulation_sys_time,
            user_time: emulation_user_time,
            peak_cpu_percentage: emulation_metrics.peak_cpu,
            peak_memory_gb: emulation_metrics.peak_memory_gb,
            speed_khz: (total_steps as f32 / emulation_duration.as_secs_f32()) / 1_000.0,
            overhead: emulation_duration.as_secs_f32() / native_duration.as_secs_f32(),
        },
        proving: StageStats {
            duration: proving_duration,
            sys_time: proving_sys_time,
            user_time: proving_user_time,
            peak_cpu_percentage: proving_metrics.peak_cpu,
            peak_memory_gb: proving_metrics.peak_memory_gb,
            speed_khz: (total_steps as f32 / proving_duration.as_secs_f32()) / 1_000.0,
            overhead: proving_duration.as_secs_f32() / native_duration.as_secs_f32(),
        },
        verification: StageStats {
            duration: verification_duration,
            sys_time: verification_sys_time,
            user_time: verification_user_time,
            peak_cpu_percentage: verification_metrics.peak_cpu,
            peak_memory_gb: verification_metrics.peak_memory_gb,
            speed_khz: (total_steps as f32 / verification_duration.as_secs_f32()) / 1_000.0,
            overhead: verification_duration.as_secs_f32() / native_duration.as_secs_f32(),
        },
    };

    record_benchmark_results(&result, results_file);
}
