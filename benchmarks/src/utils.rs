#[cfg(unix)]
use libc::{getrusage, rusage, RUSAGE_CHILDREN, RUSAGE_SELF};
use std::{fs::OpenOptions, io::Write};

use crate::{models::BenchmarkResult, paths::results_file};

/// Cross-platform timing state
#[cfg(unix)]
pub type TimingState = (std::time::Instant, rusage, rusage);
#[cfg(windows)]
pub type TimingState = std::time::Instant;

/// Gets a timestamped version of a filename by appending timestamp and .csv extension.
pub fn get_timestamped_filename(base_name: &str) -> String {
    let timestamp = chrono::Local::now().format("%Y-%m-%d_%H-%M-%S").to_string();
    format!("{}_{}.csv", base_name, timestamp)
}

/// Records benchmark results to a CSV file in the results directory.
pub fn record_benchmark_results(result: &BenchmarkResult, filename: &str) {
    let file_path = results_file(filename);
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&file_path)
        .unwrap_or_else(|_| panic!("Failed to open {}", file_path.display()));

    // Write header if file is empty.
    if file.metadata().unwrap().len() == 0 {
        writeln!(file, "{}", BenchmarkResult::csv_header()).expect("Failed to write CSV header");
    }

    writeln!(file, "{}", result).expect("Failed to write benchmark results");
}

/// Start timing and return resource usage.
#[cfg(unix)]
pub fn start_timer(usage_type: i32) -> rusage {
    let mut usage: rusage = unsafe { std::mem::zeroed() };
    unsafe { getrusage(usage_type, &mut usage) };
    usage
}

/// Start timing and return resource usage (Windows stub).
#[cfg(windows)]
pub fn start_timer(_usage_type: i32) -> std::time::Instant {
    std::time::Instant::now()
}

/// Stop timing and return user and system time differences.
#[cfg(unix)]
pub fn stop_timer(
    start_usage: &rusage,
    usage_type: i32,
) -> (std::time::Duration, std::time::Duration) {
    let mut end_usage: rusage = unsafe { std::mem::zeroed() };
    unsafe { getrusage(usage_type, &mut end_usage) };
    calculate_time_diff(start_usage, &end_usage)
}

/// Stop timing and return user and system time differences (Windows stub).
#[cfg(windows)]
pub fn stop_timer(
    start_time: &std::time::Instant,
    _usage_type: i32,
) -> (std::time::Duration, std::time::Duration) {
    let elapsed = start_time.elapsed();
    // On Windows, we can't easily separate user and system time, so return elapsed time for both
    (elapsed, std::time::Duration::ZERO)
}

/// Calculate user and system time differences between two rusage measurements.
#[cfg(unix)]
pub fn calculate_time_diff(
    start_usage: &rusage,
    end_usage: &rusage,
) -> (std::time::Duration, std::time::Duration) {
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

    let user_time = std::time::Duration::from_secs(user_sec as u64)
        + std::time::Duration::from_micros(user_usec as u64);
    let sys_time = std::time::Duration::from_secs(sys_sec as u64)
        + std::time::Duration::from_micros(sys_usec as u64);

    (user_time, sys_time)
}

/// Helper struct to track resource usage during a phase.
#[derive(Debug, Default, Clone, Copy)]
pub struct PhaseMetrics {
    pub peak_cpu: f64,
    pub peak_memory_gb: f64,
}

// Helper structs to iteratively track stats across repeated phases.

#[derive(Debug, Default, Clone, Copy)]
pub struct DurationTracker {
    pub ct: usize,
    pub min: std::time::Duration,
    pub avg: std::time::Duration,
    pub max: std::time::Duration,
}

impl DurationTracker {
    pub fn update(&mut self, next: &std::time::Duration) {
        let prev = self.ct as f64;
        self.ct += 1;

        if self.ct == 1 {
            self.min = *next;
            self.avg = *next;
            self.max = *next;

            return;
        }

        let curr = self.ct as f64;

        self.min = std::cmp::min(self.min, *next);
        self.avg = (self.avg.mul_f64(prev) + *next).div_f64(curr);
        self.max = std::cmp::max(self.max, *next);
    }
}

#[derive(Debug, Default, Clone, Copy)]
pub struct PhaseMetricsTracker {
    pub ct: usize,
    pub min: PhaseMetrics,
    pub avg: PhaseMetrics,
    pub max: PhaseMetrics,
}

impl PhaseMetricsTracker {
    pub fn update(&mut self, next: &PhaseMetrics) {
        let prev = self.ct as f64;
        self.ct += 1;

        if self.ct == 1 {
            self.min = *next;
            self.avg = *next;
            self.max = *next;

            return;
        }

        let curr = self.ct as f64;

        self.min.peak_cpu = self.min.peak_cpu.min(next.peak_cpu);
        self.min.peak_memory_gb = self.min.peak_memory_gb.min(next.peak_memory_gb);

        self.avg.peak_cpu = ((self.avg.peak_cpu * prev) + next.peak_cpu) / curr;
        self.avg.peak_memory_gb = ((self.avg.peak_memory_gb * prev) + next.peak_memory_gb) / curr;

        self.max.peak_cpu = self.max.peak_cpu.max(next.peak_cpu);
        self.max.peak_memory_gb = self.max.peak_memory_gb.max(next.peak_memory_gb);
    }
}

#[derive(Debug, Default, Clone, Copy)]
pub struct PhasesTracker {
    pub duration: DurationTracker,
    pub user: DurationTracker,
    pub sys: DurationTracker,
    pub metrics: PhaseMetricsTracker,
}

impl PhasesTracker {
    pub fn update(
        &mut self,
        next_duration: &std::time::Duration,
        next_user: &std::time::Duration,
        next_sys: &std::time::Duration,
        next_metrics: &PhaseMetrics,
    ) {
        self.duration.update(next_duration);
        self.user.update(next_user);
        self.sys.update(next_sys);
        self.metrics.update(next_metrics);
    }
}

/// Start measuring a phase and return initial state.
#[cfg(unix)]
pub fn phase_start() -> TimingState {
    let mut initial_self_usage: rusage = unsafe { std::mem::zeroed() };
    let mut initial_children_usage: rusage = unsafe { std::mem::zeroed() };
    unsafe {
        getrusage(RUSAGE_SELF, &mut initial_self_usage);
        getrusage(RUSAGE_CHILDREN, &mut initial_children_usage);
    };
    (
        std::time::Instant::now(),
        initial_self_usage,
        initial_children_usage,
    )
}

/// Start measuring a phase and return initial state (Windows stub).
#[cfg(windows)]
pub fn phase_start() -> TimingState {
    std::time::Instant::now()
}

/// End measuring a phase and return duration and metrics.
#[cfg(unix)]
pub fn phase_end(
    timing_state: TimingState,
) -> (
    std::time::Duration,
    std::time::Duration,
    std::time::Duration,
    PhaseMetrics,
) {
    let (start_time, initial_self_usage, initial_children_usage) = timing_state;
    let mut final_self_usage: rusage = unsafe { std::mem::zeroed() };
    let mut final_children_usage: rusage = unsafe { std::mem::zeroed() };
    unsafe {
        getrusage(RUSAGE_SELF, &mut final_self_usage);
        getrusage(RUSAGE_CHILDREN, &mut final_children_usage);
    };

    let initial_cpu_time = {
        let self_time = initial_self_usage.ru_utime.tv_sec as f64
            + initial_self_usage.ru_utime.tv_usec as f64 / 1_000_000.0
            + initial_self_usage.ru_stime.tv_sec as f64
            + initial_self_usage.ru_stime.tv_usec as f64 / 1_000_000.0;
        let children_time = initial_children_usage.ru_utime.tv_sec as f64
            + initial_children_usage.ru_utime.tv_usec as f64 / 1_000_000.0
            + initial_children_usage.ru_stime.tv_sec as f64
            + initial_children_usage.ru_stime.tv_usec as f64 / 1_000_000.0;
        self_time + children_time
    };

    let final_cpu_time = {
        let self_time = final_self_usage.ru_utime.tv_sec as f64
            + final_self_usage.ru_utime.tv_usec as f64 / 1_000_000.0
            + final_self_usage.ru_stime.tv_sec as f64
            + final_self_usage.ru_stime.tv_usec as f64 / 1_000_000.0;
        let children_time = final_children_usage.ru_utime.tv_sec as f64
            + final_children_usage.ru_utime.tv_usec as f64 / 1_000_000.0
            + final_children_usage.ru_stime.tv_sec as f64
            + final_children_usage.ru_stime.tv_usec as f64 / 1_000_000.0;
        self_time + children_time
    };

    let total_cpu_time = final_cpu_time - initial_cpu_time;
    let duration = start_time.elapsed();
    let wall_time = duration.as_secs_f64();

    // Calculate CPU usage as percentage.
    let cpu_percentage = if wall_time > 0.0 {
        ((total_cpu_time / wall_time / num_cpus::get() as f64) * 100.0 * 1000.0).round() / 1000.0
    } else {
        0.0
    };

    // Get peak memory usage (use maximum of self and children).
    #[cfg(target_os = "macos")]
    let peak_memory_gb = {
        let self_mem = ((final_self_usage.ru_maxrss as f64) / (1024.0 * 1024.0 * 1024.0) * 1000.0)
            .round()
            / 1000.0;
        let children_mem =
            ((final_children_usage.ru_maxrss as f64) / (1024.0 * 1024.0 * 1024.0) * 1000.0).round()
                / 1000.0;
        f64::max(self_mem, children_mem)
    };
    #[cfg(not(target_os = "macos"))]
    let peak_memory_gb = {
        let self_mem =
            ((final_self_usage.ru_maxrss as f64) / (1024.0 * 1024.0) * 1000.0).round() / 1000.0;
        let children_mem =
            ((final_children_usage.ru_maxrss as f64) / (1024.0 * 1024.0) * 1000.0).round() / 1000.0;
        f64::max(self_mem, children_mem)
    };

    let (user_time, sys_time) = calculate_time_diff(&initial_self_usage, &final_self_usage);

    (
        duration,
        user_time,
        sys_time,
        PhaseMetrics {
            peak_cpu: cpu_percentage,
            peak_memory_gb,
        },
    )
}

/// End measuring a phase and return duration and metrics (Windows stub).
#[cfg(windows)]
pub fn phase_end(
    timing_state: TimingState,
) -> (
    std::time::Duration,
    std::time::Duration,
    std::time::Duration,
    PhaseMetrics,
) {
    let start_time = timing_state;
    let duration = start_time.elapsed();
    (
        duration,
        duration,                  // User time approximation
        std::time::Duration::ZERO, // System time
        PhaseMetrics {
            peak_cpu: 0.0,       // Not measurable on Windows easily
            peak_memory_gb: 0.0, // Not measurable on Windows easily
        },
    )
}
