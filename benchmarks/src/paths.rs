use std::path::PathBuf;

/// Get the path to the benchmarks directory.
pub fn benchmarks_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

/// Get the path to the results directory, creating it if it doesn't exist.
pub fn results_dir() -> PathBuf {
    let dir = benchmarks_dir().join("results");
    std::fs::create_dir_all(&dir).expect("Failed to create results directory");
    dir
}

/// Get the path to the graphs directory, creating it if it doesn't exist.
pub fn graphs_dir() -> PathBuf {
    let dir = benchmarks_dir().join("graphs");
    std::fs::create_dir_all(&dir).expect("Failed to create graphs directory");
    dir
}

/// Get a path in the results directory.
pub fn results_file(filename: &str) -> PathBuf {
    results_dir().join(filename)
}

/// Get a path in the graphs directory.
pub fn graphs_file(filename: &str) -> PathBuf {
    graphs_dir().join(filename)
}
