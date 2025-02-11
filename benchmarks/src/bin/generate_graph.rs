use nexus_benchmarks::graph::generate_performance_plot;
use std::error::Error;

fn main() -> Result<(), Box<dyn Error>> {
    generate_performance_plot(
        &[
            "fib_powers_2025-02-10_16-59-52.csv",
            "keccak_powers_2025-02-10_17-05-51.csv",
        ],
        "fib.html",
    )?;
    Ok(())
}
