use crate::models::BenchmarkResult;
use crate::paths::{graphs_file, results_file};
use csv::Reader;
use plotly::layout::{Axis, AxisType};
use plotly::{Plot, Scatter};
use std::error::Error;
use std::fs::File;

fn parse_csv(input_csv: &str) -> Result<Box<Scatter<f64, f64>>, Box<dyn Error>> {
    // Read the CSV file from results directory.
    let file = File::open(results_file(input_csv))?;
    let reader = Reader::from_reader(file);
    let benchmark_results = BenchmarkResult::from_csv_reader(reader)?;

    // Extract steps and durations for plotting.
    let steps: Vec<f64> = benchmark_results
        .iter()
        .map(|r| r.total_steps as f64)
        .collect();
    let durations: Vec<f64> = benchmark_results
        .iter()
        .map(|r| r.total_duration.as_secs_f64())
        .collect();
    let total_speed_khz: Vec<f64> = benchmark_results
        .iter()
        .map(|r| r.total_speed_khz as f64)
        .collect();

    // Create a scatter trace for this CSV.
    let trace = Scatter::new(steps.clone(), durations)
        .name(input_csv.trim_end_matches(".csv")) // Use filename as trace name
        .mode(plotly::common::Mode::LinesMarkers)
        .hover_template("%{customdata:.3f} kHz")
        .custom_data(total_speed_khz);

    Ok(trace)
}

/// Generate a performance plot from multiple CSV files.
pub fn generate_performance_plot(
    input_csvs: &[&str],
    output_html: &str,
) -> Result<(), Box<dyn Error>> {
    // Create a new plot.
    let mut plot = Plot::new();

    // Process each CSV file and create a trace.
    for input_csv in input_csvs {
        let trace = parse_csv(input_csv)?;
        plot.add_trace(trace);
    }

    // Create tick values and labels for x-axis powers of 2 (from 2^12 to 2^19).
    let x_tick_values: Vec<f64> = (12..=19).map(|p| 2f64.powi(p)).collect();
    let x_tick_text: Vec<String> = (12..=19).map(|p| format!("2^{}", p)).collect();
    let y_tick_values: Vec<f64> = (-2..=9).map(|p| 2f64.powi(p)).collect();
    let y_tick_text: Vec<String> = (-2..=9).map(|p| format!("2^{}", p)).collect();
    plot.set_layout(
        plotly::Layout::new()
            .title("ZK-VM Performance: Steps vs Duration")
            .x_axis(
                Axis::new()
                    .title("Total Steps")
                    .type_(AxisType::Log)
                    .tick_values(x_tick_values)
                    .tick_text(x_tick_text),
            )
            .y_axis(
                Axis::new()
                    .title("Duration (seconds)")
                    .type_(AxisType::Log)
                    .tick_values(y_tick_values)
                    .tick_text(y_tick_text)
                    .zero_line(true),
            ),
    );

    // Save the plot to an HTML file in the graphs directory.
    let output_path = graphs_file(output_html);
    plot.write_html(output_path.clone());
    Ok(())
}
