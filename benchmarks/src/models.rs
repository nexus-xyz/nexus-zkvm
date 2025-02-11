use csv::StringRecord;
use serde::Serialize;
use std::error::Error;
use std::time::Duration;

/// Statistics for a single stage of the benchmark.
#[derive(Debug, Serialize)]
pub struct StageStats {
    pub speed_khz: f32,
    pub overhead: f32,
    pub peak_cpu_percentage: f64,
    pub peak_memory_gb: f64,
    pub duration: Duration,
    pub sys_time: Duration,
    pub user_time: Duration,
}

impl StageStats {
    /// Write the header for a stage with a given prefix.
    pub fn header_with_prefix(prefix: &str) -> String {
        format!("{}_speed_khz,{}_overhead,{}_peak_cpu_percentage,{}_peak_memory_gb,{}_duration,{}_sys_time,{}_user_time",
            prefix, prefix, prefix, prefix, prefix, prefix, prefix)
    }

    /// Parse a stage's statistics from CSV record fields starting at the given offset.
    fn from_csv_record(record: &StringRecord, offset: usize) -> Result<Self, Box<dyn Error>> {
        Ok(StageStats {
            speed_khz: record[offset].parse()?,
            overhead: record[offset + 1].parse()?,
            peak_cpu_percentage: record[offset + 2].parse()?,
            peak_memory_gb: record[offset + 3].parse()?,
            duration: Duration::from_secs_f32(record[offset + 4].parse()?),
            sys_time: Duration::from_secs_f32(record[offset + 5].parse()?),
            user_time: Duration::from_secs_f32(record[offset + 6].parse()?),
        })
    }
}

impl std::fmt::Display for StageStats {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{},{},{},{},{},{},{}",
            self.speed_khz,
            self.overhead,
            self.peak_cpu_percentage,
            self.peak_memory_gb,
            self.duration.as_secs_f32(),
            self.sys_time.as_secs_f32(),
            self.user_time.as_secs_f32()
        )
    }
}

/// Complete benchmark results including all stages.
#[derive(Debug, Serialize)]
pub struct BenchmarkResult {
    pub timestamp: String,
    pub test: String,
    pub emulator_type: String,
    pub total_speed_khz: f32,
    pub total_duration: Duration,
    pub total_steps: u32,
    pub cpu_cores: usize,
    pub total_ram_gb: f64,
    pub total_peak_cpu_percentage: f64,
    pub total_peak_memory_gb: f64,
    pub num_loads: u32,
    pub num_stores: u32,
    pub stack_size: u32,
    pub heap_size: u32,
    pub native: StageStats,
    pub emulation: StageStats,
    pub proving: StageStats,
    pub verification: StageStats,
}

impl BenchmarkResult {
    pub fn csv_header() -> String {
        format!("timestamp,test,emulator_type,total_speed_khz,total_duration,total_steps,cpu_cores,total_ram_gb,total_peak_cpu_percentage,total_peak_memory_gb,num_loads,num_stores,stack_size,heap_size,\
                {},\
                {},\
                {},\
                {}",
            StageStats::header_with_prefix("native"),
            StageStats::header_with_prefix("emulation"),
            StageStats::header_with_prefix("proving"),
            StageStats::header_with_prefix("verification")
        )
    }

    /// Parse a CSV record into a BenchmarkResult.
    pub fn from_csv_record(record: &StringRecord) -> Result<Self, Box<dyn Error>> {
        // Fixed offsets for each stage's stats in the CSV record.
        const NATIVE_OFFSET: usize = 14;
        const EMULATION_OFFSET: usize = 21;
        const PROVING_OFFSET: usize = 28;
        const VERIFICATION_OFFSET: usize = 35;

        Ok(BenchmarkResult {
            timestamp: record[0].to_string(),
            test: record[1].to_string(),
            emulator_type: record[2].to_string(),
            total_speed_khz: record[3].parse()?,
            total_duration: Duration::from_secs_f32(record[4].parse()?),
            total_steps: record[5].parse()?,
            cpu_cores: record[6].parse()?,
            total_ram_gb: record[7].parse()?,
            total_peak_cpu_percentage: record[8].parse()?,
            total_peak_memory_gb: record[9].parse()?,
            num_loads: record[10].parse()?,
            num_stores: record[11].parse()?,
            stack_size: record[12].parse()?,
            heap_size: record[13].parse()?,
            native: StageStats::from_csv_record(record, NATIVE_OFFSET)?,
            emulation: StageStats::from_csv_record(record, EMULATION_OFFSET)?,
            proving: StageStats::from_csv_record(record, PROVING_OFFSET)?,
            verification: StageStats::from_csv_record(record, VERIFICATION_OFFSET)?,
        })
    }

    /// Parse multiple BenchmarkResults from a CSV reader.
    pub fn from_csv_reader<R: std::io::Read>(
        reader: csv::Reader<R>,
    ) -> Result<Vec<Self>, Box<dyn Error>> {
        let mut results = Vec::new();
        for record in reader.into_records() {
            let record = record?;
            results.push(Self::from_csv_record(&record)?);
        }
        Ok(results)
    }
}

impl std::fmt::Display for BenchmarkResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{}",
            self.timestamp,
            self.test,
            self.emulator_type,
            self.total_speed_khz,
            self.total_duration.as_secs_f32(),
            self.total_steps,
            self.cpu_cores,
            self.total_ram_gb,
            self.total_peak_cpu_percentage,
            self.total_peak_memory_gb,
            self.num_loads,
            self.num_stores,
            self.stack_size,
            self.heap_size,
            self.native,
            self.emulation,
            self.proving,
            self.verification
        )
    }
}
