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
const STAGE_STATS_LEN: usize = 7;

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
    pub piecewise_min_total_speed_khz: f32,
    pub piecewise_min_total_duration: Duration,
    pub piecewise_min_total_overhead: f32,
    pub avg_total_speed_khz: f32,
    pub avg_total_duration: Duration,
    pub avg_total_overhead: f32,
    pub piecewise_max_total_speed_khz: f32,
    pub piecewise_max_total_duration: Duration,
    pub piecewise_max_total_overhead: f32,
    pub total_steps: u32,
    pub cpu_cores: usize,
    pub total_ram_gb: f64,
    pub piecewise_min_total_peak_cpu_percentage: f64,
    pub piecewise_min_total_peak_memory_gb: f64,
    pub avg_total_peak_cpu_percentage: f64,
    pub avg_total_peak_memory_gb: f64,
    pub piecewise_max_total_peak_cpu_percentage: f64,
    pub piecewise_max_total_peak_memory_gb: f64,
    pub num_loads: u32,
    pub num_stores: u32,
    pub stack_size: u32,
    pub heap_size: u32,
    pub native_mins: StageStats,
    pub native_avgs: StageStats,
    pub native_maxs: StageStats,
    pub emulation_mins: StageStats,
    pub emulation_avgs: StageStats,
    pub emulation_maxs: StageStats,
    pub proving_mins: StageStats,
    pub proving_avgs: StageStats,
    pub proving_maxs: StageStats,
    pub verification_mins: StageStats,
    pub verification_avgs: StageStats,
    pub verification_maxs: StageStats,
}

impl BenchmarkResult {
    pub fn csv_header() -> String {
        format!("timestamp,test,emulator_type,piecewise_min_total_speed_khz,piecewise_min_total_duration,piecewise_min_total_overhead,avg_total_speed_khz,avg_total_duration,avg_total_overhead,piecewise_max_total_speed_khz,piecewise_max_total_duration,piecewise_max_total_overhead,total_steps,cpu_cores,total_ram_gb,piecewise_min_total_peak_cpu_percentage,piecewise_min_total_peak_memory_gb,avg_total_peak_cpu_percentage,avg_total_peak_memory_gb,piecewise_max_total_peak_cpu_percentage,piecewise_max_total_peak_memory_gb,num_loads,num_stores,stack_size,heap_size,\
                {},\
                {},\
                {},\
                {},\
                {},\
                {},\
                {},\
                {},\
                {},\
                {},\
                {},\
                {}",
                StageStats::header_with_prefix("native_min"),
                StageStats::header_with_prefix("native_avg"),
                StageStats::header_with_prefix("native_max"),
                StageStats::header_with_prefix("emulation_min"),
                StageStats::header_with_prefix("emulation_avg"),
                StageStats::header_with_prefix("emulation_max"),
                StageStats::header_with_prefix("proving_min"),
                StageStats::header_with_prefix("proving_avg"),
                StageStats::header_with_prefix("proving_max"),
                StageStats::header_with_prefix("verification_min"),
                StageStats::header_with_prefix("verification_avg"),
                StageStats::header_with_prefix("verification_max"),
        )
    }

    /// Parse a CSV record into a BenchmarkResult.
    pub fn from_csv_record(record: &StringRecord) -> Result<Self, Box<dyn Error>> {
        // Fixed offsets for each stage's stats in the CSV record.
        const NATIVE_OFFSET: usize = 25;
        const EMULATION_OFFSET: usize = NATIVE_OFFSET + 3 * STAGE_STATS_LEN;
        const PROVING_OFFSET: usize = EMULATION_OFFSET + 3 * STAGE_STATS_LEN;
        const VERIFICATION_OFFSET: usize = PROVING_OFFSET + 3 * STAGE_STATS_LEN;

        Ok(BenchmarkResult {
            timestamp: record[0].to_string(),
            test: record[1].to_string(),
            emulator_type: record[2].to_string(),
            piecewise_min_total_speed_khz: record[3].parse()?,
            piecewise_min_total_duration: Duration::from_secs_f32(record[4].parse()?),
            piecewise_min_total_overhead: record[5].parse()?,
            avg_total_speed_khz: record[6].parse()?,
            avg_total_duration: Duration::from_secs_f32(record[7].parse()?),
            avg_total_overhead: record[8].parse()?,
            piecewise_max_total_speed_khz: record[9].parse()?,
            piecewise_max_total_duration: Duration::from_secs_f32(record[10].parse()?),
            piecewise_max_total_overhead: record[11].parse()?,
            total_steps: record[12].parse()?,
            cpu_cores: record[13].parse()?,
            total_ram_gb: record[14].parse()?,
            piecewise_min_total_peak_cpu_percentage: record[15].parse()?,
            piecewise_min_total_peak_memory_gb: record[16].parse()?,
            avg_total_peak_cpu_percentage: record[17].parse()?,
            avg_total_peak_memory_gb: record[18].parse()?,
            piecewise_max_total_peak_cpu_percentage: record[19].parse()?,
            piecewise_max_total_peak_memory_gb: record[20].parse()?,
            num_loads: record[21].parse()?,
            num_stores: record[22].parse()?,
            stack_size: record[23].parse()?,
            heap_size: record[24].parse()?,
            native_mins: StageStats::from_csv_record(record, NATIVE_OFFSET)?,
            native_avgs: StageStats::from_csv_record(record, NATIVE_OFFSET + STAGE_STATS_LEN)?,
            native_maxs: StageStats::from_csv_record(record, NATIVE_OFFSET + 2 * STAGE_STATS_LEN)?,
            emulation_mins: StageStats::from_csv_record(record, EMULATION_OFFSET)?,
            emulation_avgs: StageStats::from_csv_record(
                record,
                EMULATION_OFFSET + STAGE_STATS_LEN,
            )?,
            emulation_maxs: StageStats::from_csv_record(
                record,
                EMULATION_OFFSET + 2 * STAGE_STATS_LEN,
            )?,
            proving_mins: StageStats::from_csv_record(record, PROVING_OFFSET)?,
            proving_avgs: StageStats::from_csv_record(record, PROVING_OFFSET + STAGE_STATS_LEN)?,
            proving_maxs: StageStats::from_csv_record(
                record,
                PROVING_OFFSET + 2 * STAGE_STATS_LEN,
            )?,
            verification_mins: StageStats::from_csv_record(record, VERIFICATION_OFFSET)?,
            verification_avgs: StageStats::from_csv_record(
                record,
                VERIFICATION_OFFSET + STAGE_STATS_LEN,
            )?,
            verification_maxs: StageStats::from_csv_record(
                record,
                VERIFICATION_OFFSET + 2 * STAGE_STATS_LEN,
            )?,
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
            "{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{}",
            self.timestamp,
            self.test,
            self.emulator_type,
            self.piecewise_min_total_speed_khz,
            self.piecewise_min_total_duration.as_secs_f32(),
            self.piecewise_min_total_overhead,
            self.avg_total_speed_khz,
            self.avg_total_duration.as_secs_f32(),
            self.avg_total_overhead,
            self.piecewise_max_total_speed_khz,
            self.piecewise_max_total_duration.as_secs_f32(),
            self.piecewise_max_total_overhead,
            self.total_steps,
            self.cpu_cores,
            self.total_ram_gb,
            self.piecewise_min_total_peak_cpu_percentage,
            self.piecewise_min_total_peak_memory_gb,
            self.avg_total_peak_cpu_percentage,
            self.avg_total_peak_memory_gb,
            self.piecewise_max_total_peak_cpu_percentage,
            self.piecewise_max_total_peak_memory_gb,
            self.num_loads,
            self.num_stores,
            self.stack_size,
            self.heap_size,
            self.native_mins,
            self.native_avgs,
            self.native_maxs,
            self.emulation_mins,
            self.emulation_avgs,
            self.emulation_maxs,
            self.proving_mins,
            self.proving_avgs,
            self.proving_maxs,
            self.verification_mins,
            self.verification_avgs,
            self.verification_maxs,
        )
    }
}
