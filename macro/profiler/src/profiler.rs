use std::fs::File;
use std::io::Write;

use pprof::{protos::Message, ProfilerGuard};

pub fn pprof_start() -> ProfilerGuard<'static> {
    pprof::ProfilerGuardBuilder::default()
        .frequency(1000)
        .blocklist(&["libc", "libgcc", "pthread", "vdso"])
        .build()
        .expect("Failed to start profiler")
}

pub fn pprof_end(guard: ProfilerGuard<'static>, filename: &str) {
    let report = guard
        .report()
        .build()
        .expect("Failed to pprof build report");
    let profile = report.pprof().expect("Failed to generate pprof profile");

    let mut content = Vec::new();
    profile
        .encode(&mut content)
        .expect("Failed to encode pprof profile");

    let mut file = File::create(filename).expect("Failed to create pprof profile file");
    file.write_all(&content)
        .expect("Failed to write pprof profile data");
}
