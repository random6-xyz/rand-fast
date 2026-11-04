use std::{
    hint::black_box,
    path::PathBuf,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    thread,
    time::{Duration, Instant},
};

use clap::{Args, Parser, Subcommand};

#[derive(Debug, Parser)]
#[command(
    name = "sched-workload",
    about = "Workloads for scheduler latency validation"
)]
struct Cli {
    #[command(subcommand)]
    mode: Mode,
}

#[derive(Debug, Subcommand)]
enum Mode {
    /// Periodically sleep and wake to generate scheduler samples.
    Target(TargetArgs),
    /// Run CPU-bound worker threads for contention testing.
    Hog(HogArgs),
}

#[derive(Debug, Clone, Args)]
struct CommonArgs {
    /// Write a machine-readable report here when the workload finishes.
    #[arg(long, value_name = "PATH")]
    report: Option<PathBuf>,
    /// Create this file once the workload is ready to be observed.
    #[arg(long, value_name = "PATH")]
    ready_file: Option<PathBuf>,
}

#[derive(Debug, Clone, Args)]
struct TargetArgs {
    #[command(flatten)]
    common: CommonArgs,

    /// How long the workload should run.
    #[arg(long, value_parser = parse_duration)]
    duration: Duration,

    /// Time between wakeups.
    #[arg(long, default_value = "1ms", value_parser = parse_duration)]
    period: Duration,
}

#[derive(Debug, Clone, Args)]
struct HogArgs {
    #[command(flatten)]
    common: CommonArgs,

    /// How long the workers should run.
    #[arg(long, value_parser = parse_duration)]
    duration: Duration,

    /// Number of CPU-bound worker threads.
    #[arg(long, default_value_t = 1)]
    workers: usize,
}

fn main() -> std::process::ExitCode {
    let cli = Cli::parse();
    let result = match cli.mode {
        Mode::Target(args) => run_target(args),
        Mode::Hog(args) => run_hog(args),
    };

    if let Err(error) = result {
        eprintln!("error: {error}");
        std::process::ExitCode::FAILURE
    } else {
        std::process::ExitCode::SUCCESS
    }
}

fn run_target(args: TargetArgs) -> Result<(), String> {
    if args.period.is_zero() {
        return Err("period must be greater than zero".to_string());
    }

    println!("target pid: {}", std::process::id());
    let latencies = LatencySamples::default();
    mark_ready(&args.common)?;
    let deadline = Instant::now() + args.duration;
    let mut cycles = 0u64;
    while Instant::now() < deadline {
        let started = Instant::now();
        thread::sleep(args.period);
        // How much longer than the request the thread took to run again. This
        // is the fixture's own wake-to-run view, independent of the collector.
        latencies.record(started.elapsed().saturating_sub(args.period));
        let mut value = 0u64;
        for _ in 0..256 {
            value = value.wrapping_mul(31).wrapping_add(1);
        }
        black_box(value);
        cycles += 1;
    }
    write_report(
        &args.common,
        "sched-target",
        args.duration,
        cycles,
        latencies.percentiles(),
        &[("period_ms", args.period.as_millis() as u64)],
    )
}

fn run_hog(args: HogArgs) -> Result<(), String> {
    if args.workers == 0 {
        return Err("workers must be greater than zero".to_string());
    }

    println!(
        "contention pid: {}, workers: {}",
        std::process::id(),
        args.workers
    );
    let stop = Arc::new(AtomicBool::new(false));
    let iterations = Arc::new(AtomicU64::new(0));
    let mut handles = Vec::with_capacity(args.workers);
    for worker in 0..args.workers {
        let stop = Arc::clone(&stop);
        let iterations = Arc::clone(&iterations);
        handles.push(thread::spawn(move || {
            let mut value = worker as u64;
            while !stop.load(Ordering::Relaxed) {
                value = value.wrapping_mul(31).wrapping_add(1);
                black_box(value);
                iterations.fetch_add(1, Ordering::Relaxed);
            }
        }));
    }
    mark_ready(&args.common)?;

    thread::sleep(args.duration);
    stop.store(true, Ordering::Relaxed);
    for handle in handles {
        handle
            .join()
            .map_err(|_| "a contention worker panicked".to_string())?;
    }
    write_report(
        &args.common,
        "sched-hog",
        args.duration,
        iterations.load(Ordering::Relaxed),
        None,
        &[("workers", args.workers as u64)],
    )
}

/// Latency samples taken by the fixture itself.
#[derive(Default)]
struct LatencySamples {
    samples: Mutex<Vec<u32>>,
}

impl LatencySamples {
    fn record(&self, elapsed: Duration) {
        let micros = elapsed.as_micros().min(u32::MAX as u128) as u32;
        if let Ok(mut samples) = self.samples.lock()
            && samples.len() < 200_000
        {
            samples.push(micros);
        }
    }

    fn percentiles(&self) -> Option<(u32, u32, u32)> {
        let mut samples = self.samples.lock().ok()?.clone();
        if samples.is_empty() {
            return None;
        }
        samples.sort_unstable();
        Some((
            percentile(&samples, 50),
            percentile(&samples, 95),
            percentile(&samples, 99),
        ))
    }
}

fn percentile(sorted: &[u32], pct: usize) -> u32 {
    if sorted.is_empty() {
        return 0;
    }
    let rank = (pct * sorted.len()).div_ceil(100).max(1);
    sorted[rank - 1]
}

fn mark_ready(common: &CommonArgs) -> Result<(), String> {
    if let Some(path) = &common.ready_file {
        std::fs::write(path, b"ready\n")
            .map_err(|error| format!("write {}: {error}", path.display()))?;
    }
    Ok(())
}

fn write_report(
    common: &CommonArgs,
    workload: &str,
    duration: Duration,
    ops: u64,
    latency: Option<(u32, u32, u32)>,
    extra: &[(&str, u64)],
) -> Result<(), String> {
    let Some(path) = &common.report else {
        return Ok(());
    };
    let mut body = format!(
        "{{\"workload\":\"{workload}\",\"pid\":{},\"duration_ms\":{},\"ops\":{ops}",
        std::process::id(),
        duration.as_millis()
    );
    if let Some((p50, p95, p99)) = latency {
        body.push_str(&format!(
            ",\"latency_us\":{{\"p50\":{p50},\"p95\":{p95},\"p99\":{p99}}}"
        ));
    }
    for (name, value) in extra {
        body.push_str(&format!(",\"{name}\":{value}"));
    }
    body.push_str("}\n");
    std::fs::write(path, body).map_err(|error| format!("write {}: {error}", path.display()))
}

fn parse_duration(value: &str) -> Result<Duration, String> {
    let duration = humantime::parse_duration(value)
        .map_err(|error| format!("invalid duration `{value}`: {error}"))?;
    if duration.is_zero() {
        return Err("duration must be greater than zero".to_string());
    }
    Ok(duration)
}
