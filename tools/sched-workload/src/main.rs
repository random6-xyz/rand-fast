use std::{
    hint::black_box,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
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
struct TargetArgs {
    /// How long the workload should run.
    #[arg(long, value_parser = parse_duration)]
    duration: Duration,

    /// Time between wakeups.
    #[arg(long, default_value = "1ms", value_parser = parse_duration)]
    period: Duration,
}

#[derive(Debug, Clone, Args)]
struct HogArgs {
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
    let deadline = Instant::now() + args.duration;
    while Instant::now() < deadline {
        thread::sleep(args.period);
        let mut value = 0u64;
        for _ in 0..256 {
            value = value.wrapping_mul(31).wrapping_add(1);
        }
        black_box(value);
    }
    Ok(())
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
    let mut handles = Vec::with_capacity(args.workers);
    for worker in 0..args.workers {
        let stop = Arc::clone(&stop);
        handles.push(thread::spawn(move || {
            let mut value = worker as u64;
            while !stop.load(Ordering::Relaxed) {
                value = value.wrapping_mul(31).wrapping_add(1);
                black_box(value);
            }
        }));
    }

    thread::sleep(args.duration);
    stop.store(true, Ordering::Relaxed);
    for handle in handles {
        handle
            .join()
            .map_err(|_| "a contention worker panicked".to_string())?;
    }
    Ok(())
}

fn parse_duration(value: &str) -> Result<Duration, String> {
    let duration = humantime::parse_duration(value)
        .map_err(|error| format!("invalid duration `{value}`: {error}"))?;
    if duration.is_zero() {
        return Err("duration must be greater than zero".to_string());
    }
    Ok(duration)
}
