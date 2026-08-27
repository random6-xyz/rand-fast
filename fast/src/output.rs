use std::time::Duration;

use humantime::format_duration;

use crate::stats::{Statistics, Summary};

pub fn print_report(
    pid: u32,
    process_name: &str,
    duration: Duration,
    stats: &Statistics,
    interrupted: bool,
    process_exited: bool,
) {
    println!("PID: {process_name} ({pid})");
    println!("Duration: {}", format_duration(duration));
    if interrupted {
        println!("Status: interrupted");
    } else if process_exited {
        println!("Status: process exited");
    }

    println!("Samples: {}", stats.sample_count());
    println!("Lost events: {}", stats.lost_events());
    if stats.lost_events() > 0 {
        println!("Warning: some scheduler events were lost from the perf buffer");
    }

    println!();
    println!("Scheduler latency");
    match stats.summary() {
        Some(summary) => print_summary(&summary),
        None => println!("No scheduler latency samples were collected."),
    }

    println!();
    println!("CPU latency (running CPU)");
    let mut has_cpu_summary = false;
    for (cpu, summary) in stats.cpu_summaries() {
        has_cpu_summary = true;
        println!(
            "cpu {cpu:<4} samples {:<8} p50 {:>10} p95 {:>10} p99 {:>10} max {:>10}",
            summary.count,
            format_ns(summary.p50_ns),
            format_ns(summary.p95_ns),
            format_ns(summary.p99_ns),
            format_ns(summary.max_ns),
        );
    }
    if !has_cpu_summary {
        println!("No per-CPU samples were collected.");
    }

    println!();
    println!("Slow events");
    println!("> 1ms  {:>8}", stats.slow_1ms());
    println!("> 10ms {:>8}", stats.slow_10ms());
    println!("> 50ms {:>8}", stats.slow_50ms());
}

fn print_summary(summary: &Summary) {
    println!("{:<8}{:>10}", "p50", format_ns(summary.p50_ns));
    println!("{:<8}{:>10}", "p95", format_ns(summary.p95_ns));
    println!("{:<8}{:>10}", "p99", format_ns(summary.p99_ns));
    println!("{:<8}{:>10}", "max", format_ns(summary.max_ns));
}

pub fn format_ns(nanoseconds: u64) -> String {
    if nanoseconds < 1_000 {
        return format!("{nanoseconds} ns");
    }

    let microseconds = nanoseconds.saturating_add(500) / 1_000;
    if microseconds < 1_000 {
        return format!("{microseconds} µs");
    }

    if nanoseconds < 1_000_000_000 {
        return format!("{:.1} ms", nanoseconds as f64 / 1_000_000.0);
    }

    format!("{:.2} s", nanoseconds as f64 / 1_000_000_000.0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formats_latency_units() {
        assert_eq!(format_ns(42), "42 ns");
        assert_eq!(format_ns(21_000), "21 µs");
        assert_eq!(format_ns(7_200_000), "7.2 ms");
        assert_eq!(format_ns(84_100_000), "84.1 ms");
        assert_eq!(format_ns(1_250_000_000), "1.25 s");
    }

    #[test]
    fn rounds_sub_millisecond_values_without_printing_1000_microseconds() {
        assert_eq!(format_ns(999_600), "1.0 ms");
    }
}
