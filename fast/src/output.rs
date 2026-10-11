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

/// The scheduler command's `data` object.
///
/// The human report prints percentiles per CPU as well; the document carries
/// the overall percentiles plus the per-CPU rows, because a consumer that
/// wanted the table should not have to re-run the collection to get it.
#[derive(Debug, Clone, serde::Serialize)]
pub struct SchedulerJson {
    /// Number of latency samples collected.
    pub samples: u64,
    /// Records the kernel dropped from the perf buffer.
    pub lost_events: u64,
    /// Median runnable-to-running latency.
    pub p50_us: u64,
    /// 95th percentile latency.
    pub p95_us: u64,
    /// 99th percentile latency.
    pub p99_us: u64,
    /// Longest single latency.
    pub max_us: u64,
    /// Waits over 1ms.
    pub slow_over_1ms: u64,
    /// Waits over 10ms.
    pub slow_over_10ms: u64,
    /// Waits over 50ms.
    pub slow_over_50ms: u64,
    /// The same percentiles broken down by the CPU the thread ran on.
    pub per_cpu: Vec<CpuLatencyJson>,
}

/// One CPU's scheduler latency row.
#[derive(Debug, Clone, serde::Serialize)]
pub struct CpuLatencyJson {
    /// CPU the thread ran on.
    pub cpu: u32,
    /// Samples on this CPU.
    pub samples: u64,
    /// Median latency on this CPU.
    pub p50_us: u64,
    /// 95th percentile latency on this CPU.
    pub p95_us: u64,
    /// 99th percentile latency on this CPU.
    pub p99_us: u64,
    /// Longest single latency on this CPU.
    pub max_us: u64,
}

/// Builds the scheduler document's `data` object.
pub fn scheduler_json(stats: &Statistics) -> SchedulerJson {
    let summary = stats.summary();
    SchedulerJson {
        samples: stats.sample_count() as u64,
        lost_events: stats.lost_events(),
        p50_us: summary.map_or(0, |s| s.p50_ns / 1_000),
        p95_us: summary.map_or(0, |s| s.p95_ns / 1_000),
        p99_us: summary.map_or(0, |s| s.p99_ns / 1_000),
        max_us: summary.map_or(0, |s| s.max_ns / 1_000),
        slow_over_1ms: stats.slow_1ms(),
        slow_over_10ms: stats.slow_10ms(),
        slow_over_50ms: stats.slow_50ms(),
        per_cpu: stats
            .cpu_summaries()
            .map(|(cpu, summary)| CpuLatencyJson {
                cpu,
                samples: summary.count as u64,
                p50_us: summary.p50_ns / 1_000,
                p95_us: summary.p95_ns / 1_000,
                p99_us: summary.p99_ns / 1_000,
                max_us: summary.max_ns / 1_000,
            })
            .collect(),
    }
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

    /// A collector with a known distribution, so the document's numbers can be
    /// checked against the ones the human report prints.
    fn sample_stats() -> Statistics {
        let mut stats = Statistics::default();
        for latency_ns in [40_000u64, 900_000, 2_000_000, 84_000_000] {
            stats.record(fast_common::SchedulerLatencyEvent {
                latency_ns,
                wake_ns: 0,
                run_ns: latency_ns,
                tid: 1,
                wake_cpu: 0,
                run_cpu: 3,
                reserved: 0,
            });
        }
        stats.record_lost(2);
        stats
    }

    #[test]
    fn scheduler_json_reports_microseconds() {
        let data = scheduler_json(&sample_stats());
        assert_eq!(data.samples, 4);
        assert_eq!(data.lost_events, 2);
        // 40us, 900us, 2ms, 84ms -> the maximum survives the unit change.
        assert_eq!(data.max_us, 84_000);
        assert!(data.p99_us <= data.max_us);
        assert!(data.p50_us <= data.p95_us);
    }

    #[test]
    fn scheduler_json_carries_the_per_cpu_rows() {
        let data = scheduler_json(&sample_stats());
        assert_eq!(data.per_cpu.len(), 1);
        assert_eq!(data.per_cpu[0].cpu, 3);
        assert_eq!(data.per_cpu[0].samples, 4);
    }

    #[test]
    fn scheduler_json_counts_slow_events() {
        let data = scheduler_json(&sample_stats());
        assert_eq!(data.slow_over_1ms, 2, "2ms and 84ms are over 1ms");
        assert_eq!(data.slow_over_10ms, 1, "only 84ms is over 10ms");
        assert_eq!(data.slow_over_50ms, 1, "only 84ms is over 50ms");
    }

    #[test]
    fn scheduler_json_of_an_empty_run_is_still_a_valid_document() {
        // No samples must produce a document with zero counts, not a missing
        // or malformed one.
        let data = scheduler_json(&Statistics::default());
        assert_eq!(data.samples, 0);
        assert_eq!(data.p95_us, 0);
        assert!(data.per_cpu.is_empty());
    }

    #[test]
    fn scheduler_json_is_serializable() {
        let value = serde_json::to_value(scheduler_json(&sample_stats()))
            .expect("the payload must serialize");
        assert_eq!(value["samples"], serde_json::json!(4));
        assert_eq!(value["per_cpu"][0]["cpu"], serde_json::json!(3));
    }
}
