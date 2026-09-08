use std::collections::{BTreeMap, BTreeSet};
use std::fs;

use anyhow::{Context, Result};
use aya::{Ebpf, include_bytes_aligned};
use fast_common::IoEvent;

use crate::{cli::IoArgs, process, runtime};

/// `block_rq_*` can be bursty on busy devices; 64 pages (256 KiB) per CPU
/// keeps event loss low.
const PERF_PAGE_COUNT: usize = 64;

#[derive(Debug)]
struct IoStats {
    threshold_ns: u64,
    latencies: Vec<u64>,
    by_device: BTreeMap<u32, Vec<u64>>,
    slow: u64,
    lost: u64,
}

impl IoStats {
    fn new(threshold_ns: u64) -> Self {
        Self {
            threshold_ns,
            latencies: Vec::new(),
            by_device: BTreeMap::new(),
            slow: 0,
            lost: 0,
        }
    }

    fn record(&mut self, event: IoEvent) {
        self.latencies.push(event.latency_ns);
        self.by_device
            .entry(event.dev)
            .or_default()
            .push(event.latency_ns);
        if event.latency_ns > self.threshold_ns {
            self.slow += 1;
        }
    }
    fn record_lost(&mut self, count: u64) {
        self.lost = self.lost.saturating_add(count);
    }
    fn summary(&self) -> Option<Summary> {
        summary(&self.latencies)
    }
    fn device_summaries(&self) -> Vec<(u32, Summary)> {
        let mut out = Vec::new();
        for (dev, vals) in &self.by_device {
            if let Some(s) = summary(vals) {
                out.push((*dev, s));
            }
        }
        out.sort_by_key(|(d, _)| *d);
        out
    }
}

impl runtime::EventHandler<IoEvent> for IoStats {
    fn on_event(&mut self, event: IoEvent) {
        self.record(event);
    }

    fn on_lost(&mut self, count: u64) {
        self.record_lost(count);
    }
}

#[derive(Debug, Clone, Copy)]
struct Summary {
    count: usize,
    p50_ns: u64,
    p95_ns: u64,
    p99_ns: u64,
    max_ns: u64,
}

fn summary(values: &[u64]) -> Option<Summary> {
    if values.is_empty() {
        return None;
    }
    let mut sorted = values.to_vec();
    sorted.sort_unstable();
    let percentile = |p: f64| {
        let idx = ((p / 100.0) * sorted.len() as f64).ceil() as usize;
        let idx = idx.clamp(1, sorted.len()) - 1;
        sorted[idx]
    };
    Some(Summary {
        count: sorted.len(),
        p50_ns: percentile(50.0),
        p95_ns: percentile(95.0),
        p99_ns: percentile(99.0),
        max_ns: *sorted.last().unwrap(),
    })
}

fn format_ns(ns: u64) -> String {
    if ns < 1_000 {
        return format!("{ns} ns");
    }
    let us = ns.saturating_add(500) / 1_000;
    if us < 1_000 {
        return format!("{us} µs");
    }
    if ns < 1_000_000_000 {
        return format!("{:.1} ms", ns as f64 / 1_000_000.0);
    }
    format!("{:.2} s", ns as f64 / 1_000_000_000.0)
}

fn read_proc_io(pid: u32) -> Result<(u64, u64)> {
    let content = fs::read_to_string(format!("/proc/{pid}/io"))
        .with_context(|| format!("failed to read /proc/{pid}/io"))?;
    let mut rchar = 0u64;
    let mut wchar = 0u64;
    for line in content.lines() {
        if let Some(v) = line.strip_prefix("rchar:") {
            rchar = v.trim().parse().unwrap_or(0);
        } else if let Some(v) = line.strip_prefix("wchar:") {
            wchar = v.trim().parse().unwrap_or(0);
        }
    }
    Ok((rchar, wchar))
}

pub fn run(args: IoArgs) -> Result<()> {
    let pid = args.pid;
    let threshold = args.threshold;
    let process_name =
        process::read_name(pid).with_context(|| format!("cannot read process {pid}"))?;
    let initial_tids =
        process::thread_ids(pid).with_context(|| format!("cannot enumerate threads for {pid}"))?;

    let mut bpf = Ebpf::load(include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/fast-ebpf"
    )))
    .context("failed to load eBPF object; run as root or grant CAP_BPF and CAP_PERFMON")?;
    runtime::attach_tracepoint(&mut bpf, "block", "block_rq_issue")?;
    runtime::attach_tracepoint(&mut bpf, "block", "block_rq_complete")?;

    let mut target_tids = runtime::take_target_map(&mut bpf)?;

    let mut known_tids = BTreeSet::new();
    let mut stats = IoStats::new(threshold.as_nanos() as u64);
    let (rchar_start, wchar_start) = read_proc_io(pid).unwrap_or((0, 0));
    let summary = runtime::run_collection(
        &mut bpf,
        &mut target_tids,
        // Pending I/O lives in a request-keyed LRU map inside the eBPF
        // program; no TID-keyed pending state needs thread-exit cleanup.
        &mut runtime::NoPendingCleanup,
        &mut known_tids,
        &initial_tids,
        &mut stats,
        runtime::CollectionOptions {
            pid,
            duration: args.duration,
            events_map: "IO_EVENTS",
            perf_page_count: PERF_PAGE_COUNT,
            mode: 0,
        },
    )?;

    let (rchar_end, wchar_end) = read_proc_io(pid).unwrap_or((rchar_start, wchar_start));
    let rchar_delta = rchar_end.saturating_sub(rchar_start);
    let wchar_delta = wchar_end.saturating_sub(wchar_start);

    println!("PID: {process_name} ({pid})");
    println!("Duration: {}", humantime::format_duration(summary.elapsed));
    if summary.interrupted {
        println!("Status: interrupted");
    }
    println!("Samples: {}", stats.latencies.len());
    println!("Lost events: {}", stats.lost);
    println!(
        "Slow > {}: {}",
        humantime::format_duration(threshold),
        stats.slow
    );
    println!("rchar: {rchar_delta} bytes, wchar: {wchar_delta} bytes");
    println!();
    println!("I/O latency");
    match stats.summary() {
        Some(s) => {
            println!("{:<8}{:>10}", "p50", format_ns(s.p50_ns));
            println!("{:<8}{:>10}", "p95", format_ns(s.p95_ns));
            println!("{:<8}{:>10}", "p99", format_ns(s.p99_ns));
            println!("{:<8}{:>10}", "max", format_ns(s.max_ns));
        }
        None => println!("No I/O samples were collected."),
    }
    println!();
    println!("Per-device latency");
    let dev_summaries = stats.device_summaries();
    if dev_summaries.is_empty() {
        println!("No per-device samples were collected.");
    } else {
        for (dev, s) in dev_summaries {
            let major = dev >> 20;
            let minor = dev & 0xFFFFF;
            println!(
                "dev {major}:{minor} samples {:<4} p50 {:>10} p95 {:>10} p99 {:>10} max {:>10}",
                s.count,
                format_ns(s.p50_ns),
                format_ns(s.p95_ns),
                format_ns(s.p99_ns),
                format_ns(s.max_ns)
            );
        }
    }
    println!();
    println!(
        "Slow-device threshold: {} (configurable via --threshold)",
        humantime::format_duration(threshold)
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counts_slow_and_device() {
        let mut s = IoStats::new(1_000_000);
        s.record(IoEvent {
            latency_ns: 5_000_000,
            tid: 1,
            dev: 0x0801,
            sectors: 8,
            op: 0,
        });
        s.record(IoEvent {
            latency_ns: 5_000_000,
            tid: 1,
            dev: 0x0801,
            sectors: 8,
            op: 0,
        });
        assert_eq!(s.slow, 2);
        assert_eq!(s.by_device.len(), 1);
        assert_eq!(s.latencies.len(), 2);

        let mut strict = IoStats::new(10_000_000);
        strict.record(IoEvent {
            latency_ns: 5_000_000,
            tid: 1,
            dev: 0x0801,
            sectors: 8,
            op: 0,
        });
        assert_eq!(strict.slow, 0);
    }

    #[test]
    fn summary_computed() {
        let mut s = IoStats::new(100_000_000);
        for i in 1..=10u64 {
            s.record(IoEvent {
                latency_ns: i * 1_000_000,
                tid: 1,
                dev: 0,
                sectors: 1,
                op: 0,
            });
        }
        let sum = s.summary().unwrap();
        assert!(sum.p50_ns > 0);
        assert_eq!(sum.max_ns, 10_000_000);
    }
}
