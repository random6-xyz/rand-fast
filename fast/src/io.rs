use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::Path,
};

use anyhow::{Context, Result};
use aya::{Ebpf, include_bytes_aligned};
use fast_common::{IoEvent, io_op_name};

use crate::{cli::IoArgs, process, runtime};

/// `block_rq_*` can be bursty on busy devices; 64 pages (256 KiB) per CPU
/// keeps event loss low.
const PERF_PAGE_COUNT: usize = 64;

/// Upper bound on rows in the slow-I/O table (the slowest ones are kept).
const SLOW_TABLE_ROWS: usize = 16;

/// Aggregate counters for one operation kind.
#[derive(Debug, Default, Clone, Copy)]
struct OpStats {
    count: u64,
    sectors: u64,
}

impl OpStats {
    fn record(&mut self, sectors: u32) {
        self.count += 1;
        self.sectors += u64::from(sectors);
    }
}

/// Per-device statistics: latency samples, operation split, and sectors moved.
#[derive(Debug, Default)]
struct DeviceStats {
    latencies: Vec<u64>,
    read: OpStats,
    write: OpStats,
    other: OpStats,
}

impl DeviceStats {
    fn record(&mut self, event: &IoEvent) {
        self.latencies.push(event.latency_ns);
        match event.op {
            0 => self.read.record(event.sectors),
            1 => self.write.record(event.sectors),
            _ => self.other.record(event.sectors),
        }
    }

    fn count(&self) -> usize {
        self.latencies.len()
    }

    fn sectors(&self) -> u64 {
        self.read.sectors + self.write.sectors + self.other.sectors
    }
}

/// One row of the slow-I/O table; ordered by latency for a bounded min-heap.
/// Equality is latency-based: two rows with the same latency are
/// interchangeable in the table.
#[derive(Debug, Clone, Copy)]
struct SlowEntry {
    latency_ns: u64,
    event: IoEvent,
}

impl PartialEq for SlowEntry {
    fn eq(&self, other: &Self) -> bool {
        self.latency_ns == other.latency_ns
    }
}

impl Eq for SlowEntry {}

impl Ord for SlowEntry {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.latency_ns.cmp(&other.latency_ns)
    }
}

impl PartialOrd for SlowEntry {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

#[derive(Debug)]
struct IoStats {
    threshold_ns: u64,
    latencies: Vec<u64>,
    by_device: BTreeMap<u32, DeviceStats>,
    /// Total number of I/Os above the threshold.
    slow: u64,
    /// The `SLOW_TABLE_ROWS` slowest I/Os above the threshold.
    slow_top: std::collections::BinaryHeap<std::cmp::Reverse<SlowEntry>>,
    lost: u64,
}

impl IoStats {
    fn new(threshold_ns: u64) -> Self {
        Self {
            threshold_ns,
            latencies: Vec::new(),
            by_device: BTreeMap::new(),
            slow: 0,
            slow_top: std::collections::BinaryHeap::new(),
            lost: 0,
        }
    }

    fn record(&mut self, event: IoEvent) {
        self.latencies.push(event.latency_ns);
        self.by_device.entry(event.dev).or_default().record(&event);
        if event.latency_ns > self.threshold_ns {
            self.slow += 1;
            let entry = std::cmp::Reverse(SlowEntry {
                latency_ns: event.latency_ns,
                event,
            });
            if self.slow_top.len() < SLOW_TABLE_ROWS {
                self.slow_top.push(entry);
            } else if let Some(std::cmp::Reverse(smallest)) = self.slow_top.peek()
                && entry.0 > *smallest
            {
                self.slow_top.pop();
                self.slow_top.push(entry);
            }
        }
    }

    fn record_lost(&mut self, count: u64) {
        self.lost = self.lost.saturating_add(count);
    }

    fn summary(&self) -> Option<Summary> {
        summary(&self.latencies)
    }

    /// Slow-I/O table rows, slowest first.
    fn slow_table(&self) -> Vec<SlowEntry> {
        let mut rows: Vec<_> = self
            .slow_top
            .iter()
            .map(|std::cmp::Reverse(entry)| *entry)
            .collect();
        rows.sort_by_key(|entry| std::cmp::Reverse(entry.latency_ns));
        rows
    }

    /// Operation split across all devices: (read, write, other).
    fn op_summary(&self) -> (OpStats, OpStats, OpStats) {
        let mut total = (OpStats::default(), OpStats::default(), OpStats::default());
        for device in self.by_device.values() {
            total.0.count += device.read.count;
            total.0.sectors += device.read.sectors;
            total.1.count += device.write.count;
            total.1.sectors += device.write.sectors;
            total.2.count += device.other.count;
            total.2.sectors += device.other.sectors;
        }
        total
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

fn format_bytes(bytes: u64) -> String {
    const KIB: f64 = 1024.0;
    let value = bytes as f64;
    if value < KIB {
        return format!("{bytes} B");
    }
    if value < KIB * KIB {
        return format!("{:.1} KiB", value / KIB);
    }
    if value < KIB * KIB * KIB {
        return format!("{:.1} MiB", value / (KIB * KIB));
    }
    format!("{:.2} GiB", value / (KIB * KIB * KIB))
}

/// Resolves a kernel `dev_t` (major << 20 | minor) to its sysfs device name,
/// for example `vdb1` or `sda`.
fn block_dev_name(dev: u32) -> Option<String> {
    let major = dev >> 20;
    let minor = dev & 0xFFFFF;
    let path = fs::canonicalize(format!("/sys/dev/block/{major}:{minor}")).ok()?;
    Path::new(&path)
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
}

fn device_label(dev: u32) -> String {
    let major = dev >> 20;
    let minor = dev & 0xFFFFF;
    match block_dev_name(dev) {
        Some(name) => format!("{name} ({major}:{minor})"),
        None => format!("{major}:{minor}"),
    }
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

fn print_op_split(read: OpStats, write: OpStats, other: OpStats) {
    let mut parts = Vec::new();
    for (stats, name) in [(read, "read"), (write, "write"), (other, "other")] {
        if stats.count > 0 {
            parts.push(format!(
                "{name} {} ({})",
                stats.count,
                format_bytes(stats.sectors * 512)
            ));
        }
    }
    if parts.is_empty() {
        return;
    }
    println!("ops: {}", parts.join(", "));
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
    let collection = runtime::run_collection(
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
    println!(
        "Duration: {}",
        humantime::format_duration(collection.elapsed)
    );
    if collection.interrupted {
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
            println!("{:<8}{:>10}", "samples", s.count);
            println!("{:<8}{:>10}", "p50", format_ns(s.p50_ns));
            println!("{:<8}{:>10}", "p95", format_ns(s.p95_ns));
            println!("{:<8}{:>10}", "p99", format_ns(s.p99_ns));
            println!("{:<8}{:>10}", "max", format_ns(s.max_ns));
            let (read, write, other) = stats.op_summary();
            print_op_split(read, write, other);
        }
        None => println!("No I/O samples were collected."),
    }
    println!();

    println!("Per-device latency");
    let devices: Vec<(&u32, &DeviceStats)> = stats.by_device.iter().collect();
    if devices.is_empty() {
        println!("No per-device samples were collected.");
    } else {
        for (dev, device) in devices {
            println!(
                "dev {:<12} samples {:<6} sectors {}",
                device_label(*dev),
                device.count(),
                device.sectors()
            );
            let (read, write, other) = (device.read, device.write, device.other);
            print_op_split(read, write, other);
            if let Some(s) = summary(&device.latencies) {
                println!(
                    "  p50 {:>10} p95 {:>10} p99 {:>10} max {:>10}",
                    format_ns(s.p50_ns),
                    format_ns(s.p95_ns),
                    format_ns(s.p99_ns),
                    format_ns(s.max_ns)
                );
            }
        }
    }
    println!();

    let slow_rows = stats.slow_table();
    println!(
        "Slow I/O > {} (top {} of {})",
        humantime::format_duration(threshold),
        slow_rows.len(),
        stats.slow
    );
    if slow_rows.is_empty() {
        println!("(none)");
    } else {
        println!(
            "{:>10}  {:<12}  {:<5}  {:>8}  {:>9}  {:>7}",
            "latency", "device", "op", "sectors", "bytes", "tid"
        );
        for row in slow_rows {
            println!(
                "{:>10}  {:<12}  {:<5}  {:>8}  {:>9}  {:>7}",
                format_ns(row.latency_ns),
                device_label(row.event.dev),
                io_op_name(row.event.op),
                row.event.sectors,
                format_bytes(u64::from(row.event.sectors) * 512),
                row.event.tid
            );
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn io_event(latency_ms: u64, dev: u32, op: u32, sectors: u32) -> IoEvent {
        IoEvent {
            latency_ns: latency_ms * 1_000_000,
            tid: 1,
            dev,
            sectors,
            op,
        }
    }

    #[test]
    fn counts_slow_and_device() {
        let mut s = IoStats::new(1_000_000);
        s.record(io_event(5, 0x0801, 0, 8));
        s.record(io_event(5, 0x0801, 0, 8));
        assert_eq!(s.slow, 2);
        assert_eq!(s.by_device.len(), 1);
        assert_eq!(s.latencies.len(), 2);

        let mut strict = IoStats::new(10_000_000);
        strict.record(io_event(5, 0x0801, 0, 8));
        assert_eq!(strict.slow, 0);
    }

    #[test]
    fn summary_computed() {
        let mut s = IoStats::new(100_000_000);
        for i in 1..=10u64 {
            s.record(io_event(i, 0, 0, 1));
        }
        let sum = s.summary().unwrap();
        assert!(sum.p50_ns > 0);
        assert_eq!(sum.max_ns, 10_000_000);
    }

    #[test]
    fn splits_operations_per_device() {
        let mut s = IoStats::new(1_000_000_000);
        s.record(io_event(1, 0x0801, 0, 8));
        s.record(io_event(1, 0x0801, 0, 8));
        s.record(io_event(1, 0x0801, 1, 16));
        s.record(io_event(1, 0x0801, 7, 4));
        s.record(io_event(1, 0x0802, 1, 32));

        let device = &s.by_device[&0x0801];
        assert_eq!(device.read.count, 2);
        assert_eq!(device.read.sectors, 16);
        assert_eq!(device.write.count, 1);
        assert_eq!(device.write.sectors, 16);
        assert_eq!(device.other.count, 1);
        assert_eq!(device.other.sectors, 4);
        assert_eq!(device.sectors(), 36);

        let (read, write, other) = s.op_summary();
        assert_eq!(read.count, 2);
        assert_eq!(write.count, 2);
        assert_eq!(write.sectors, 48);
        assert_eq!(other.count, 1);
    }

    #[test]
    fn slow_table_keeps_slowest_rows() {
        let mut s = IoStats::new(1_000_000);
        // 20 slow I/Os strictly above the 1 ms threshold: 2..=21 ms.
        for i in 2..=21u64 {
            s.record(io_event(i, 0x0801, 0, 8));
        }
        assert_eq!(s.slow, 20);
        let rows = s.slow_table();
        assert_eq!(rows.len(), SLOW_TABLE_ROWS);
        // The slowest (21 ms) first, truncated before the fastest (6 ms).
        assert_eq!(rows[0].latency_ns, 21_000_000);
        assert_eq!(rows[SLOW_TABLE_ROWS - 1].latency_ns, 6_000_000);
    }

    #[test]
    fn formats_bytes() {
        assert_eq!(format_bytes(512), "512 B");
        assert_eq!(format_bytes(1024), "1.0 KiB");
        assert_eq!(format_bytes(512 * 1024), "512.0 KiB");
        assert_eq!(format_bytes(2 * 1024 * 1024), "2.0 MiB");
    }

    #[test]
    fn formats_seconds() {
        assert_eq!(format_ns(1_250_000_000), "1.25 s");
        assert_eq!(format_ns(2_000_000_000), "2.00 s");
    }

    #[test]
    fn op_names() {
        assert_eq!(io_op_name(0), "read");
        assert_eq!(io_op_name(1), "write");
        assert_eq!(io_op_name(7), "other");
    }
}
