use std::{
    collections::{BTreeMap, BTreeSet},
    convert::TryInto,
    fs,
};

use anyhow::{Context, Result, bail};
use aya::{Ebpf, include_bytes_aligned, maps::HashMap as AyaHashMap, maps::MapData};
use fast_common::CpuSampleEvent;

use crate::{cli::CpuArgs, process, runtime};

/// One `CpuSampleEvent` is emitted per run of a target thread, matching the
/// scheduler event volume; the default buffer is sufficient.
const PERF_PAGE_COUNT: usize = runtime::DEFAULT_PERF_PAGE_COUNT;

#[derive(Debug, Default, Clone, Copy)]
struct CpuUsage {
    utime: u64,
    stime: u64,
}

#[derive(Debug, Default)]
struct CpuStats {
    samples: Vec<CpuSampleEvent>,
    stack_counts: BTreeMap<i64, usize>,
    lost: u64,
    start_usage: Option<CpuUsage>,
    end_usage: Option<CpuUsage>,
    start_system: Option<u64>,
    end_system: Option<u64>,
}

impl CpuStats {
    fn record(&mut self, sample: CpuSampleEvent) {
        // Count hot stacks by kernel stack id
        if sample.kernel_stack_id >= 0 {
            *self.stack_counts.entry(sample.kernel_stack_id).or_default() += 1;
        }
        self.samples.push(sample);
    }

    fn record_lost(&mut self, count: u64) {
        self.lost = self.lost.saturating_add(count);
    }

    fn hot_stacks(&self, n: usize) -> Vec<(i64, usize)> {
        let mut v: Vec<_> = self.stack_counts.iter().map(|(k, c)| (*k, *c)).collect();
        v.sort_by_key(|(_, count)| std::cmp::Reverse(*count));
        v.truncate(n);
        v
    }

    fn cpu_percent(&self) -> Option<f64> {
        let start = self.start_usage.as_ref()?;
        let end = self.end_usage.as_ref()?;
        let sys_start = self.start_system?;
        let sys_end = self.end_system?;
        let proc_delta = (end.utime + end.stime).saturating_sub(start.utime + start.stime);
        let sys_delta = sys_end.saturating_sub(sys_start);
        if sys_delta == 0 {
            return None;
        }
        // ticks to percent: proc / sys * 100, scaled by num_cpus approximation via sys total
        Some((proc_delta as f64 / sys_delta as f64) * 100.0)
    }
}

impl runtime::EventHandler<CpuSampleEvent> for CpuStats {
    fn on_event(&mut self, event: CpuSampleEvent) {
        self.record(event);
    }

    fn on_lost(&mut self, count: u64) {
        self.record_lost(count);
    }
}

fn read_proc_cpu_usage(pid: u32) -> Result<CpuUsage> {
    let stat = fs::read_to_string(format!("/proc/{pid}/stat"))
        .with_context(|| format!("failed to read /proc/{pid}/stat"))?;
    // /proc/pid/stat: field 14 utime, 15 stime (1-indexed, but comm may contain spaces)
    // Find last ')'
    let end = stat.rfind(')').context("malformed stat")?;
    let after = &stat[end + 2..];
    let fields: Vec<&str> = after.split_whitespace().collect();
    // fields[11] is utime (14-3), fields[12] is stime
    if fields.len() < 13 {
        bail!("stat has too few fields");
    }
    let utime: u64 = fields[11].parse().context("parse utime")?;
    let stime: u64 = fields[12].parse().context("parse stime")?;
    Ok(CpuUsage { utime, stime })
}

fn read_system_ticks() -> Result<u64> {
    let content = fs::read_to_string("/proc/stat").context("read /proc/stat")?;
    let line = content.lines().next().context("empty /proc/stat")?;
    let parts: Vec<&str> = line.split_whitespace().collect();
    // cpu  user nice system idle iowait irq softirq steal guest
    let mut total = 0u64;
    for p in &parts[1..] {
        if let Ok(v) = p.parse::<u64>() {
            total = total.saturating_add(v);
        }
    }
    Ok(total)
}

pub fn run(args: CpuArgs) -> Result<()> {
    let pid = args.pid;
    let process_name = process::read_name(pid)
        .with_context(|| format!("cannot read process {pid}; check that it exists"))?;
    let initial_tids = process::thread_ids(pid)
        .with_context(|| format!("cannot enumerate threads for process {pid}"))?;

    let mut bpf = Ebpf::load(include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/fast-ebpf"
    )))
    .context("failed to load the eBPF object; run as root or grant CAP_BPF and CAP_PERFMON")?;
    runtime::attach_tracepoint(&mut bpf, "sched", "sched_wakeup")?;
    runtime::attach_tracepoint(&mut bpf, "sched", "sched_switch")?;

    let mut target_tids = runtime::take_target_map(&mut bpf)?;
    // Keep PENDING_WAKEUPS for scheduler correlation, even if CPU mode doesn't strictly need it
    let pending_map = bpf
        .take_map("PENDING_WAKEUPS")
        .context("eBPF map PENDING_WAKEUPS is missing")?;
    let mut pending_wakeups: AyaHashMap<MapData, u32, [u64; 2]> = pending_map
        .try_into()
        .context("PENDING_WAKEUPS has an unexpected map type or layout")?;

    let mut known_tids = BTreeSet::new();
    let mut stats = CpuStats {
        start_usage: read_proc_cpu_usage(pid).ok(),
        start_system: read_system_ticks().ok(),
        ..CpuStats::default()
    };
    let summary = runtime::run_collection(
        &mut bpf,
        &mut target_tids,
        &mut pending_wakeups,
        &mut known_tids,
        &initial_tids,
        &mut stats,
        runtime::CollectionOptions {
            pid,
            duration: args.duration,
            events_map: "CPU_EVENTS",
            perf_page_count: PERF_PAGE_COUNT,
        },
    )?;

    stats.end_usage = read_proc_cpu_usage(pid).ok();
    stats.end_system = read_system_ticks().ok();

    print_cpu_report(
        pid,
        &process_name,
        summary.elapsed,
        &stats,
        summary.interrupted,
        summary.process_exited,
    );
    Ok(())
}

fn print_cpu_report(
    pid: u32,
    name: &str,
    duration: std::time::Duration,
    stats: &CpuStats,
    interrupted: bool,
    exited: bool,
) {
    use humantime::format_duration;
    println!("PID: {name} ({pid})");
    println!("Duration: {}", format_duration(duration));
    if interrupted {
        println!("Status: interrupted");
    } else if exited {
        println!("Status: process exited");
    }
    println!("Samples: {}", stats.samples.len());
    println!("Lost: {}", stats.lost);
    if let Some(p) = stats.cpu_percent() {
        println!("CPU usage: {:.1}% (over {:.1}s wall, {} ticks total)", p, duration.as_secs_f64(), stats.end_system.unwrap_or(0) - stats.start_system.unwrap_or(0));
    } else {
        println!("CPU usage: unavailable (could not read /proc)");
    }
    println!();
    println!("On-CPU samples (hot stacks)");
    let hot = stats.hot_stacks(5);
    if hot.is_empty() {
        println!("No stack samples collected.");
    } else {
        for (id, cnt) in hot {
            println!("stack {id:<6} samples {cnt}");
        }
    }
    println!();
    println!("Per-CPU samples");
    let mut per_cpu: BTreeMap<u32, usize> = BTreeMap::new();
    for s in &stats.samples {
        *per_cpu.entry(s.cpu).or_default() += 1;
    }
    if per_cpu.is_empty() {
        println!("No per-CPU samples.");
    } else {
        for (cpu, cnt) in per_cpu {
            println!("cpu {cpu:<4} samples {cnt}");
        }
    }
    println!();
    println!("Correlation");
    if let Some(p) = stats.cpu_percent() {
        if p > 80.0 && !stats.samples.is_empty() {
            println!("CPU saturation likely contributes to scheduler latency (CPU {:.1}% with {} samples)", p, stats.samples.len());
        } else if p > 50.0 {
            println!("Moderate CPU pressure ({:.1}%)", p);
        } else {
            println!("CPU not saturated ({:.1}%)", p);
        }
    } else {
        println!("Correlation unavailable");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(tid: u32, cpu: u32, kstack: i64) -> CpuSampleEvent {
        CpuSampleEvent { tid, cpu, kernel_stack_id: kstack, user_stack_id: -1, _pad: 0, _pad2: 0 }
    }

    #[test]
    fn tracks_hot_stacks() {
        let mut stats = CpuStats::default();
        stats.record(sample(1, 0, 10));
        stats.record(sample(1, 0, 10));
        stats.record(sample(1, 0, 11));
        let hot = stats.hot_stacks(1);
        assert_eq!(hot[0], (10, 2));
    }

    #[test]
    fn cpu_percent_calc() {
        let stats = CpuStats {
            start_usage: Some(CpuUsage { utime: 100, stime: 0 }),
            end_usage: Some(CpuUsage { utime: 200, stime: 0 }),
            start_system: Some(1000),
            end_system: Some(2000),
            ..CpuStats::default()
        };
        let p = stats.cpu_percent().unwrap();
        assert!((p - 10.0).abs() < 0.1);
    }
}
