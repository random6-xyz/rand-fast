use std::{collections::BTreeMap, collections::BTreeSet, convert::TryInto};

use anyhow::{Context, Result};
use aya::{Ebpf, include_bytes_aligned, maps::HashMap as AyaHashMap, maps::MapData};
use fast_common::OffCpuEvent;

use crate::{cli::OffCpuArgs, process, runtime};

/// Sleep/wakeup storms produce many events; 64 pages (256 KiB) per CPU keeps
/// event loss low.
const PERF_PAGE_COUNT: usize = 64;

#[derive(Debug, Default)]
struct OffCpuStats {
    waits: Vec<u64>,
    by_stack: BTreeMap<i64, Vec<u64>>,
    lost: u64,
}

impl OffCpuStats {
    fn record(&mut self, ev: OffCpuEvent) {
        self.waits.push(ev.wait_ns);
        self.by_stack.entry(ev.stack_id).or_default().push(ev.wait_ns);
    }
    fn record_lost(&mut self, c: u64) {
        self.lost = self.lost.saturating_add(c);
    }
    fn summary(&self) -> Option<Summary> {
        summary(&self.waits)
    }
}

impl runtime::EventHandler<OffCpuEvent> for OffCpuStats {
    fn on_event(&mut self, event: OffCpuEvent) {
        self.record(event);
    }

    fn on_lost(&mut self, count: u64) {
        self.record_lost(count);
    }
}

#[derive(Debug, Clone, Copy)]
struct Summary {
    p50_ns: u64,
    p95_ns: u64,
    p99_ns: u64,
    max_ns: u64,
}

fn summary(values: &[u64]) -> Option<Summary> {
    if values.is_empty() { return None; }
    let mut s = values.to_vec();
    s.sort_unstable();
    let pct = |p: f64| {
        let idx = ((p/100.0)*s.len() as f64).ceil() as usize;
        let idx = idx.clamp(1, s.len())-1;
        s[idx]
    };
    Some(Summary { p50_ns: pct(50.0), p95_ns: pct(95.0), p99_ns: pct(99.0), max_ns: *s.last().unwrap() })
}
fn format_ns(ns: u64) -> String {
    if ns < 1_000 { return format!("{ns} ns"); }
    let us = ns.saturating_add(500)/1_000;
    if us < 1_000 { return format!("{us} µs"); }
    if ns < 1_000_000_000 { return format!("{:.1} ms", ns as f64/1_000_000.0); }
    format!("{:.2} s", ns as f64/1_000_000_000.0)
}

pub fn run(args: OffCpuArgs) -> Result<()> {
    let pid = args.pid;
    let process_name = process::read_name(pid).with_context(|| format!("cannot read {pid}"))?;
    let initial_tids = process::thread_ids(pid).with_context(|| format!("cannot enumerate {pid}"))?;

    let mut bpf = Ebpf::load(include_bytes_aligned!(concat!(env!("OUT_DIR"), "/fast-ebpf")))
        .context("failed to load eBPF object; run as root or grant CAP_BPF and CAP_PERFMON")?;
    runtime::attach_tracepoint(&mut bpf, "sched", "sched_stat_sleep")?;
    runtime::attach_tracepoint(&mut bpf, "sched", "sched_wakeup")?;

    let mut target_tids = runtime::take_target_map(&mut bpf)?;
    let pending_map = bpf
        .take_map("OFFCPU_START")
        .context("eBPF map OFFCPU_START is missing")?;
    let mut pending: AyaHashMap<MapData, u32, u64> = pending_map
        .try_into()
        .context("OFFCPU_START has an unexpected map type or layout")?;

    let mut known = BTreeSet::new();
    let mut stats = OffCpuStats::default();
    let summary = runtime::run_collection(
        &mut bpf,
        &mut target_tids,
        &mut pending,
        &mut known,
        &initial_tids,
        &mut stats,
        runtime::CollectionOptions {
            pid,
            duration: args.duration,
            events_map: "OFFCPU_EVENTS",
            perf_page_count: PERF_PAGE_COUNT,
        },
    )?;

    println!("PID: {process_name} ({pid})");
    println!("Duration: {}", humantime::format_duration(summary.elapsed));
    if summary.interrupted { println!("Status: interrupted"); }
    println!("Samples: {}", stats.waits.len());
    println!("Lost: {}", stats.lost);
    println!();
    println!("Off-CPU wait");
    match stats.summary() {
        Some(s) => {
            println!("{:<8}{:>10}", "p50", format_ns(s.p50_ns));
            println!("{:<8}{:>10}", "p95", format_ns(s.p95_ns));
            println!("{:<8}{:>10}", "p99", format_ns(s.p99_ns));
            println!("{:<8}{:>10}", "max", format_ns(s.max_ns));
        }
        None => println!("No off-CPU samples collected. Test with futex contention: two threads contending on a mutex."),
    }
    println!();
    println!("Hot wait stacks");
    let mut hot: Vec<(i64, usize)> = stats.by_stack.iter().map(|(k,v)| (*k, v.len())).collect();
    hot.sort_by_key(|(_, count)| std::cmp::Reverse(*count));
    hot.truncate(5);
    if hot.is_empty() { println!("No stacks."); } else { for (id, cnt) in hot { println!("stack {id:<6} samples {cnt}"); } }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn wait_stack() {
        let mut s = OffCpuStats::default();
        s.record(OffCpuEvent { wait_ns: 10_000, stack_id: 5, tid: 1, reason: 0, _pad: 0, _pad2: 0 });
        s.record(OffCpuEvent { wait_ns: 20_000, stack_id: 5, tid: 1, reason: 0, _pad: 0, _pad2: 0 });
        assert_eq!(s.waits.len(), 2);
        assert_eq!(s.by_stack.len(), 1);
    }
}
