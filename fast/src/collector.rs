use std::collections::BTreeSet;

use anyhow::{Context, Result};
use aya::{Ebpf, include_bytes_aligned, maps::HashMap as AyaHashMap, maps::MapData};
use fast_common::SchedulerLatencyEvent;

use crate::{
    cli::SchedArgs,
    output,
    process,
    runtime,
    stats::Statistics,
};

/// The scheduler emits at most one event per wakeup of the target threads, so
/// the default buffer size matches earlier releases.
const PERF_PAGE_COUNT: usize = runtime::DEFAULT_PERF_PAGE_COUNT;

impl runtime::EventHandler<SchedulerLatencyEvent> for Statistics {
    fn on_event(&mut self, event: SchedulerLatencyEvent) {
        self.record(event);
    }

    fn on_lost(&mut self, count: u64) {
        self.record_lost(count);
    }
}

pub fn run(args: SchedArgs) -> Result<()> {
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
    let pending_map = bpf
        .take_map("PENDING_WAKEUPS")
        .context("eBPF map PENDING_WAKEUPS is missing")?;
    let mut pending_wakeups: AyaHashMap<MapData, u32, [u64; 2]> = pending_map
        .try_into()
        .context("PENDING_WAKEUPS has an unexpected map type or layout")?;

    let mut known_tids = BTreeSet::new();
    let mut stats = Statistics::default();
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
            events_map: "EVENTS",
            perf_page_count: PERF_PAGE_COUNT,
        },
    )?;

    output::print_report(
        pid,
        &process_name,
        summary.elapsed,
        &stats,
        summary.interrupted,
        summary.process_exited,
    );
    Ok(())
}
