use std::collections::{BTreeMap, BTreeSet};

use anyhow::{Context, Result};
use aya::{
    Ebpf, include_bytes_aligned,
    maps::{HashMap as AyaHashMap, MapData},
};
use fast_common::{
    COLLECT_OFFCPU, OFFCPU_REASON_IO, OFFCPU_REASON_WAIT, OffCpuEvent, OffCpuPending,
};

use crate::{
    cli::OffCpuArgs,
    process, runtime,
    symbolize::{Frame, StackMaps, StackSymbolizer},
};

/// Sleep/wakeup storms produce many events; 64 pages (256 KiB) per CPU keeps
/// event loss low.
const PERF_PAGE_COUNT: usize = 64;

/// How many wait stacks the report prints before truncating.
const MAX_STACKS_SHOWN: usize = 5;

/// How many frames of each stack are printed.
const MAX_FRAMES_SHOWN: usize = 8;

/// A wait reason, either the coarse one the kernel task state gives or the
/// finer one recovered from the symbolized blocking stack.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord)]
pub enum WaitReason {
    /// Waiting on a futex, condition variable or sleep. Detected from the
    /// blocking stack rather than the task state, because the kernel blocks
    /// a futex wait and a timer sleep the same way.
    #[default]
    Futex,
    /// Waiting on disk or network I/O.
    Io,
    /// Waiting for a page to come back from swap or the page cache.
    Memory,
    /// Sleeping, with no more specific cause found.
    Sleep,
    /// The task state gave a hint but the stack did not name a cause.
    Wait,
    /// Neither the task state nor the stack was usable.
    Unknown,
}

impl WaitReason {
    /// The label used in the report.
    pub fn label(&self) -> &'static str {
        match self {
            Self::Futex => "futex / lock",
            Self::Io => "disk or network I/O",
            Self::Memory => "page or swap",
            Self::Sleep => "sleep",
            Self::Wait => "wait",
            Self::Unknown => "unknown",
        }
    }

    /// The coarse reason carried in the event, before stack inspection.
    fn from_event(reason: u32) -> Self {
        match reason {
            OFFCPU_REASON_IO => Self::Io,
            OFFCPU_REASON_WAIT => Self::Wait,
            _ => Self::Unknown,
        }
    }

    /// Refines a coarse reason using the symbolized blocking stack.
    ///
    /// The task state only separates interruptible from uninterruptible
    /// waits, which lumps futexes and timers together and cannot tell a page
    /// fault from a disk read. The blocking stack names the actual path, so
    /// the top frames are matched against the functions that block on each
    /// of those.
    ///
    /// The coarse reason is only overridden when the stack names something
    /// more specific, so an unresolved stack degrades to what the kernel
    /// already told us rather than to "unknown".
    fn refine(self, frames: &[Frame]) -> Self {
        for frame in frames {
            let Some(name) = frame.symbol_name() else {
                continue;
            };
            if is_futex_frame(name) {
                return Self::Futex;
            }
            if is_memory_frame(name) {
                return Self::Memory;
            }
            if is_io_frame(name) {
                return Self::Io;
            }
        }
        match self {
            Self::Wait => Self::Sleep,
            other => other,
        }
    }
}

/// Frames that mean the thread parked on a futex.
fn is_futex_frame(symbol: &str) -> bool {
    symbol.contains("futex")
}

/// Frames that mean the thread is waiting for a page or a swap slot.
fn is_memory_frame(symbol: &str) -> bool {
    symbol.contains("wait_on_page")
        || symbol.contains("wait_on_bit")
        || symbol.contains("swap_cluster")
        || symbol.contains("swap_page")
        || symbol.contains("swap_in")
        || symbol.contains("pagefault")
}

/// Frames that mean the thread is waiting on a device or the page cache.
fn is_io_frame(symbol: &str) -> bool {
    symbol.contains("blkdev_")
        || symbol.contains("wait_for_completion")
        || symbol.contains("io_schedule")
        || symbol.contains("filemap_")
        || symbol.contains("tcp_")
        || symbol.contains("netif_")
}

/// One blocking stack and the wait time attributed to it.
#[derive(Debug, Default, Clone)]
pub struct WaitStack {
    /// Number of waits that ended here.
    samples: usize,
    /// Summed wait time, in nanoseconds. This is the ranking signal: a stack
    /// hit rarely but for a long time matters more than one hit constantly
    /// for microseconds.
    total_ns: u64,
    /// Longest single wait, in nanoseconds.
    max_ns: u64,
    /// The reason the last event for this stack resolved to. A stack is one
    /// blocking path, so it has one reason.
    reason: WaitReason,
}

/// Aggregated off-CPU statistics for one run.
#[derive(Debug, Default)]
pub struct OffCpuStats {
    waits: Vec<u64>,
    by_stack: BTreeMap<i64, WaitStack>,
    by_reason: BTreeMap<WaitReason, ReasonTotals>,
    lost: u64,
}

/// Waits and total time for one reason.
#[derive(Debug, Default, Clone, Copy)]
pub struct ReasonTotals {
    /// Number of waits.
    pub samples: usize,
    /// Summed wait time in nanoseconds.
    pub total_ns: u64,
}

impl OffCpuStats {
    fn record(&mut self, event: OffCpuEvent) {
        self.record_with(event, WaitReason::from_event(event.reason));
    }

    /// Records a wait whose reason has already been resolved.
    fn record_with(&mut self, event: OffCpuEvent, reason: WaitReason) {
        self.waits.push(event.wait_ns);

        let entry = self.by_stack.entry(event.stack_id).or_default();
        entry.samples += 1;
        entry.total_ns = entry.total_ns.saturating_add(event.wait_ns);
        entry.max_ns = entry.max_ns.max(event.wait_ns);
        entry.reason = reason;

        let totals = self.by_reason.entry(reason).or_default();
        totals.samples += 1;
        totals.total_ns = totals.total_ns.saturating_add(event.wait_ns);
    }

    /// Replaces the reason of every wait attributed to a stack, once that
    /// stack has been symbolized.
    ///
    /// Reasons are counted per reason as events arrive, but the finer
    /// classification needs the stack, which is only read after collection
    /// has finished. The wait itself is counted in exactly one bucket either
    /// way, so the totals stay consistent.
    fn refine_stack_reason(&mut self, stack_id: i64, reason: WaitReason) {
        let Some(entry) = self.by_stack.get_mut(&stack_id) else {
            return;
        };
        if entry.reason == reason {
            return;
        }
        let samples = entry.samples;
        let total_ns = entry.total_ns;
        if let Some(previous) = self.by_reason.get_mut(&entry.reason) {
            previous.samples = previous.samples.saturating_sub(samples);
            previous.total_ns = previous.total_ns.saturating_sub(total_ns);
            if previous.samples == 0 {
                self.by_reason.remove(&entry.reason);
            }
        }
        let totals = self.by_reason.entry(reason).or_default();
        totals.samples += samples;
        totals.total_ns = totals.total_ns.saturating_add(total_ns);
        entry.reason = reason;
    }

    fn record_lost(&mut self, count: u64) {
        self.lost = self.lost.saturating_add(count);
    }

    /// Number of waits observed.
    pub fn sample_count(&self) -> usize {
        self.waits.len()
    }

    /// Records the kernel's dropped-event count.
    pub fn lost(&self) -> u64 {
        self.lost
    }

    /// Summed off-CPU time in nanoseconds.
    pub fn total_ns(&self) -> u64 {
        self.waits
            .iter()
            .fold(0u64, |acc, wait| acc.saturating_add(*wait))
    }

    /// p50, p95 and p99 of the waits, in nanoseconds.
    pub fn percentiles(&self) -> (u64, u64, u64) {
        if self.waits.is_empty() {
            return (0, 0, 0);
        }
        let mut sorted = self.waits.clone();
        sorted.sort_unstable();
        let rank = |percentile: usize| -> u64 {
            let index = (sorted.len() * percentile).div_ceil(100);
            sorted[index.saturating_sub(1)]
        };
        (rank(50), rank(95), rank(99))
    }

    /// Waits ranked by total time, longest first.
    pub fn stacks_by_total_time(&self) -> Vec<(i64, &WaitStack)> {
        let mut ordered: Vec<(i64, &WaitStack)> =
            self.by_stack.iter().map(|(id, s)| (*id, s)).collect();
        ordered.sort_by(|a, b| {
            b.1.total_ns
                .cmp(&a.1.total_ns)
                // The stack id breaks ties so the report is reproducible.
                .then(a.0.cmp(&b.0))
        });
        ordered
    }

    /// Reasons ranked by total time, longest first.
    pub fn reasons_by_total_time(&self) -> Vec<(WaitReason, ReasonTotals)> {
        let mut ordered: Vec<(WaitReason, ReasonTotals)> =
            self.by_reason.iter().map(|(r, t)| (*r, *t)).collect();
        ordered.sort_by(|a, b| b.1.total_ns.cmp(&a.1.total_ns).then(a.0.cmp(&b.0)));
        ordered
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

fn format_ns(ns: u64) -> String {
    if ns < 1_000 {
        return format!("{ns} ns");
    }
    let us = ns.saturating_add(500) / 1_000;
    if us < 1_000 {
        return format!("{us} us");
    }
    if ns < 1_000_000_000 {
        return format!("{:.1} ms", ns as f64 / 1_000_000.0);
    }
    format!("{:.2} s", ns as f64 / 1_000_000_000.0)
}

pub fn run(args: OffCpuArgs) -> Result<()> {
    let pid = args.pid;
    let process_name = process::read_name(pid).with_context(|| format!("cannot read {pid}"))?;
    let initial_tids =
        process::thread_ids(pid).with_context(|| format!("cannot enumerate {pid}"))?;

    let mut bpf = Ebpf::load(include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/fast-ebpf"
    )))
    .context("failed to load eBPF object; run as root or grant CAP_BPF and CAP_PERFMON")?;
    // The switch handler records when a target thread starts waiting, together
    // with the stack that blocked it, and the wakeup handler pairs it into an
    // off-CPU event, so both must attach.
    runtime::attach_tracepoint(&mut bpf, "sched", "sched_switch")?;
    runtime::attach_tracepoint(&mut bpf, "sched", "sched_wakeup")?;

    let mut target_tids = runtime::take_target_map(&mut bpf)?;
    // Pending waits live in OFFCPU_START; clearing it when a target thread
    // exits prevents stale entries from pairing with reused TIDs.
    let pending_map = bpf
        .take_map("OFFCPU_START")
        .context("eBPF map OFFCPU_START is missing")?;
    let mut offcpu_start: AyaHashMap<MapData, u32, OffCpuPending> = pending_map
        .try_into()
        .context("OFFCPU_START has an unexpected map type or layout")?;
    let mut known = BTreeSet::new();
    let mut stats = OffCpuStats::default();
    let summary = runtime::run_collection(
        &mut bpf,
        &mut target_tids,
        &mut offcpu_start,
        &mut known,
        &initial_tids,
        &mut stats,
        runtime::CollectionOptions {
            pid,
            duration: args.duration,
            events_map: "OFFCPU_EVENTS",
            perf_page_count: PERF_PAGE_COUNT,
            mode: COLLECT_OFFCPU,
        },
    )?;

    // The stack maps are only needed for the report, and reading them costs
    // nothing once collection has stopped.
    let stack_maps = StackMaps::take(&mut bpf)?;
    let mut symbolizer = StackSymbolizer::new(pid);

    // Refine each stack's reason from its symbols, then rebuild the reason
    // totals from the refined values.
    let ranked_ids: Vec<i64> = stats.by_stack.keys().copied().collect();
    for stack_id in &ranked_ids {
        let coarse = stats
            .by_stack
            .get(stack_id)
            .map(|stack| stack.reason)
            .unwrap_or(WaitReason::Unknown);
        let frames = match stack_maps.read(*stack_id, false) {
            Ok(ips) => symbolizer.kernel_frames(&ips),
            Err(_) => Vec::new(),
        };
        stats.refine_stack_reason(*stack_id, coarse.refine(&frames));
    }

    print_report(
        &process_name,
        pid,
        summary.elapsed,
        &stats,
        summary.interrupted,
    );

    print_stacks(&mut symbolizer, &stats, &stack_maps);
    Ok(())
}

fn print_report(
    name: &str,
    pid: u32,
    elapsed: std::time::Duration,
    stats: &OffCpuStats,
    interrupted: bool,
) {
    println!("PID: {name} ({pid})");
    println!("Duration: {}", humantime::format_duration(elapsed));
    if interrupted {
        println!("Status: interrupted");
    }
    println!("Samples: {}", stats.sample_count());
    println!("Lost: {}", stats.lost());
    println!("Total off-CPU: {}", format_ns(stats.total_ns()));

    let (p50, p95, p99) = stats.percentiles();
    println!();
    println!("Off-CPU wait");
    if stats.sample_count() == 0 {
        println!("No off-CPU samples collected.");
        println!("Test with: fast-workload lock-hog --duration 30s --workers 16");
    } else {
        println!("{:<8}{:>10}", "p50", format_ns(p50));
        println!("{:<8}{:>10}", "p95", format_ns(p95));
        println!("{:<8}{:>10}", "p99", format_ns(p99));
    }

    println!();
    println!("Wait reasons (by total time)");
    let reasons = stats.reasons_by_total_time();
    if reasons.is_empty() {
        println!("No waits recorded.");
    } else {
        let total = stats.total_ns().max(1);
        for (reason, totals) in &reasons {
            println!(
                "  {:<20} {:>10}  {:>5} waits  {:>5.1}%",
                reason.label(),
                format_ns(totals.total_ns),
                totals.samples,
                totals.total_ns as f64 / total as f64 * 100.0
            );
        }
    }
}

fn print_stacks(symbolizer: &mut StackSymbolizer, stats: &OffCpuStats, stack_maps: &StackMaps) {
    println!();
    println!("Top wait stacks (by total time)");
    let hot = stats.stacks_by_total_time();
    if hot.is_empty() {
        println!("No stacks.");
        return;
    }
    for (stack_id, stack) in hot.iter().take(MAX_STACKS_SHOWN) {
        println!(
            "  stack {stack_id}  {} total  {} max  {} waits  {}",
            format_ns(stack.total_ns),
            format_ns(stack.max_ns),
            stack.samples,
            stack.reason.label()
        );
        let frames = match stack_maps.read(*stack_id, false) {
            Ok(ips) => symbolizer.kernel_frames(&ips),
            Err(error) => {
                println!("    (stack unavailable: {error})");
                continue;
            }
        };
        if frames.is_empty() {
            println!("    (no stack captured)");
            continue;
        }
        for (depth, frame) in frames.iter().enumerate() {
            if depth == MAX_FRAMES_SHOWN {
                println!("    ... {} more frames", frames.len() - MAX_FRAMES_SHOWN);
                break;
            }
            println!("    {depth:<2} {}", frame.render());
        }
    }
    if hot.len() > MAX_STACKS_SHOWN {
        println!(
            "  ... {} more stack(s) not shown",
            hot.len() - MAX_STACKS_SHOWN
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn frame(symbol: &str) -> Frame {
        Frame {
            symbol: Some(symbol.to_string()),
            module: Some("vmlinux".to_string()),
            ip: 0x1000,
            kernel: true,
        }
    }

    fn event(wait_ns: u64, stack_id: i64, reason: u32) -> OffCpuEvent {
        OffCpuEvent {
            wait_ns,
            stack_id,
            tid: 1,
            reason,
            _pad: 0,
            _pad2: 0,
        }
    }

    #[test]
    fn formats_durations_at_each_scale() {
        assert_eq!(format_ns(999), "999 ns");
        assert_eq!(format_ns(1_000), "1 us");
        assert_eq!(format_ns(999_499), "999 us");
        // Rounding up must carry into the next unit rather than printing
        // "1000 us", which reads as a bug.
        assert_eq!(format_ns(999_999), "1.0 ms");
        assert_eq!(format_ns(1_500_000), "1.5 ms");
        assert_eq!(format_ns(2_500_000_000), "2.50 s");
    }

    #[test]
    fn sums_waits_and_ranks_stacks_by_total_time() {
        let mut s = OffCpuStats::default();
        // Stack 1: many short waits. Stack 2: one long wait. Stack 2 must rank
        // first, because total time is what a user feels.
        s.record(event(1_000, 1, OFFCPU_REASON_WAIT));
        s.record(event(1_000, 1, OFFCPU_REASON_WAIT));
        s.record(event(1_000, 1, OFFCPU_REASON_WAIT));
        s.record(event(500_000, 2, OFFCPU_REASON_IO));

        assert_eq!(s.sample_count(), 4);
        assert_eq!(s.total_ns(), 503_000);
        let ranked = s.stacks_by_total_time();
        assert_eq!(ranked[0].0, 2);
        assert_eq!(ranked[0].1.total_ns, 500_000);
        assert_eq!(ranked[0].1.max_ns, 500_000);
        assert_eq!(ranked[1].1.samples, 3);
    }

    #[test]
    fn groups_reasons_from_the_task_state() {
        let mut s = OffCpuStats::default();
        s.record(event(1_000, 1, OFFCPU_REASON_WAIT));
        s.record(event(2_000, 2, OFFCPU_REASON_IO));
        s.record(event(4_000, 3, OFFCPU_REASON_IO));

        let reasons = s.reasons_by_total_time();
        assert_eq!(reasons[0].0, WaitReason::Io);
        assert_eq!(reasons[0].1.total_ns, 6_000);
        assert_eq!(reasons[0].1.samples, 2);
        assert_eq!(reasons[1].0, WaitReason::Wait);
        assert_eq!(reasons[1].1.total_ns, 1_000);
    }

    #[test]
    fn refines_a_wait_reason_into_futex() {
        let mut s = OffCpuStats::default();
        // The task state only says "interruptible"; the stack says futex.
        s.record(event(1_000, 7, OFFCPU_REASON_WAIT));
        s.refine_stack_reason(7, WaitReason::Futex);

        let reasons = s.reasons_by_total_time();
        assert_eq!(reasons.len(), 1);
        assert_eq!(reasons[0].0, WaitReason::Futex);
        assert_eq!(reasons[0].1.total_ns, 1_000);
        assert_eq!(reasons[0].1.samples, 1);
    }

    #[test]
    fn refining_moves_time_between_reason_buckets() {
        let mut s = OffCpuStats::default();
        s.record(event(1_000, 7, OFFCPU_REASON_WAIT));
        s.record(event(3_000, 7, OFFCPU_REASON_WAIT));
        s.record(event(5_000, 8, OFFCPU_REASON_IO));
        assert_eq!(s.total_ns(), 9_000);

        s.refine_stack_reason(7, WaitReason::Futex);

        let reasons = s.reasons_by_total_time();
        let futex = reasons
            .iter()
            .find(|(r, _)| *r == WaitReason::Futex)
            .unwrap();
        assert_eq!(futex.1.total_ns, 4_000);
        assert_eq!(futex.1.samples, 2);
        // The old bucket is gone rather than left at zero.
        assert!(!reasons.iter().any(|(r, _)| *r == WaitReason::Wait));
        // Refining must not change the overall total.
        assert_eq!(s.total_ns(), 9_000);
    }

    #[test]
    fn refining_an_unknown_stack_is_a_no_op() {
        let mut s = OffCpuStats::default();
        s.record(event(1_000, 7, OFFCPU_REASON_WAIT));
        s.refine_stack_reason(99, WaitReason::Futex);
        assert_eq!(s.reasons_by_total_time()[0].0, WaitReason::Wait);
    }

    #[test]
    fn matching_wait_reason_frames() {
        assert!(is_futex_frame("futex_wait"));
        assert!(is_futex_frame("do_futex"));
        assert!(is_memory_frame("wait_on_page_bit_common"));
        assert!(is_memory_frame("do_swap_page"));
        assert!(is_io_frame("blkdev_issue_flush"));
        assert!(is_io_frame("wait_for_completion"));
        assert!(!is_futex_frame("schedule"));
        assert!(!is_io_frame("futex_wait"));
    }

    #[test]
    fn refine_uses_the_first_specific_frame() {
        // schedule is at the top of every blocking stack; the frames beneath
        // it are what name the actual cause.
        let frames = vec![
            frame("__schedule"),
            frame("schedule"),
            frame("futex_wait_queue_me"),
        ];
        assert_eq!(WaitReason::Wait.refine(&frames), WaitReason::Futex);

        let io = vec![frame("__schedule"), frame("wait_for_completion")];
        assert_eq!(WaitReason::Wait.refine(&io), WaitReason::Io);

        let memory = vec![frame("wait_on_page_bit_common")];
        assert_eq!(WaitReason::Wait.refine(&memory), WaitReason::Memory);
    }

    #[test]
    fn refine_falls_back_without_a_specific_frame() {
        // An unresolved stack must degrade to the coarse reason rather than
        // to "unknown", and an interruptible wait with no named cause reads
        // as a plain sleep.
        let unresolved = vec![Frame {
            symbol: None,
            module: None,
            ip: 0xdead_beef,
            kernel: true,
        }];
        assert_eq!(WaitReason::Wait.refine(&unresolved), WaitReason::Sleep);
        assert_eq!(WaitReason::Io.refine(&unresolved), WaitReason::Io);
        assert_eq!(WaitReason::Unknown.refine(&unresolved), WaitReason::Unknown);
    }

    #[test]
    fn computes_wait_percentiles() {
        let mut s = OffCpuStats::default();
        for wait in [40u64, 10, 30, 20] {
            s.record(event(wait, 1, OFFCPU_REASON_WAIT));
        }
        assert_eq!(s.percentiles(), (20, 40, 40));
        assert_eq!(OffCpuStats::default().percentiles(), (0, 0, 0));
    }

    #[test]
    fn counts_lost_events() {
        let mut s = OffCpuStats::default();
        s.record_lost(3);
        s.record_lost(4);
        assert_eq!(s.lost(), 7);
    }

    #[test]
    fn reason_labels_are_distinct() {
        let labels = [
            WaitReason::Futex,
            WaitReason::Io,
            WaitReason::Memory,
            WaitReason::Sleep,
            WaitReason::Wait,
            WaitReason::Unknown,
        ]
        .map(|reason| reason.label());
        for (i, a) in labels.iter().enumerate() {
            for b in &labels[i + 1..] {
                assert_ne!(a, b, "two reasons share the label {a}");
            }
        }
    }

    #[test]
    fn stack_ranking_breaks_ties_deterministically() {
        let mut s = OffCpuStats::default();
        s.record(event(1_000, 9, OFFCPU_REASON_WAIT));
        s.record(event(1_000, 4, OFFCPU_REASON_WAIT));
        s.record(event(1_000, 7, OFFCPU_REASON_WAIT));
        let ranked = s.stacks_by_total_time();
        let ids: Vec<i64> = ranked.iter().map(|(id, _)| *id).collect();
        assert_eq!(ids, vec![4, 7, 9]);
    }
}
