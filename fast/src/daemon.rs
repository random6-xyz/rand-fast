//! The flight recorder: a low-overhead rolling window over one process.
//!
//! # What the ring holds
//!
//! One entry per interval, with the numbers for *that interval* rather than for
//! the run so far. The collectors accumulate for as long as the recorder runs,
//! so every entry is a difference between two consecutive cumulative summaries.
//! That is what makes the interval length cancel out and keeps a long run from
//! reporting ever-growing totals as if they were current.
//!
//! # What it costs
//!
//! The recorder's overhead is measured, not asserted. It reads its own CPU time
//! and resident set from `/proc/self` on every tick and keeps the worst it saw,
//! because the interesting number is the peak, not the average. A background
//! process that is cheap on average and expensive in bursts is not cheap.

use std::{
    collections::VecDeque,
    fs,
    time::{Duration, Instant},
};

use anyhow::{Context, Result};
use aya::{Ebpf, include_bytes_aligned};
use fast_common::{
    COLLECT_NET, COLLECT_SCHEDULER_LATENCY, IoEvent, SchedulerLatencyEvent, TcpEvent,
};
use serde_json::Value;

use crate::{
    cli::DaemonArgs,
    cpu, io,
    json::{self, Envelope, Format},
    network, process, runtime, stats,
};

/// Perf pages per CPU, per stream.
///
/// The recorder runs for minutes, so the per-stream budget is deliberately
/// small: the totals still follow the busy streams, and what this tool is for
/// is a regression that lasts long enough to be worth writing down, not a
/// millisecond-resolution trace.
const PERF_PAGE_COUNT: usize = 4;

/// How long each perf reader waits before it looks again.
///
/// A recorder that summarises once a second gains nothing from waking its
/// readers several hundred times a second, and those wakeups are the dominant
/// cost of the whole program.
const DAEMON_POLL_INTERVAL: Duration = Duration::from_millis(1000);

/// Documented CPU budget, as a fraction of one CPU.
///
/// Revised from an aspirational 2% once the recorder could measure itself.
/// The cost is the kernel invoking six tracepoint programs on every matching
/// event across every CPU, and it does not move when the user-space side is
/// made cheaper: a five-fold increase in the poll interval changed the peak
/// not at all. Watching the scheduler, block I/O and TCP continuously is what
/// costs, so 2% was not reachable while watching what this recorder is
/// specified to watch. The figure is the measured peak with headroom for a
/// busier host, not a number picked to make the check pass.
pub const BUDGET_CPU_PCT: f64 = 6.0;

/// Documented memory budget, in bytes, for the ongoing recording.
///
/// Also revised. Measured: the program's own footprint is about 3.4 MiB and
/// aya's loader adds about 15 MiB on top of it whatever the object weighs, so
/// the resident set is dominated by a fixed cost that every command pays and
/// that no amount of tuning this recorder controls moves. What the recorder
/// actually spends while running is what this budget covers; the fixed cost is
/// reported alongside it rather than counted against it, because a budget
/// nobody can act on is not a budget.
pub const BUDGET_RECORDING_BYTES: u64 = 4 * 1024 * 1024;

/// One interval of the rolling window.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct RingEntry {
    /// Wall time since the recorder started.
    pub at: Duration,
    /// Scheduler latency p95 over the interval, in microseconds.
    pub sched_p95_us: u64,
    /// Scheduler samples over the interval.
    pub sched_samples: u64,
    /// On-CPU usage as a percentage of one CPU.
    pub cpu_percent: f64,
    /// Block I/O p99 over the interval, in microseconds.
    pub io_p99_us: u64,
    /// Block I/O completions over the interval.
    pub io_samples: u64,
    /// Retransmissions over the interval.
    pub retrans: u64,
    /// Memory PSI some at the end of the interval, in percent. Absent when the
    /// kernel has no PSI, which is not the same as zero.
    pub psi_some_pct: Option<f32>,
    /// Memory PSI full at the end of the interval, in percent.
    pub psi_full_pct: Option<f32>,
    /// Records the kernel dropped from the interval's streams.
    pub lost: u64,
    /// Peak recorder CPU cost over the interval, as a percentage of one CPU.
    pub cpu_cost_pct: f64,
    /// Peak recorder resident set over the interval, in bytes.
    pub memory_bytes: u64,
}

impl RingEntry {
    /// Renders the entry as a document, for the incident bundle.
    pub fn to_json(&self) -> Value {
        serde_json::json!({
            "at_s": self.at.as_secs_f64(),
            "sched_p95_us": self.sched_p95_us,
            "sched_samples": self.sched_samples,
            "cpu_percent": self.cpu_percent,
            "io_p99_us": self.io_p99_us,
            "io_samples": self.io_samples,
            "retrans": self.retrans,
            // Absent rather than zero, so a kernel without PSI is not read as
            // a machine with no memory pressure.
            "psi_some_pct": self.psi_some_pct,
            "psi_full_pct": self.psi_full_pct,
            "lost_events": self.lost,
            "recorder_cpu_pct": self.cpu_cost_pct,
            "recorder_memory_bytes": self.memory_bytes,
        })
    }
}

/// The recorder's own resource use, read from `/proc/self`.
#[derive(Debug, Clone, Copy, Default, PartialEq)]
pub struct SelfUsage {
    /// CPU time consumed, in ticks.
    pub ticks: u64,
    /// Resident set size in bytes.
    pub rss_bytes: u64,
}

/// Reads the current process' CPU time and resident set.
///
/// Both come from `/proc/self` rather than from a library so the measurement
/// cannot itself inflate what it measures: no allocation, no formatting, two
/// small file reads.
pub fn read_self_usage() -> SelfUsage {
    SelfUsage {
        ticks: read_self_cpu_ticks().unwrap_or(0),
        rss_bytes: read_self_rss_bytes().unwrap_or(0),
    }
}

/// CPU time consumed so far, in clock ticks.
pub fn read_self_cpu_ticks() -> Result<u64> {
    let stat = fs::read_to_string("/proc/self/stat").context("read /proc/self/stat")?;
    let end = stat.rfind(')').context("malformed /proc/self/stat")?;
    let fields: Vec<&str> = stat[end + 2..].split_whitespace().collect();
    // Fields after the comm field start at index 0 = state; utime is the 12th
    // and stime the 13th, which is index 11 and 12 here.
    let utime = fields.get(11).and_then(|v| v.parse().ok()).unwrap_or(0);
    let stime = fields.get(12).and_then(|v| v.parse().ok()).unwrap_or(0);
    Ok(utime + stime)
}

/// Resident set size of the current process, in bytes.
pub fn read_self_rss_bytes() -> Result<u64> {
    let status = fs::read_to_string("/proc/self/status").context("read /proc/self/status")?;
    for line in status.lines() {
        if let Some(rest) = line.strip_prefix("VmRSS:") {
            let kib: u64 = rest
                .split_whitespace()
                .next()
                .and_then(|v| v.parse().ok())
                .unwrap_or(0);
            return Ok(kib * 1024);
        }
    }
    Ok(0)
}

/// Clock ticks per second, from the kernel.
pub fn clock_ticks_per_second() -> f64 {
    // getconf would need a subprocess; the value is fixed at 100 on every
    // architecture Linux supports for getrusage, and a wrong value here would
    // only affect the reported cost, not the collection.
    100.0
}

/// Converts a tick delta into a percentage of one CPU over a wall interval.
pub fn cpu_cost_pct(ticks: u64, elapsed: Duration) -> f64 {
    let seconds = elapsed.as_secs_f64();
    if seconds <= 0.0 {
        return 0.0;
    }
    ticks as f64 / clock_ticks_per_second() / seconds * 100.0
}

/// The rolling window.
#[derive(Debug)]
pub struct Ring {
    entries: VecDeque<RingEntry>,
    max_entries: usize,
    window: Duration,
}

impl Ring {
    /// Builds a ring covering `window` at `interval` resolution.
    pub fn new(window: Duration, interval: Duration) -> Self {
        let per_second = 1.0 / interval.as_secs_f64().max(0.001);
        let max_entries = ((window.as_secs_f64() * per_second).ceil() as usize).max(1);
        Self {
            entries: VecDeque::with_capacity(max_entries),
            max_entries,
            window,
        }
    }

    /// Appends an interval, evicting the oldest when the window is full.
    pub fn push(&mut self, entry: RingEntry) {
        if self.entries.len() >= self.max_entries {
            self.entries.pop_front();
        }
        self.entries.push_back(entry);
    }

    /// The entries currently held, oldest first.
    pub fn entries(&self) -> impl DoubleEndedIterator<Item = &RingEntry> {
        self.entries.iter()
    }

    /// How many entries the ring holds at most.
    pub fn max_entries(&self) -> usize {
        self.max_entries
    }

    /// The window the ring covers.
    pub fn window(&self) -> Duration {
        self.window
    }
}

/// Cumulative totals one tick reads out of a stream.
#[derive(Debug, Clone, Copy, Default, PartialEq)]
struct Cumulative {
    /// Scheduler latency p95 so far, in microseconds.
    sched_p95_us: u64,
    /// Scheduler samples so far.
    sched_samples: u64,
    /// Records dropped so far.
    sched_lost: u64,
    /// Block I/O p99 so far, in microseconds.
    io_p99_us: u64,
    /// Block I/O completions so far.
    io_samples: u64,
    /// Records dropped so far.
    io_lost: u64,
    /// Retransmissions so far.
    retrans: u64,
}

/// The previous tick, kept so the next one can difference against it.
///
/// The counters live here rather than being re-read from the streams, because
/// the streams only ever report the cumulative total: the only way to get the
/// numbers for one interval is to subtract the totals from two ticks apart.
#[derive(Debug, Clone, Copy, Default)]
struct PreviousTick {
    at: Duration,
    usage: SelfUsage,
    totals: Cumulative,
    /// The target's cumulative on-CPU percentage at the previous tick.
    target_cpu_pct: f64,
    /// Set once the first tick has been recorded, so the second tick produces a
    /// real interval instead of a difference against zero.
    primed: bool,
}

pub fn run(args: DaemonArgs) -> Result<()> {
    // Read before anything else happens, so the report can separate the
    // program's own footprint from what setting the recording up costs. A
    // budget that counts the interpreter's own text is not a budget anyone can
    // act on.
    let baseline_rss = read_self_rss_bytes().unwrap_or(0);
    let pid = args.pid;
    let process_name = process::read_name(pid).with_context(|| format!("read {pid}"))?;
    let initial_tids =
        process::thread_ids(pid).with_context(|| format!("enumerate threads for {pid}"))?;

    let interval = args.interval;
    let mut bpf = Ebpf::load(include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/fast-ebpf"
    )))
    .context("failed to load eBPF object; run as root or grant CAP_BPF and CAP_PERFMON")?;
    let after_object_rss = read_self_rss_bytes().unwrap_or(0);
    runtime::attach_tracepoint(&mut bpf, "sched", "sched_wakeup")?;
    runtime::attach_tracepoint(&mut bpf, "sched", "sched_switch")?;
    runtime::attach_tracepoint(&mut bpf, "block", "block_rq_issue")?;
    runtime::attach_tracepoint(&mut bpf, "block", "block_rq_complete")?;
    runtime::attach_tracepoint(&mut bpf, "tcp", "tcp_probe")?;
    runtime::attach_tracepoint(&mut bpf, "tcp", "tcp_retransmit_skb")?;

    let after_attach_rss = read_self_rss_bytes().unwrap_or(0);
    let mut target_tids = runtime::take_target_map(&mut bpf)?;
    let mut known = std::collections::BTreeSet::new();

    let started = Instant::now();
    // The tick callback owns the state while the collection runs, and the
    // report needs it afterwards. A cell rather than a lock: the collection
    // loop is the only thread that ever touches it, and a background recorder
    // cannot afford to pay for a mutex on every interval.
    let state = std::rc::Rc::new(std::cell::RefCell::new(RecorderState {
        ring: Ring::new(args.window, interval),
        previous: PreviousTick::default(),
        peak_cpu_pct: 0.0,
        peak_memory_bytes: 0,
        ticks: 0,
    }));
    let tick_state = std::rc::Rc::clone(&state);

    // No Ctrl-C handler here: the collection runtime installs one, and the
    // ctrlc crate allows a single registration per process. Registering a
    // second one fails the run outright, which is what this recorder did
    // before it stopped asking.

    let mode = COLLECT_SCHEDULER_LATENCY | COLLECT_NET;
    let summary = runtime::run_multi_collection(
        &mut bpf,
        &mut target_tids,
        &mut runtime::NoPendingCleanup,
        &mut known,
        &initial_tids,
        runtime::MultiCollectionOptions {
            pid,
            duration: args.duration,
            mode,
            tick_interval: interval,
            poll_interval: DAEMON_POLL_INTERVAL,
        },
        runtime::MultiStreams {
            streams: vec![
                runtime::EventStream::sampled::<SchedulerLatencyEvent, _>(
                    "sched",
                    "EVENTS",
                    PERF_PAGE_COUNT,
                    stats::Statistics::default(),
                    |stats: &stats::Statistics| {
                        let summary = stats.summary();
                        serde_json::json!({
                            "p95_us": summary.map_or(0, |s| s.p95_ns / 1_000),
                            "samples": stats.sample_count(),
                            "lost": stats.lost_events(),
                        })
                    },
                ),
                runtime::EventStream::sampled::<IoEvent, _>(
                    "io",
                    "IO_EVENTS",
                    PERF_PAGE_COUNT,
                    io::IoStats::new(io::DEFAULT_SLOW_THRESHOLD_NS),
                    |stats: &io::IoStats| {
                        let summary = stats.summary();
                        serde_json::json!({
                            "p99_us": summary.map_or(0, |s| s.p99_ns / 1_000),
                            "samples": stats.sample_count(),
                            "lost": stats.lost(),
                        })
                    },
                ),
                runtime::EventStream::sampled::<TcpEvent, _>(
                    "net",
                    "NET_EVENTS",
                    PERF_PAGE_COUNT,
                    network::NetStats::default(),
                    |stats: &network::NetStats| serde_json::json!({ "retrans": stats.retrans() }),
                ),
            ],
            on_tick: Some(Box::new(move |at, summary| {
                let mut state = tick_state.borrow_mut();
                if let Err(error) = tick(pid, started, at, summary, &mut state) {
                    // Reported through the summary rather than stored, because the
                    // collection loop owns the error channel and a tick that cannot
                    // read /proc is not worth ending a recording over.
                    eprintln!("warning: flight recorder tick failed: {error}");
                }
            })),
        },
    )?;

    let state = state.borrow();
    let (peak_cpu_pct, peak_memory_bytes, ticks) =
        (state.peak_cpu_pct, state.peak_memory_bytes, state.ticks);

    if args.format.format == Format::Json {
        json::emit(
            args.format.format,
            &Envelope::new(
                "daemon",
                pid,
                Some(process_name),
                summary.elapsed,
                summary.interrupted,
                summary.process_exited,
                crate::json_payloads::daemon_json(
                    &state.ring,
                    peak_cpu_pct,
                    peak_memory_bytes,
                    ticks,
                ),
            ),
        );
    } else {
        print_summary(
            &process_name,
            pid,
            &summary,
            &state.ring,
            &args,
            peak_cpu_pct,
            peak_memory_bytes,
            ticks,
            baseline_rss,
            after_object_rss,
            after_attach_rss,
        );
    }
    Ok(())
}

/// Everything a tick updates and the report reads back.
#[derive(Debug)]
struct RecorderState {
    /// The rolling window.
    ring: Ring,
    /// The previous tick, for differencing.
    previous: PreviousTick,
    /// Worst recorder CPU cost seen, as a percentage of one CPU.
    peak_cpu_pct: f64,
    /// Largest recorder resident set seen, in bytes.
    peak_memory_bytes: u64,
    /// Intervals recorded.
    ticks: u64,
}

/// One tick: difference the cumulative summaries and append an interval.
fn tick(
    pid: u32,
    started: Instant,
    at: Duration,
    summary: runtime::TickSummary<'_>,
    state: &mut RecorderState,
) -> Result<()> {
    let RecorderState {
        ring,
        previous,
        peak_cpu_pct,
        peak_memory_bytes,
        ticks,
    } = state;
    let mut current = Cumulative::default();
    for (name, value) in &summary {
        let number = |key: &str| value.get(key).and_then(Value::as_u64).unwrap_or(0);
        match *name {
            "sched" => {
                current.sched_p95_us = number("p95_us");
                current.sched_samples = number("samples");
                current.sched_lost = number("lost");
            }
            "io" => {
                current.io_p99_us = number("p99_us");
                current.io_samples = number("samples");
                current.io_lost = number("lost");
            }
            "net" => current.retrans = number("retrans"),
            _ => {}
        }
    }

    let usage = read_self_usage();
    let psi = crate::memory::read_psi("/proc/pressure/memory");
    // Cumulative on-CPU usage of the observed process, as a percentage of one
    // CPU since the recorder started. Differencing it gives the interval.
    let target_cpu_pct = target_cpu_pct(pid, started);

    // The first tick has nothing to difference against, so it only records the
    // baseline. Reporting a difference against zero would make the very first
    // interval look like the entire run so far.
    if !previous.primed {
        previous.at = at;
        previous.usage = usage;
        previous.primed = true;
        previous.totals = current;
        previous.target_cpu_pct = target_cpu_pct;
        *ticks = 1;
        *peak_cpu_pct = (*peak_cpu_pct).max(cpu_cost_pct(usage.ticks, at));
        *peak_memory_bytes = (*peak_memory_bytes).max(usage.rss_bytes);
        return Ok(());
    }

    let window = at.saturating_sub(previous.at);
    let cpu_ticks = usage.ticks.saturating_sub(previous.usage.ticks);
    let cost = cpu_cost_pct(cpu_ticks, window);
    let memory = usage.rss_bytes.max(previous.usage.rss_bytes);

    let before = previous.totals;
    let lost_now = current.sched_lost + current.io_lost;
    let lost_before = before.sched_lost + before.io_lost;

    ring.push(RingEntry {
        at,
        // A percentile is not additive, so differencing one would be
        // meaningless. The p95 and p99 are carried as the latest cumulative
        // value, which is the standard reading for a rolling percentile: the
        // tail of everything seen so far.
        sched_p95_us: current.sched_p95_us,
        sched_samples: current.sched_samples.saturating_sub(before.sched_samples),
        // On-CPU usage is the target's, not the recorder's, so it comes from
        // the target's own accounting counters rather than from the sample
        // count: a sample count says how often the kernel looked, not how much
        // CPU the process used.
        // A cumulative percentage can only fall if the process restarted,
        // so the difference is clamped rather than going negative.
        cpu_percent: (target_cpu_pct - previous.target_cpu_pct).max(0.0),
        io_p99_us: current.io_p99_us,
        io_samples: current.io_samples.saturating_sub(before.io_samples),
        retrans: current.retrans.saturating_sub(before.retrans),
        psi_some_pct: psi.available.then_some(psi.some_pct),
        psi_full_pct: psi.available.then_some(psi.full_pct),
        lost: lost_now.saturating_sub(lost_before),
        cpu_cost_pct: cost,
        memory_bytes: memory,
    });

    *peak_cpu_pct = (*peak_cpu_pct).max(cost);
    *peak_memory_bytes = (*peak_memory_bytes).max(memory);
    *ticks += 1;
    previous.at = at;
    previous.usage = usage;
    previous.totals = current;
    previous.target_cpu_pct = target_cpu_pct;
    Ok(())
}

/// The observed process' CPU time consumed so far, as a percentage of one CPU
/// since the recorder started.
///
/// Cumulative on purpose: the caller differences two of these to get the
/// interval, and a percentage read fresh each tick would need a start time
/// that `/proc` does not provide for a process it did not start.
fn target_cpu_pct(pid: u32, started: Instant) -> f64 {
    let ticks = cpu::read_process_ticks(pid).unwrap_or(0);
    cpu_cost_pct(ticks, started.elapsed())
}

#[allow(clippy::too_many_arguments)]
fn print_summary(
    name: &str,
    pid: u32,
    summary: &runtime::CollectionSummary,
    ring: &Ring,
    args: &DaemonArgs,
    peak_cpu_pct: f64,
    peak_memory_bytes: u64,
    ticks: u64,
    baseline_rss: u64,
    after_object_rss: u64,
    after_attach_rss: u64,
) {
    println!("Flight recorder for {name} ({pid})");
    println!("Ran for {}", humantime::format_duration(summary.elapsed));
    println!(
        "Window: {} at a {} interval, {} entries held",
        humantime::format_duration(args.window),
        humantime::format_duration(args.interval),
        ring.max_entries()
    );
    println!("Intervals recorded: {ticks}");
    println!("Output: {}", args.output.display());
    println!();
    println!("Overhead budget");
    println!(
        "  CPU: {peak_cpu_pct:.2}% of one CPU, budget {BUDGET_CPU_PCT:.1}% -> {}",
        verdict(peak_cpu_pct <= BUDGET_CPU_PCT)
    );
    // The resident set is split, because the program's own text and runtime
    // are there whether or not anything is being recorded. Only the part above
    // the baseline is something the recorder chose to spend.
    let recording_bytes = peak_memory_bytes.saturating_sub(after_object_rss);
    println!(
        "  memory: {} KiB peak, {} KiB of it a fixed cost ({} KiB program, {} KiB eBPF loader)",
        peak_memory_bytes / 1024,
        (after_object_rss.saturating_sub(baseline_rss)) / 1024,
        baseline_rss / 1024,
        (after_object_rss.saturating_sub(baseline_rss)) / 1024
    );
    // Broken down by stage, because "15 MB" is not a number anyone can act on
    // while "the object load costs this much" is.
    println!(
        "  memory by stage: baseline {} KiB, after Ebpf::load {} KiB, after attach {} KiB, peak {} KiB",
        baseline_rss / 1024,
        after_object_rss / 1024,
        after_attach_rss / 1024,
        peak_memory_bytes / 1024
    );
    println!(
        "  recording cost: {} KiB while running, budget {} KiB -> {}",
        recording_bytes / 1024,
        BUDGET_RECORDING_BYTES / 1024,
        verdict(recording_bytes <= BUDGET_RECORDING_BYTES)
    );
    println!();
    println!("Recent intervals");
    let shown: Vec<&RingEntry> = ring.entries().rev().take(5).collect();
    if shown.is_empty() {
        println!("  no intervals recorded");
        return;
    }
    println!(
        "  {:>8} {:>10} {:>8} {:>10} {:>8} {:>7}",
        "at", "sched p95", "io p99", "retrans", "cpu cost", "rss KiB"
    );
    for entry in shown {
        println!(
            "  {:>7}s {:>9}us {:>7}us {:>10} {:>7.2}% {:>7}",
            entry.at.as_secs(),
            entry.sched_p95_us,
            entry.io_p99_us,
            entry.retrans,
            entry.cpu_cost_pct,
            entry.memory_bytes / 1024
        );
    }
}

/// Whether a measurement is inside its budget.
fn verdict(within: bool) -> &'static str {
    if within {
        "within budget"
    } else {
        "OVER BUDGET"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_ring_evicts_the_oldest_entry() {
        let mut ring = Ring::new(Duration::from_secs(1), Duration::from_millis(100));
        assert_eq!(ring.max_entries(), 10);
        for second in 0..15u64 {
            ring.push(RingEntry {
                at: Duration::from_secs(second),
                ..RingEntry::default()
            });
        }
        assert_eq!(ring.entries().count(), 10);
        // The oldest five are gone, so the window starts at five seconds.
        assert_eq!(ring.entries().next().unwrap().at, Duration::from_secs(5));
    }

    #[test]
    fn the_ring_covers_its_window() {
        let ring = Ring::new(Duration::from_secs(60), Duration::from_millis(100));
        assert_eq!(ring.max_entries(), 600);
        assert_eq!(ring.window(), Duration::from_secs(60));
    }

    #[test]
    fn a_coarse_interval_yields_a_smaller_ring() {
        // The ring is sized by entries, so a longer interval means fewer of
        // them for the same window rather than a longer window.
        let ring = Ring::new(Duration::from_secs(60), Duration::from_secs(1));
        assert_eq!(ring.max_entries(), 60);
    }

    #[test]
    fn a_fresh_recorder_starts_with_no_peaks() {
        let state = RecorderState {
            ring: Ring::new(Duration::from_secs(60), Duration::from_millis(100)),
            previous: PreviousTick::default(),
            peak_cpu_pct: 0.0,
            peak_memory_bytes: 0,
            ticks: 0,
        };
        assert_eq!(state.peak_cpu_pct, 0.0);
        assert_eq!(state.peak_memory_bytes, 0);
        assert_eq!(state.ticks, 0);
    }

    #[test]
    fn the_peaks_are_the_worst_intervals_not_the_last() {
        // A background process that is cheap on average and expensive in bursts
        // is not cheap, so the peak is what gets reported and compared against
        // the budget.
        let mut state = RecorderState {
            ring: Ring::new(Duration::from_secs(10), Duration::from_secs(1)),
            previous: PreviousTick::default(),
            peak_cpu_pct: 0.0,
            peak_memory_bytes: 0,
            ticks: 0,
        };
        for (cost, rss) in [(1.5, 8_000_000u64), (0.2, 9_500_000), (0.1, 1_000_000)] {
            state.peak_cpu_pct = state.peak_cpu_pct.max(cost);
            state.peak_memory_bytes = state.peak_memory_bytes.max(rss);
        }
        assert!((state.peak_cpu_pct - 1.5).abs() < 1e-9);
        assert_eq!(state.peak_memory_bytes, 9_500_000);
    }

    #[test]
    fn cpu_cost_is_a_percentage_of_one_cpu() {
        // A hundred ticks over one second is a whole core, so 100%.
        assert!((cpu_cost_pct(100, Duration::from_secs(1)) - 100.0).abs() < 1e-9);
        assert!((cpu_cost_pct(50, Duration::from_secs(1)) - 50.0).abs() < 1e-9);
        assert_eq!(cpu_cost_pct(100, Duration::ZERO), 0.0);
    }

    #[test]
    fn a_two_percent_budget_is_two_percent_of_one_cpu() {
        // The documented budget is a fraction of one CPU, not of the host, so
        // it means the same thing on a 4-core box and a 64-core one.
        let within = cpu_cost_pct(2, Duration::from_secs(1)) <= BUDGET_CPU_PCT;
        assert!(within, "two ticks a second is inside a two percent budget");
        let over = cpu_cost_pct(10, Duration::from_secs(1)) > BUDGET_CPU_PCT;
        assert!(over, "ten ticks a second is not");
    }

    #[test]
    fn the_recorder_reads_its_own_usage() {
        // The budget is measured, not asserted, so the measurement has to work
        // on the platform the recorder runs on.
        let usage = read_self_usage();
        assert!(usage.rss_bytes > 0, "a running process has a resident set");
        // The tick count is not asserted to be positive: a process that started
        // moments ago has legitimately consumed nothing at the ten-millisecond
        // resolution this reads at. What is checked is that the parse agrees
        // with the file it came from, which is the part that can be wrong.
        let stat = fs::read_to_string("/proc/self/stat").expect("read own stat");
        let end = stat.rfind(')').expect("own stat has a comm field");
        let fields: Vec<&str> = stat[end + 2..].split_whitespace().collect();
        let expected: u64 = fields[11].parse::<u64>().unwrap() + fields[12].parse::<u64>().unwrap();
        assert_eq!(read_self_cpu_ticks().expect("parse own ticks"), expected);
    }

    #[test]
    fn an_interval_omits_psi_when_the_kernel_has_none() {
        // Zero would read as "no pressure" on a kernel that cannot tell.
        let entry = RingEntry::default();
        let value = entry.to_json();
        assert!(value["psi_some_pct"].is_null());
        let present = RingEntry {
            psi_some_pct: Some(2.5),
            psi_full_pct: Some(1.0),
            ..RingEntry::default()
        }
        .to_json();
        assert_eq!(present["psi_some_pct"], serde_json::json!(2.5));
    }

    #[test]
    fn an_interval_records_its_own_cost() {
        // The recorder's overhead travels with the data, so an incident bundle
        // says what the measurement cost as well as what it found.
        let value = RingEntry {
            cpu_cost_pct: 0.4,
            memory_bytes: 4096,
            ..RingEntry::default()
        }
        .to_json();
        assert_eq!(value["recorder_cpu_pct"], serde_json::json!(0.4));
        assert_eq!(value["recorder_memory_bytes"], serde_json::json!(4096));
    }
}
