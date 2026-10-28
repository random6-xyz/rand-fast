//! The flight recorder: a low-overhead rolling window over one process.
//!
//! # What the ring holds
//!
//! One entry per interval, with the numbers for *that interval* rather than for
//! the run so far. Latency distributions reset at each tick; cumulative loss,
//! retransmission and unmatched counts are differenced between ticks.
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
    io::Read,
    time::{Duration, Instant},
};

#[path = "daemon_storage.rs"]
mod storage;
use anyhow::{Context, Result};
use aya::{Ebpf, include_bytes_aligned};
use fast_common::{
    COLLECT_NET, COLLECT_SCHEDULER_LATENCY, IoEvent, SchedulerLatencyEvent, TcpEvent,
};
use serde_json::Value;

use crate::{
    cli::DaemonArgs,
    cpu,
    json::{self, Envelope, Format},
    process, runtime,
    trigger::{Interval, Signal, Triggers},
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

/// Schema for daemon reports and their incident bundles.
const DAEMON_SCHEMA: &str = "rand-fast/v2";

/// Documented CPU budget, as a fraction of one CPU.
///
/// Revised from an aspirational 2% once the recorder could measure itself.
/// The cost is the kernel invoking six hot tracepoint programs on every
/// matching scheduler/block/TCP event across every CPU, plus one cleanup
/// program only when a target thread exits. It does not move when the user-space
/// side is made cheaper: a five-fold increase in the poll interval changed the peak
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

/// How many intervals an incident bundle carries.
///
/// The ring holds as many as `--window` asks for, but a bundle is a report, not
/// a second copy of the ring: what it needs is the run-up to the trigger, and
/// the oldest part of that is the least likely to explain the interval that
/// tripped. Bounding this is what makes a bundle a fixed size, and a fixed size
/// is what lets `--max-disk-bytes` be a real ceiling instead of a number that
/// is exceeded whenever the window is wide.
///
/// The cost is that a restart restores this many intervals rather than the whole
/// window, and the live ring refills from the next tick, so nothing is lost
/// except history older than the trigger.
pub const BUNDLE_MAX_INTERVALS: usize = 60;

/// Per-stream dropped records for an interval.
#[derive(Debug, Clone, Copy, Default, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct LostByStream {
    pub sched: u64,
    pub io: u64,
    pub net: u64,
}

/// One interval of the rolling window.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct RingEntry {
    /// Wall time since the recorder started.
    pub at: Duration,
    /// Scheduler latency p95 over the interval, in microseconds.
    pub sched_p95_us: u64,
    /// Scheduler samples over the interval.
    pub sched_samples: u64,
    /// On-CPU usage as a percentage of one CPU, absent when unavailable.
    pub cpu_percent: Option<f64>,
    /// Block I/O p99 over the interval, in microseconds.
    pub io_p99_us: u64,
    /// Block I/O completions over the interval.
    pub io_samples: u64,
    /// Target requests that could not be tracked over the interval.
    pub io_unmatched: u64,
    /// Retransmissions over the interval.
    pub retrans: u64,
    /// Memory PSI some at the end of the interval, in percent. Absent when the
    /// kernel has no PSI, which is not the same as zero.
    pub psi_some_pct: Option<f32>,
    /// Memory PSI full at the end of the interval, in percent.
    pub psi_full_pct: Option<f32>,
    /// Perf and userspace queue records lost from the interval streams.
    pub lost: u64,
    /// Subset of lost records dropped by the bounded userspace queue.
    pub queue_lost: u64,
    /// Per-stream losses, absent for history written by older versions.
    pub lost_by_stream: Option<LostByStream>,
    /// Peak recorder CPU cost over the interval, as a percentage of one CPU.
    pub cpu_cost_pct: f64,
    /// Peak recorder resident set over the interval, in bytes.
    pub memory_bytes: u64,
    /// The triggers that fired on this interval, worst first. Empty on a
    /// quiet interval. An incident write can fail even when triggers fired.
    pub fired: Vec<Signal>,
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
            "io_unmatched": self.io_unmatched,
            "retrans": self.retrans,
            // Absent rather than zero, so a kernel without PSI is not read as
            // a machine with no memory pressure.
            "psi_some_pct": self.psi_some_pct,
            "psi_full_pct": self.psi_full_pct,
            "lost_events": self.lost,
            "queue_lost_events": self.queue_lost,
            "lost_events_by_stream": self.lost_by_stream,
            "recorder_cpu_pct": self.cpu_cost_pct,
            "recorder_memory_bytes": self.memory_bytes,
            // Which trigger fired, so a bundle says what tripped it rather
            // than only that something did. Empty on a quiet interval.
            "fired": self.fired.iter().map(|signal| signal.name()).collect::<Vec<_>>(),
        })
    }
}

/// Writes one incident bundle: the ring, the interval that tripped, and enough
/// context to read them without the machine they came from.
///
/// A recorder whose output is a single line of numbers is no use at three in
/// the morning to whoever has to work out what happened. So a bundle is a
/// directory with a manifest, the recent intervals, and a plain-text summary,
/// and the file name is ordered by time so a directory listing is a timeline.
///
/// The bundle is written before its own entry joins the ring, which means it
/// contains the triggering interval and the history that led up to it, but not
/// the intervals that follow. That is deliberate: the whole point of the
/// window is the part before the trigger.
fn write_incident(
    ring: &Ring,
    entry: RingEntry,
    triggers: &Triggers,
    args: &DaemonArgs,
    slow: &SlowSamples,
) -> Result<IncidentWrite> {
    let output = storage::Output::open(&args.output)?;
    let directory = output.create(&stamp(entry.at))?;

    // The most recent intervals, not all of them: see BUNDLE_MAX_INTERVALS.
    // Taken from the end, because the newest is what leads to the trigger.
    let total_entries = ring.entries().count();
    let carried = total_entries.min(BUNDLE_MAX_INTERVALS);

    let manifest = serde_json::json!({
        "schema": DAEMON_SCHEMA,
        "command": "daemon.incident",
        "recorded_at_s": entry.at.as_secs_f64(),
        "process": { "pid": args.pid },
        "triggered_by": entry
            .fired
            .iter()
            .map(|signal| serde_json::json!({
                "signal": signal.name(),
                "unit": signal.unit(),
                "threshold": signal.threshold(triggers),
                "measured": entry.measured(*signal),
            }))
            .collect::<Vec<_>>(),
        "thresholds": triggers
            .enabled()
            .iter()
            .map(|signal| serde_json::json!({
                "signal": signal.name(),
                "unit": signal.unit(),
                "at_or_above": signal.threshold(triggers),
            }))
            .collect::<Vec<_>>(),
        // Stated in the bundle, because a reader who assumed it holds the whole
        // window would draw the wrong conclusion from a short one.
        "history": {
            "intervals_carried": carried,
            "interval_limit": BUNDLE_MAX_INTERVALS,
            "ring_window_s": args.window.as_secs_f64(),
        },
        "interval": {
            "at_s": entry.at.as_secs_f64(),
            "sched_p95_us": entry.sched_p95_us,
            "sched_samples": entry.sched_samples,
            "io_p99_us": entry.io_p99_us,
            "io_samples": entry.io_samples,
            "io_unmatched": entry.io_unmatched,
            "retrans": entry.retrans,
            "psi_some_pct": entry.psi_some_pct,
            "psi_full_pct": entry.psi_full_pct,
            "lost_events": entry.lost,
            "queue_lost_events": entry.queue_lost,
            "lost_events_by_stream": entry.lost_by_stream,
            "measurement_semantics": MEASUREMENT_SEMANTICS,
            "recorder_cpu_pct": entry.cpu_cost_pct,
            "recorder_memory_bytes": entry.memory_bytes,
        },
    });
    directory.json("manifest.json", &manifest)?;

    let intervals: Vec<Value> = ring
        .entries()
        .skip(total_entries - carried)
        .map(RingEntry::to_json)
        .collect();
    directory.json("intervals.json", &Value::Array(intervals))?;
    directory.json("slow-samples.json", &slow.to_json())?;

    // The diagnosis is the same ranking `fast diagnose` prints, fed with what
    // the recorder has measured. It is not a second, weaker copy of that
    // command: the signals a background recorder does not collect are named as
    // uncollected, so "no lock contention found" cannot be read as "lock
    // contention was looked for and not found".
    let diagnosis = diagnose_from(&entry, args.pid, slow);
    directory.json("diagnosis.json", &diagnosis)?;
    directory.write("summary.txt", &incident_text(&entry, triggers, &diagnosis))?;

    // Written last, and on its own, so a bundle is either complete or absent
    // rather than a directory that looks finished and is not.
    directory.json(
        "complete.json",
        &serde_json::json!({
            "schema": DAEMON_SCHEMA,
            "files": [
                "manifest.json",
                "intervals.json",
                "slow-samples.json",
                "diagnosis.json",
                "summary.txt",
            ],
        }),
    )?;
    let rotation_error = match output.rotate(args.max_disk_bytes, directory.name()) {
        Ok(state) => {
            if state.unknown {
                eprintln!(
                    "warning: incident output size cannot be fully verified; the {} byte cap may be exceeded (counted regular file bytes: {})",
                    args.max_disk_bytes, state.total
                );
            } else if state.total > args.max_disk_bytes {
                eprintln!(
                    "warning: incident output holds {} regular file bytes, over the {} byte cap; the current incident and unrecognized data are retained",
                    state.total, args.max_disk_bytes
                );
            }
            None
        }
        Err(error) => Some(error),
    };
    Ok(IncidentWrite { rotation_error })
}

/// A complete bundle may survive even when the subsequent rotation fails.
struct IncidentWrite {
    rotation_error: Option<anyhow::Error>,
}

/// The slowest latencies in the triggering interval, in microseconds.
struct SlowSamples {
    sched_us: Vec<u64>,
    io_us: Vec<u64>,
}

impl SlowSamples {
    fn to_json(&self) -> Value {
        serde_json::json!({
            "sched_us": self.sched_us,
            "io_us": self.io_us,
            "note": "the triggering interval's slowest dispatched latencies, longest first, rounded down to microseconds",
        })
    }
}

#[cfg(test)]
fn directory_total(dir: &std::path::Path) -> Option<u64> {
    fn size(dir: &std::path::Path) -> Option<u64> {
        let mut total = 0;
        for entry in fs::read_dir(dir).ok()? {
            let entry = entry.ok()?;
            let m = entry.metadata().ok()?;
            total += if m.is_dir() {
                size(&entry.path())?
            } else if m.is_file() {
                m.len()
            } else {
                0
            };
        }
        Some(total)
    }
    size(dir)
}

/// A byte count in the largest unit that leaves the number readable.
fn human_bytes(bytes: u64) -> String {
    const KIB: u64 = 1024;
    const MIB: u64 = 1024 * 1024;
    const GIB: u64 = 1024 * 1024 * 1024;
    if bytes >= GIB {
        format!("{:.1} GiB", bytes as f64 / GIB as f64)
    } else if bytes >= MIB {
        format!("{:.1} MiB", bytes as f64 / MIB as f64)
    } else if bytes >= KIB {
        format!("{:.1} KiB", bytes as f64 / KIB as f64)
    } else {
        format!("{bytes} B")
    }
}

/// Reads the rolling window back from the most recent bundle on disk.
///
/// A recorder that restarts is least useful immediately after whatever made it
/// restart, which is exactly when the minutes before the restart matter most.
/// The newest complete bundle holds that window, so a restarted recorder
/// starts with the history it would otherwise have thrown away.
///
/// Only the newest bundle is read. Older ones are there to be rotated away, and
/// stitching several together would produce a window with gaps in it that look
/// exactly like a quiet machine.
///
/// History is read with a hard byte bound, so a corrupted or hostile bundle
/// cannot make the recorder allocate without limit.
const MAX_RESTORE_BYTES: u64 = 1024 * 1024;

/// A bundle that cannot be read is skipped rather than fatal: a recorder must
/// start even when the disk it is about to write to is in a strange state, and
/// a missing history is a far smaller problem than a recorder that will not
/// run.
fn restore_ring(output: &std::path::Path, window: Duration) -> Restored {
    let Ok(output) = storage::Output::open(output) else {
        return Restored::default();
    };
    let Ok(Some(text)) = output.read_latest(MAX_RESTORE_BYTES) else {
        return Restored::default();
    };
    let Ok(Value::Array(entries)) = serde_json::from_str::<Value>(&text) else {
        return Restored::default();
    };

    let mut restored = Restored::default();
    for entry in entries {
        let Some(entry) = ring_entry_from_json(&entry) else {
            continue;
        };
        // Older than the window being kept, so it cannot be what a reader of the
        // window expects to find in it.
        if restored.previous_at.is_zero() || entry.at >= restored.previous_at {
            restored.previous_at = entry.at;
        }
        restored.entries.push(entry);
    }
    // Keep only what fits: the window is about how far back the recorder looks,
    // and carrying more would make the first tick report a span it claims to
    // cover but does not.
    let oldest = restored.previous_at.checked_sub(window).unwrap_or_default();
    restored.entries.retain(|entry| entry.at >= oldest);
    restored
}

/// Rebuilds a ring entry from a bundle's JSON.
///
/// Returns `None` for an entry it cannot understand, so a bundle written by a
/// different version degrades to the intervals that still parse rather than
/// being discarded whole.
fn ring_entry_from_json(value: &Value) -> Option<RingEntry> {
    let number = |key: &str| value.get(key).and_then(Value::as_u64);
    let at = Duration::try_from_secs_f64(value.get("at_s")?.as_f64()?).ok()?;
    Some(RingEntry {
        at,
        sched_p95_us: number("sched_p95_us").unwrap_or(0),
        sched_samples: number("sched_samples").unwrap_or(0),
        cpu_percent: value.get("cpu_percent").and_then(Value::as_f64),
        io_p99_us: number("io_p99_us").unwrap_or(0),
        io_samples: number("io_samples").unwrap_or(0),
        io_unmatched: number("io_unmatched").unwrap_or(0),
        retrans: number("retrans").unwrap_or(0),
        psi_some_pct: value
            .get("psi_some_pct")
            .and_then(Value::as_f64)
            .map(|value| value as f32),
        psi_full_pct: value
            .get("psi_full_pct")
            .and_then(Value::as_f64)
            .map(|value| value as f32),
        lost: number("lost_events").unwrap_or(0),
        queue_lost: number("queue_lost_events").unwrap_or(0),
        lost_by_stream: value
            .get("lost_events_by_stream")
            .and_then(|value| serde_json::from_value(value.clone()).ok()),
        cpu_cost_pct: value
            .get("recorder_cpu_pct")
            .and_then(Value::as_f64)
            .unwrap_or_default(),
        memory_bytes: number("recorder_memory_bytes").unwrap_or(0),
        // A restored entry keeps no record of having tripped anything: that
        // incident has already been written, and counting it again on the
        // restart would report a bundle that does not exist.
        fired: Vec::new(),
    })
}

/// Ranks causes from the recorder's own measurements, naming what it did not
/// collect.
///
/// Reuses the scoring `fast diagnose` uses rather than a second, weaker copy,
/// so a bundle and a diagnosis report cannot drift apart. The limits are
/// stated in the output: a background recorder does not gather off-CPU wait
/// reasons, page fault rates or transmitted segment counts, and saying so is
/// the difference between "nothing found" and "not looked for".
fn diagnose_from(entry: &RingEntry, pid: u32, slow: &SlowSamples) -> Value {
    let evidence = crate::diagnose::Evidence {
        sched_samples: entry.sched_samples as usize,
        sched_p95_us: entry.sched_p95_us,
        io_samples: entry.io_samples as usize,
        io_unmatched: entry.io_unmatched,
        io_p99_us: entry.io_p99_us,
        // The recorder knows the p99 but not how many requests crossed the
        // slow threshold, so this signal is left out rather than guessed at.
        io_slow: 0,
        net_samples: 0,
        // Retransmissions are counted but segments are not, so there is no
        // ratio to score. Zero here would read as a perfect link rather than
        // as an absent measurement.
        retrans_ratio: 0.0,
        offcpu_samples: 0,
        offcpu_p95_us: 0,
        offcpu_total_us: 0,
        offcpu_futex_ratio: 0.0,
        offcpu_io_ratio: 0.0,
        offcpu_network_ratio: 0.0,
        offcpu_memory_ratio: 0.0,
        minor_faults_per_s: 0.0,
        major_faults_per_s: 0.0,
        reclaims_per_s: 0.0,
        psi_some_pct: entry.psi_some_pct.unwrap_or(0.0),
        psi_full_pct: entry.psi_full_pct.unwrap_or(0.0),
        cpu_samples: 0,
        cpu_percent: entry.cpu_percent.unwrap_or_default(),
        // The recorder knows the streams' dropped-event count for the interval
        // but not for the whole run, so this is the interval's figure.
        lost: vec![("interval", entry.lost)],
        // A kernel without PSI must be scored as having no pressure data rather
        // than as having none of the pressure, or the memory cause is ruled out
        // by a reading that was never taken.
        psi_available: entry.psi_some_pct.is_some(),
        swap_kb: 0,
    };
    let causes = crate::scoring::score(&evidence);
    serde_json::json!({
        "schema": DAEMON_SCHEMA,
        "command": "daemon.incident.diagnosis",
        "pid": pid,
        "scored_by": "the ranking fast diagnose uses, fed with the recorder's own measurements",
        "causes": causes
            .iter()
            .map(|diagnosis| serde_json::json!({
                "cause": diagnosis.cause,
                "confidence_pct": diagnosis.confidence,
                "evidence": diagnosis.evidence,
            }))
            .collect::<Vec<_>>(),
        "not_collected": [
            "off-CPU wait reasons and stacks",
            "page fault and direct reclaim rates",
            "transmitted segment count, so no retransmission ratio",
            "on-CPU samples; usage is read from the target's accounting counters",
        ],
        "slowest_samples": slow.to_json(),
    })
}

/// The directory an incident at `at` goes in.
///
/// The name sorts lexicographically in time order, so `ls` on the output
/// directory is a timeline. That is not decoration: rotation deletes the oldest
/// first, and a restart recovers from the newest, so if the names did not sort
/// by time both would act on the wrong bundle.
///
/// The stamp is therefore a zero-padded millisecond count, not a formatted
/// duration. A human-readable one sorts wrongly: `10s` sorts after `2s`, so
/// `max()` over the names picks the wrong bundle and rotation would delete a
/// recent one before an old one. The readable form is in the manifest, where
/// nothing has to sort it.
fn stamp(at: Duration) -> String {
    format!("{:012}s", at.as_millis())
}
/// The measurement a signal fired on, in the signal's own unit.
impl RingEntry {
    fn measured(&self, signal: Signal) -> Option<f64> {
        match signal {
            Signal::SchedulerP95 => Some(self.sched_p95_us as f64),
            Signal::IoP99 => Some(self.io_p99_us as f64),
            Signal::Retransmissions => Some(self.retrans as f64),
            Signal::PsiSome => self.psi_some_pct.map(f64::from),
            Signal::PsiFull => self.psi_full_pct.map(f64::from),
            Signal::CpuUsage => self.cpu_percent,
        }
    }
}

/// The human-readable half of a bundle.
///
/// Written next to the JSON rather than instead of it, because the first thing
/// anyone does with a bundle is read it.
fn incident_text(entry: &RingEntry, triggers: &Triggers, diagnosis: &Value) -> String {
    let mut text = String::new();
    text.push_str(&format!(
        "Incident at {}s into the recording\n\n",
        entry.at.as_secs()
    ));
    text.push_str("Triggered by\n");
    for signal in &entry.fired {
        let measured = entry.measured(*signal).unwrap_or_default();
        let threshold = signal.threshold(triggers).unwrap_or_default();
        text.push_str(&format!(
            "  {signal} = {measured} {} (threshold {threshold} {})\n",
            signal.unit(),
            signal.unit()
        ));
    }
    text.push_str("\nThe interval\n");
    text.push_str(&format!(
        "  scheduler p95  {} us over {} samples\n",
        entry.sched_p95_us, entry.sched_samples
    ));
    text.push_str(&format!(
        "  block I/O p99  {} us over {} completions, {} unmatched\n",
        entry.io_p99_us, entry.io_samples, entry.io_unmatched
    ));
    text.push_str(&format!("  retransmissions {}\n", entry.retrans));
    match (entry.psi_some_pct, entry.psi_full_pct) {
        (Some(some), Some(full)) => {
            text.push_str(&format!("  memory PSI     {some}% some, {full}% full\n"));
        }
        _ => text.push_str("  memory PSI     unavailable, this kernel reports none\n"),
    }
    text.push_str(&format!(
        "  events lost    {} ({} from userspace queue)\n",
        entry.lost, entry.queue_lost
    ));
    text.push_str(&format!("  {MEASUREMENT_SEMANTICS}\n"));
    text.push_str("\nLikely cause, from the recorder's own measurements\n");
    match diagnosis["causes"].as_array() {
        Some(causes) if !causes.is_empty() => {
            for (rank, cause) in causes.iter().enumerate() {
                let name = cause["cause"].as_str().unwrap_or("unknown");
                let confidence = cause["confidence_pct"].as_f64().unwrap_or_default();
                text.push_str(&format!("  {}. {name} ({confidence:.1}%)\n", rank + 1));
            }
        }
        _ => text.push_str("  no cause scored above the reporting threshold\n"),
    }
    if let Some(missing) = diagnosis["not_collected"].as_array() {
        text.push_str("  not measured by this recorder:");
        for signal in missing {
            if let Some(name) = signal.as_str() {
                text.push_str(&format!("\n    {name}"));
            }
        }
        text.push('\n');
    }
    text.push_str("\nWhat it cost to measure\n");
    // Rounded, because a bundle is read by a person at three in the morning
    // and sixteen significant figures of recorder overhead is not information.
    text.push_str(&format!(
        "  recorder {:.2}% of one CPU, {} KiB resident\n",
        entry.cpu_cost_pct,
        entry.memory_bytes / 1024
    ));
    text
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

/// Nearest-rank over dispatch-time samples, using the lower edge of a
/// logarithmic bucket (eight buckets per power of two). The lower edge is
/// exact below 16 ns and at most 12.5% below a larger sample, before the
/// final conversion to whole microseconds. The 16 slowest values remain exact.
/// A sample arriving in the queue after a tick belongs to the next interval.
/// Loss counters are assigned when observed, which can differ from the
/// corresponding sample's dispatch interval.
pub const MEASUREMENT_SEMANTICS: &str = "New intervals use dispatch-time boundaries; shutdown drains readers while the target continues running, so final duration includes shutdown. Per-CPU perf snapshots and /proc CPU reads are not atomic; events after a reader stops are not observed. Restored history may use older semantics. Percentiles are nearest-rank over dispatched interval samples, approximated by logarithmic bucket lower bounds (at most 12.5% low in nanoseconds, then rounded down to microseconds); slow samples are actual values rounded down to microseconds. Approximation can suppress a near-threshold trigger. Queue backlog may move samples to a later interval; perf and queue loss are counted when observed, and lost samples can bias results. Perf reports only LOST records emitted by the kernel; unreported shutdown losses are not measurable. Counters saturate at u64 maximum. Empty percentiles are zero.";

const HISTOGRAM_BUCKETS: usize = 504;

struct IntervalLatency {
    buckets: [u64; HISTOGRAM_BUCKETS],
    count: u64,
    slowest: Vec<u64>,
    perf_lost: u64,
    queue_lost: u64,
}

impl Default for IntervalLatency {
    fn default() -> Self {
        Self {
            buckets: [0; HISTOGRAM_BUCKETS],
            count: 0,
            slowest: Vec::with_capacity(SLOW_SAMPLE_COUNT),
            perf_lost: 0,
            queue_lost: 0,
        }
    }
}

impl IntervalLatency {
    fn record(&mut self, ns: u64) {
        let index = if ns < 16 {
            ns as usize
        } else {
            let shift = 63 - ns.leading_zeros() - 3;
            16 + (shift as usize - 1) * 8 + ((ns >> shift) as usize - 8)
        };
        self.buckets[index] = self.buckets[index].saturating_add(1);
        self.count = self.count.saturating_add(1);
        let position = self.slowest.partition_point(|&value| value >= ns);
        if position < SLOW_SAMPLE_COUNT {
            if self.slowest.len() == SLOW_SAMPLE_COUNT {
                self.slowest.pop();
            }
            self.slowest.insert(position, ns);
        }
    }

    fn percentile_ns(&self, percentile: u64) -> u64 {
        if self.count == 0 {
            return 0;
        }
        let rank = ((self.count as u128 * percentile as u128 + 99) / 100) as u64;
        let mut seen = 0u64;
        for (index, count) in self.buckets.iter().enumerate() {
            seen = seen.saturating_add(*count);
            if seen >= rank {
                return if index < 16 {
                    index as u64
                } else {
                    let offset = index - 16;
                    (8 + (offset % 8) as u64) << (offset / 8 + 1)
                };
            }
        }
        0
    }

    fn take_snapshot(&mut self, percentile: u64) -> (u64, u64, Vec<u64>) {
        let value = self.percentile_ns(percentile) / 1_000;
        let count = self.count;
        let slowest = self.slowest.iter().map(|ns| ns / 1_000).collect();
        self.buckets.fill(0);
        self.count = 0;
        self.slowest.clear();
        (value, count, slowest)
    }
}

#[derive(Default)]
struct RecorderScheduler(IntervalLatency);
impl runtime::EventHandler<SchedulerLatencyEvent> for RecorderScheduler {
    fn on_event(&mut self, event: SchedulerLatencyEvent) {
        self.0.record(event.latency_ns);
    }
    fn on_lost(&mut self, count: u64) {
        self.0.perf_lost = self.0.perf_lost.saturating_add(count);
    }
    fn on_queue_lost(&mut self, count: u64) {
        self.0.queue_lost = self.0.queue_lost.saturating_add(count);
    }
}

#[derive(Default)]
struct RecorderIo {
    latency: IntervalLatency,
    unmatched: u64,
}
impl runtime::EventHandler<IoEvent> for RecorderIo {
    fn on_event(&mut self, event: IoEvent) {
        if event.op == fast_common::IO_OP_UNMATCHED {
            self.unmatched = self.unmatched.saturating_add(1);
        } else {
            self.latency.record(event.latency_ns);
        }
    }
    fn on_lost(&mut self, count: u64) {
        self.latency.perf_lost = self.latency.perf_lost.saturating_add(count);
    }
    fn on_queue_lost(&mut self, count: u64) {
        self.latency.queue_lost = self.latency.queue_lost.saturating_add(count);
    }
}

/// The recorder needs only retransmission and loss counts, not endpoint RTTs.
/// Keeping endpoints or individual RTT samples would grow without bound.
#[derive(Default)]
struct RecorderNetwork {
    retrans: u64,
    lost: u64,
    queue_lost: u64,
}

impl runtime::EventHandler<TcpEvent> for RecorderNetwork {
    fn on_event(&mut self, event: TcpEvent) {
        if event.retrans != 0 {
            self.retrans = self.retrans.saturating_add(1);
        }
    }

    fn on_lost(&mut self, count: u64) {
        self.lost = self.lost.saturating_add(count);
    }
    fn on_queue_lost(&mut self, count: u64) {
        self.queue_lost = self.queue_lost.saturating_add(count);
    }
}

fn scheduler_snapshot(stats: &mut RecorderScheduler) -> Value {
    let (p95_us, samples, slowest_us) = stats.0.take_snapshot(95);
    serde_json::json!({ "p95_us": p95_us, "samples": samples,
        "lost": stats.0.perf_lost, "queue_lost": stats.0.queue_lost, "slowest_us": slowest_us })
}

fn io_snapshot(stats: &mut RecorderIo) -> Value {
    let (p99_us, samples, slowest_us) = stats.latency.take_snapshot(99);
    serde_json::json!({ "p99_us": p99_us, "samples": samples,
        "lost": stats.latency.perf_lost, "queue_lost": stats.latency.queue_lost,
        "unmatched": stats.unmatched, "slowest_us": slowest_us })
}

fn network_snapshot(stats: &mut RecorderNetwork) -> Value {
    serde_json::json!({ "retrans": stats.retrans, "lost": stats.lost, "queue_lost": stats.queue_lost })
}

/// Interval latency measurements and cumulative event counters.
#[derive(Debug, Clone, Copy, Default, PartialEq)]
struct Cumulative {
    /// Scheduler latency p95 for this interval, in microseconds.
    sched_p95_us: u64,
    /// Scheduler samples for this interval.
    sched_samples: u64,
    /// Records dropped so far.
    sched_lost: u64,
    /// Block I/O p99 for this interval, in microseconds.
    io_p99_us: u64,
    /// Block I/O completions for this interval.
    io_samples: u64,
    /// Records dropped so far.
    io_lost: u64,
    /// Target requests that could not be tracked so far.
    io_unmatched: u64,
    /// Retransmissions so far.
    retrans: u64,
    /// Network records dropped so far.
    net_lost: u64,
    /// Queue records dropped in the latest interval.
    queue_lost: u64,
}

/// The previous tick, kept so the next one can difference against it.
///
/// Cumulative event counters are differenced; latency snapshots reset at each tick.
#[derive(Debug, Clone, Copy, Default)]
struct PreviousTick {
    at: Duration,
    usage: SelfUsage,
    totals: Cumulative,
    /// The previous successful target accounting reading.
    target_cpu: Option<(Instant, u64)>,
    /// Set once the first tick has been recorded, so the second tick produces a
    /// real interval instead of a difference against zero.
    primed: bool,
}

pub fn run(args: DaemonArgs) -> Result<()> {
    storage::Output::open(&args.output).with_context(|| {
        format!(
            "unsafe incident output {}; use a trusted directory (see fast/INCIDENT-MIGRATION.md)",
            args.output.display()
        )
    })?;
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
    crate::io_request_layout::configure(&mut bpf)?;
    let after_object_rss = read_self_rss_bytes().unwrap_or(0);
    runtime::attach_tracepoint(&mut bpf, "sched", "sched_wakeup")?;
    runtime::attach_tracepoint(&mut bpf, "sched", "sched_switch")?;
    runtime::attach_tracepoint(&mut bpf, "sched", "sched_process_exit")?;
    runtime::attach_raw_tracepoint(&mut bpf, "block_rq_issue")?;
    runtime::attach_raw_tracepoint(&mut bpf, "block_rq_complete")?;
    runtime::attach_tracepoint(&mut bpf, "tcp", "tcp_probe")?;
    runtime::attach_tracepoint(&mut bpf, "tcp", "tcp_retransmit_skb")?;

    let after_attach_rss = read_self_rss_bytes().unwrap_or(0);
    let mut target_tids = runtime::take_target_map(&mut bpf)?;
    let mut known = std::collections::BTreeSet::new();

    // The tick callback owns the state while the collection runs, and the
    // report needs it afterwards. A cell rather than a lock: the collection
    // loop is the only thread that ever touches it, and a background recorder
    // cannot afford to pay for a mutex on every interval.
    // History from before the last restart, if the caller wants it. Read
    // before the collection starts so the first tick already has a window that
    // reaches back into the previous run.
    let restored = if args.restore {
        restore_ring(&args.output, args.window)
    } else {
        Restored::default()
    };
    // Seeded before the state is built, so the first tick already sees a
    // window that reaches back into the previous run rather than one that
    // starts empty and fills up over the next minute.
    let mut ring = Ring::new(args.window, interval);
    for entry in &restored.entries {
        ring.push(entry.clone());
    }
    let state = std::rc::Rc::new(std::cell::RefCell::new(RecorderState {
        ring,
        previous: PreviousTick {
            at: restored.previous_at,
            usage: read_self_usage(),
            ..PreviousTick::default()
        },
        peak_cpu_pct: 0.0,
        peak_memory_bytes: 0,
        ticks: 0,
        incidents: Incidents::default(),
        incident_write_failed: false,
        slow_sched: Vec::new(),
        slow_io: Vec::new(),
        restored: restored.clone(),
        time_offset: restored.previous_at,
    }));
    let tick_state = std::rc::Rc::clone(&state);
    // The tick callback needs the thresholds and the output directory, both of
    // which come from the command line, so it holds its own copy rather than a
    // borrow of the arguments the caller still owns.
    let tick_args = args.clone();

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
                    RecorderScheduler::default(),
                    scheduler_snapshot,
                ),
                runtime::EventStream::sampled::<IoEvent, _>(
                    "io",
                    "IO_EVENTS",
                    PERF_PAGE_COUNT,
                    RecorderIo::default(),
                    io_snapshot,
                ),
                runtime::EventStream::sampled::<TcpEvent, _>(
                    "net",
                    "NET_EVENTS",
                    PERF_PAGE_COUNT,
                    RecorderNetwork::default(),
                    network_snapshot,
                ),
            ],
            on_tick: Some(Box::new(move |at, summary| {
                let tick_started = Instant::now();
                let mut state = tick_state.borrow_mut();
                if let Err(error) = tick(pid, tick_started, at, summary, &mut state, &tick_args) {
                    // Reported through the summary rather than stored, because the
                    // collection loop owns the error channel and a tick that cannot
                    // read /proc is not worth ending a recording over.
                    eprintln!("warning: flight recorder tick failed: {error}");
                }
                state.previous.at.saturating_sub(state.time_offset)
            })),
        },
    )?;

    let state = state.borrow();
    let (peak_cpu_pct, peak_memory_bytes, ticks) =
        (state.peak_cpu_pct, state.peak_memory_bytes, state.ticks);
    let triggers = Triggers::from_args(&args);

    if args.format.format == Format::Json {
        json::emit(
            args.format.format,
            &daemon_envelope(
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
                    state.incidents.total,
                    state.incidents.write_failures,
                    state.incidents.rotation_failures,
                    state.incidents.skipped,
                    state.incident_write_failed,
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
            &triggers,
            &state.incidents,
            state.incident_write_failed,
            &state.restored,
            args.max_disk_bytes,
        );
    }
    Ok(())
}

fn daemon_envelope<T: serde::Serialize>(
    command: &'static str,
    pid: u32,
    process: Option<String>,
    elapsed: Duration,
    interrupted: bool,
    process_exited: bool,
    data: T,
) -> Envelope<T> {
    let mut envelope = Envelope::new(
        command,
        pid,
        process,
        elapsed,
        interrupted,
        process_exited,
        data,
    );
    envelope.schema = DAEMON_SCHEMA;
    envelope
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
    /// Incidents written, and how many each trigger produced.
    incidents: Incidents,
    /// Stop writing after an error to prevent unbounded partial bundles.
    incident_write_failed: bool,
    /// The slowest latencies in the latest interval, for the incident bundle.
    slow_sched: Vec<u64>,
    slow_io: Vec<u64>,
    /// Ring entries carried over from a previous run, and where they came
    /// from, so a restarted recorder does not silently start with no history.
    restored: Restored,
    /// How far into the previous run's timeline this run starts.
    ///
    /// Without it a restarted recorder would push an entry at one second after a
    /// restored entry at eighteen seconds, and the window would read as though
    /// time ran backwards.
    time_offset: Duration,
}

/// How many of the slowest samples an incident bundle keeps.
const SLOW_SAMPLE_COUNT: usize = 16;

/// What a restarted recorder picked up from disk.
#[derive(Debug, Clone, Default, PartialEq)]
struct Restored {
    entries: Vec<RingEntry>,
    /// Wall time the previous run had reached, so the timeline stays monotonic
    /// across a restart instead of going backwards.
    previous_at: Duration,
}

/// How often each trigger fired over a run.
///
/// Kept as a running tally rather than by re-reading the incident files.
/// Only successfully written incidents are counted.
#[derive(Debug, Clone, Default, PartialEq)]
struct Incidents {
    total: u64,
    per_signal: Vec<(Signal, u64)>,
    write_failures: u64,
    rotation_failures: u64,
    skipped: u64,
}

impl Incidents {
    /// Counts one incident, given the signals that fired.
    ///
    /// An empty list is not an incident and does not count as one. The tally
    /// answers "how many bundles did this run write", and a version that
    /// incremented on every interval instead reported the interval count and
    /// claimed a bundle existed for each of them.
    fn record(&mut self, fired: &[Signal]) {
        if fired.is_empty() {
            return;
        }
        self.total = self.total.saturating_add(1);
        for signal in fired {
            match self.per_signal.iter_mut().find(|(name, _)| name == signal) {
                Some((_, count)) => *count = count.saturating_add(1),
                None => self.per_signal.push((*signal, 1)),
            }
        }
    }

    /// A summary when no incident was successfully written.
    fn empty_message(&self) -> Option<&'static str> {
        (self.total == 0).then_some("no incidents written")
    }

    /// The signals that fired at least once, most frequent first.
    fn signals(&self) -> Vec<(Signal, u64)> {
        let mut counts = self.per_signal.clone();
        counts.sort_by_key(|(_, count)| std::cmp::Reverse(*count));
        counts
    }
}

/// One tick: append interval latency snapshots and differenced counters.
fn tick(
    pid: u32,
    tick_started: Instant,
    at: Duration,
    summary: runtime::TickSummary<'_>,
    state: &mut RecorderState,
    args: &DaemonArgs,
) -> Result<()> {
    let target_cpu = cpu::read_process_ticks(pid)
        .ok()
        .map(|ticks| (Instant::now(), ticks));
    tick_with_target_cpu(tick_started, at, summary, state, args, target_cpu)
}

fn tick_with_target_cpu(
    tick_started: Instant,
    at: Duration,
    summary: runtime::TickSummary<'_>,
    state: &mut RecorderState,
    args: &DaemonArgs,
    target_cpu: Option<(Instant, u64)>,
) -> Result<()> {
    let RecorderState {
        ring,
        previous,
        peak_cpu_pct,
        peak_memory_bytes,
        ticks,
        incidents,
        incident_write_failed,
        slow_sched,
        slow_io,
        restored: _,
        time_offset,
    } = state;
    let triggers = Triggers::from_args(args);
    let mut current = Cumulative::default();
    // Slowest samples belong only to this snapshot interval.
    slow_sched.clear();
    slow_io.clear();
    for (name, value) in &summary {
        let number = |key: &str| value.get(key).and_then(Value::as_u64).unwrap_or(0);
        let slowest = |key: &str| -> Vec<u64> {
            value
                .get(key)
                .and_then(Value::as_array)
                .map(|values| values.iter().filter_map(Value::as_u64).collect())
                .unwrap_or_default()
        };
        current.queue_lost = current.queue_lost.saturating_add(number("queue_lost"));
        match *name {
            "sched" => {
                *slow_sched = slowest("slowest_us");
                current.sched_p95_us = number("p95_us");
                current.sched_samples = number("samples");
                current.sched_lost = number("lost");
            }
            "io" => {
                *slow_io = slowest("slowest_us");
                current.io_p99_us = number("p99_us");
                current.io_samples = number("samples");
                current.io_lost = number("lost");
                current.io_unmatched = number("unmatched");
            }
            "net" => {
                current.retrans = number("retrans");
                current.net_lost = number("lost");
            }
            _ => {}
        }
    }

    let usage = read_self_usage();
    // End the interval when the CPU counters were sampled, not before the
    // callback and /proc reads. The individual reads are not atomic.
    let at = at
        .saturating_add(tick_started.elapsed())
        .saturating_add(*time_offset);
    let psi = crate::memory::read_psi("/proc/pressure/memory");
    let target_cpu_percent = interval_cpu_percent(previous.target_cpu, target_cpu);

    // The first tick has nothing to difference against, so it only records the
    // baseline. Reporting a difference against zero would make the very first
    // interval look like the entire run so far.
    if !previous.primed {
        previous.at = at;
        previous.usage = usage;
        previous.primed = true;
        previous.totals = current;
        previous.target_cpu = target_cpu;
        *ticks = 1;
        *peak_cpu_pct = (*peak_cpu_pct).max(cpu_cost_pct(usage.ticks, at));
        *peak_memory_bytes = (*peak_memory_bytes).max(usage.rss_bytes);
        return Ok(());
    }

    // Both sides carry the same offset, so the interval is unaffected by it.
    let window = at.saturating_sub(previous.at);
    let cpu_ticks = usage.ticks.saturating_sub(previous.usage.ticks);
    let cost = cpu_cost_pct(cpu_ticks, window);
    let memory = usage.rss_bytes.max(previous.usage.rss_bytes);

    let before = previous.totals;
    // The queue counter is already an interval count: the runtime swaps it to
    // zero before each snapshot. The per-stream perf counters are cumulative.
    let queue_lost = current.queue_lost;
    let lost_by_stream = LostByStream {
        sched: current.sched_lost.saturating_sub(before.sched_lost),
        io: current.io_lost.saturating_sub(before.io_lost),
        net: current.net_lost.saturating_sub(before.net_lost),
    };
    let lost = lost_by_stream
        .sched
        .saturating_add(lost_by_stream.io)
        .saturating_add(lost_by_stream.net)
        .saturating_add(queue_lost);

    if lost != 0 {
        eprintln!(
            "warning: flight recorder lost {lost} events in this interval ({queue_lost} from the userspace queue)"
        );
    }

    let mut entry = RingEntry {
        at,
        // Latency distributions and their sample counts reset together at each tick.
        sched_p95_us: current.sched_p95_us,
        sched_samples: current.sched_samples,
        cpu_percent: target_cpu_percent,
        io_p99_us: current.io_p99_us,
        io_samples: current.io_samples,
        io_unmatched: current.io_unmatched.saturating_sub(before.io_unmatched),
        retrans: current.retrans.saturating_sub(before.retrans),
        psi_some_pct: psi.available.then_some(psi.some_pct),
        psi_full_pct: psi.available.then_some(psi.full_pct),
        lost,
        queue_lost,
        lost_by_stream: Some(lost_by_stream),
        cpu_cost_pct: cost,
        memory_bytes: memory,
        fired: Vec::new(),
    };

    // The triggers read the same interval the ring does, so a trigger can
    // never fire on a number the incident does not show.
    let fired = triggers.evaluate(&Interval {
        sched_p95_us: entry.sched_p95_us,
        sched_samples: entry.sched_samples,
        io_p99_us: entry.io_p99_us,
        io_samples: entry.io_samples,
        retrans: entry.retrans,
        psi_some_pct: entry.psi_some_pct.map(f64::from),
        psi_full_pct: entry.psi_full_pct.map(f64::from),
        cpu_percent: entry.cpu_percent,
    });
    entry.fired = fired.clone();
    // The incident file is written before the entry goes into the ring, so a
    // bundle that exists always has its triggering interval in it.
    let incident_result = if !fired.is_empty() && !*incident_write_failed {
        let slow = SlowSamples {
            sched_us: slow_sched.clone(),
            io_us: slow_io.clone(),
        };
        match write_incident(ring, entry.clone(), &triggers, args, &slow) {
            Ok(completed) => {
                incidents.record(&fired);
                if let Some(error) = completed.rotation_error {
                    incidents.rotation_failures = incidents.rotation_failures.saturating_add(1);
                    *incident_write_failed = true;
                    Err(error.context("incident completed, but rotation failed; incident writes disabled for this run"))
                } else {
                    Ok(())
                }
            }
            Err(error) => {
                incidents.write_failures = incidents.write_failures.saturating_add(1);
                *incident_write_failed = true;
                Err(error.context("incident write failed; incident writes disabled for this run"))
            }
        }
    } else {
        if !fired.is_empty() {
            incidents.skipped = incidents.skipped.saturating_add(1);
        }
        Ok(())
    };
    ring.push(entry);

    *peak_cpu_pct = (*peak_cpu_pct).max(cost);
    *peak_memory_bytes = (*peak_memory_bytes).max(memory);
    *ticks = ticks.saturating_add(1);
    previous.at = at;
    previous.usage = usage;
    previous.totals = current;
    previous.target_cpu = target_cpu;
    incident_result
}

/// Calculates usage from consecutive successful accounting readings.
fn interval_cpu_percent(
    previous: Option<(Instant, u64)>,
    current: Option<(Instant, u64)>,
) -> Option<f64> {
    let (before_at, before_ticks) = previous?;
    let (after_at, after_ticks) = current?;
    let elapsed = after_at.checked_duration_since(before_at)?.as_secs_f64();
    let ticks = after_ticks.checked_sub(before_ticks)?;
    // sysconf reports the units used by /proc/<pid>/stat.
    let hz = unsafe { libc::sysconf(libc::_SC_CLK_TCK) };
    if elapsed == 0.0 || hz <= 0 {
        return None;
    }
    Some(ticks as f64 / hz as f64 / elapsed * 100.0)
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
    triggers: &Triggers,
    incidents: &Incidents,
    incident_write_failed: bool,
    restored: &Restored,
    max_disk_bytes: u64,
) {
    println!("Flight recorder for {name} ({pid})");
    println!("Measurement: {MEASUREMENT_SEMANTICS}");
    println!("Ran for {}", humantime::format_duration(summary.elapsed));
    println!(
        "Window: {} at a {} interval, {} entries held",
        humantime::format_duration(args.window),
        humantime::format_duration(args.interval),
        ring.max_entries()
    );
    if restored.entries.is_empty() {
        println!("History: none restored from a previous run");
    } else {
        println!(
            "History: {} interval(s) restored, reaching back to {}s of the previous run",
            restored.entries.len(),
            restored
                .entries
                .first()
                .map_or(0, |entry| entry.at.as_secs())
        );
    }
    println!("Intervals recorded: {ticks}");
    println!(
        "Output: {} (kept under {} by dropping the oldest bundles)",
        args.output.display(),
        human_bytes(max_disk_bytes)
    );
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
    println!("Triggers");
    let enabled = triggers.enabled();
    if enabled.is_empty() {
        println!("  all disabled, so no incident will be written");
    } else {
        for signal in enabled {
            let threshold = signal.threshold(triggers).unwrap_or_default();
            println!("  {signal} at {threshold} {}", signal.unit());
        }
    }
    // The count stands on its own with no unit glued to it, so a script reading
    // this line does not have to strip a plural off a number. A line that needs
    // cleaning up before it can be compared is not machine-readable, and this
    // is the one line of the report another tool is expected to read.
    println!("  incidents written: {}", incidents.total);
    for (signal, count) in incidents.signals() {
        println!("    {signal}: {count}");
    }
    println!("  incident write failures: {}", incidents.write_failures);
    println!(
        "  rotation failures after completed incidents: {}",
        incidents.rotation_failures
    );
    println!("  incidents skipped after failure: {}", incidents.skipped);
    if incident_write_failed {
        println!("  incident writing disabled for this run");
    }
    if incidents.total == 0 && incidents.write_failures == 0 && incidents.skipped == 0 {
        println!("    no trigger fired");
    }
    println!();
    println!("Recent intervals");
    let shown: Vec<&RingEntry> = ring.entries().rev().take(5).collect();
    if shown.is_empty() {
        println!("  no intervals recorded");
        return;
    }
    println!(
        "  {:>8} {:>10} {:>8} {:>10} {:>8} {:>7} {:>8}",
        "at", "sched p95", "io p99", "retrans", "cpu cost", "rss KiB", "fired"
    );
    for entry in shown {
        let fired = if entry.fired.is_empty() {
            "-".to_string()
        } else {
            entry
                .fired
                .iter()
                .map(|signal| signal.name())
                .collect::<Vec<_>>()
                .join(",")
        };
        println!(
            "  {:>7}s {:>9}us {:>7}us {:>10} {:>7.2}% {:>7} {fired:>8}",
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
    #[test]
    fn recorder_network_counts_without_retaining_samples() {
        use crate::runtime::EventHandler;
        let mut collector = super::RecorderNetwork::default();
        let mut event: fast_common::TcpEvent = bytemuck::Zeroable::zeroed();
        for _ in 0..100_000 {
            collector.on_event(event);
        }
        event.retrans = 1;
        collector.on_event(event);
        collector.on_lost(3);
        assert_eq!(collector.retrans, 1);
        assert_eq!(collector.lost, 3);
        assert_eq!(std::mem::size_of_val(&collector), 24);
    }


    #[test]
    fn interval_cpu_percent_uses_tick_deltas_and_actual_elapsed_time() {
        use super::*;
        let hz = unsafe { libc::sysconf(libc::_SC_CLK_TCK) } as u64;
        assert!(hz > 0);
        let start = Instant::now();
        let sample = |seconds, ticks| Some((start + Duration::from_secs(seconds), ticks));
        let baseline = sample(0, 10_000 * hz);
        let first = sample(1, 10_001 * hz);
        let second = sample(2, 10_002 * hz);
        assert_eq!(interval_cpu_percent(baseline, first), Some(100.0));
        assert_eq!(interval_cpu_percent(first, second), Some(100.0));
        let changed = sample(4, 10_003 * hz);
        assert_eq!(interval_cpu_percent(second, changed), Some(50.0));
        let multicore = sample(5, 10_006 * hz);
        assert_eq!(interval_cpu_percent(changed, multicore), Some(300.0));
        assert_eq!(
            interval_cpu_percent(multicore, sample(6, 10_006 * hz)),
            Some(0.0)
        );
    }

    #[test]
    fn interval_cpu_percent_requires_consecutive_valid_readings() {
        use super::*;
        let now = Instant::now();
        let first = Some((now, 100));
        let next = Some((now + Duration::from_secs(1), 200));
        assert_eq!(interval_cpu_percent(None, first), None);
        assert_eq!(interval_cpu_percent(first, None), None);
        assert_eq!(interval_cpu_percent(None, next), None);
        assert_eq!(interval_cpu_percent(first, Some((now, 200))), None);
        assert_eq!(
            interval_cpu_percent(first, Some((now + Duration::from_secs(1), 99))),
            None
        );
        assert!(interval_cpu_percent(first, next).is_some());
    }

    #[test]
    fn missing_cpu_is_null_and_does_not_fire_or_restore_as_zero() {
        use super::*;
        let entry = RingEntry::default();
        assert!(entry.to_json()["cpu_percent"].is_null());
        assert_eq!(entry.measured(Signal::CpuUsage), None);
        assert_eq!(
            ring_entry_from_json(&entry.to_json()).unwrap().cpu_percent,
            None
        );
        let mut json = entry.to_json();
        json["cpu_percent"] = serde_json::json!(42.5);
        assert_eq!(ring_entry_from_json(&json).unwrap().cpu_percent, Some(42.5));
    }
    use super::*;

    fn tick_test_state() -> RecorderState {
        RecorderState {
            ring: Ring::new(Duration::from_secs(60), Duration::from_secs(1)),
            previous: PreviousTick::default(),
            peak_cpu_pct: 0.0,
            peak_memory_bytes: 0,
            ticks: 0,
            incidents: Incidents::default(),
            slow_sched: Vec::new(),
            slow_io: Vec::new(),
            restored: Restored::default(),
            time_offset: Duration::ZERO,
        }
    }

    fn tick_summary(samples: u64) -> runtime::TickSummary<'static> {
        vec![("sched", serde_json::json!({"samples": samples}))]
    }

    #[test]
    fn tick_baseline_and_missing_read_recovery_reach_ring_and_triggers() {
        let dir = temp_dir("tick_read_recovery");
        let mut args = default_args(&dir);
        args.trigger_cpu = "80".parse().unwrap();
        let mut state = tick_test_state();
        let start = Instant::now();
        let hz = unsafe { libc::sysconf(libc::_SC_CLK_TCK) } as u64;
        assert!(hz > 0);
        let sample = |n: u64| Some((start + Duration::from_secs(n), (1000 + n) * hz));
        tick_with_target_cpu(
            Instant::now(),
            Duration::from_secs(1),
            tick_summary(10),
            &mut state,
            &args,
            sample(0),
        )
        .unwrap();
        assert_eq!(state.ring.entries().count(), 0);
        tick_with_target_cpu(
            Instant::now(),
            Duration::from_secs(2),
            tick_summary(20),
            &mut state,
            &args,
            None,
        )
        .unwrap();
        tick_with_target_cpu(
            Instant::now(),
            Duration::from_secs(3),
            tick_summary(30),
            &mut state,
            &args,
            sample(2),
        )
        .unwrap();
        let entries: Vec<_> = state.ring.entries().collect();
        assert_eq!(
            entries.iter().map(|e| e.cpu_percent).collect::<Vec<_>>(),
            vec![None, None]
        );
        assert!(entries.iter().all(|e| !e.fired.contains(&Signal::CpuUsage)));
        tick_with_target_cpu(
            Instant::now(),
            Duration::from_secs(4),
            tick_summary(40),
            &mut state,
            &args,
            sample(3),
        )
        .unwrap();
        let entry = state.ring.entries().last().unwrap();
        assert_eq!(entry.cpu_percent, Some(100.0));
        assert_eq!(entry.sched_samples, 10);
        assert!(entry.fired.contains(&Signal::CpuUsage));
        assert_eq!(state.incidents.total, 1);
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn tick_commits_all_interval_state_when_incident_write_fails() {
        let dir = temp_dir("tick_write_recovery");
        let output = dir.join("blocked");
        std::fs::write(&output, "not a directory").unwrap();
        let mut args = default_args(&output);
        args.trigger_cpu = "80".parse().unwrap();
        let mut state = tick_test_state();
        let start = Instant::now();
        let hz = unsafe { libc::sysconf(libc::_SC_CLK_TCK) } as u64;
        assert!(hz > 0);
        let sample = |seconds, ticks| Some((start + Duration::from_secs(seconds), ticks * hz));
        tick_with_target_cpu(
            Instant::now(),
            Duration::from_secs(1),
            tick_summary(10),
            &mut state,
            &args,
            sample(0, 1000),
        )
        .unwrap();
        assert!(
            tick_with_target_cpu(
                Instant::now(),
                Duration::from_secs(2),
                tick_summary(20),
                &mut state,
                &args,
                sample(1, 1001)
            )
            .is_err()
        );
        let failed_entry = state.ring.entries().last().unwrap();
        assert_eq!(failed_entry.cpu_percent, Some(100.0));
        assert_eq!(failed_entry.sched_samples, 10);
        assert!(failed_entry.fired.contains(&Signal::CpuUsage));
        assert_eq!(state.previous.at, Duration::from_secs(2));
        assert_eq!(state.ticks, 2);
        assert_eq!(state.incidents.total, 0);
        assert_eq!(
            state.incidents.empty_message(),
            Some("no incidents written")
        );
        std::fs::remove_file(&output).unwrap();
        std::fs::create_dir(&output).unwrap();
        tick_with_target_cpu(
            Instant::now(),
            Duration::from_secs(3),
            tick_summary(35),
            &mut state,
            &args,
            sample(2, 1003),
        )
        .unwrap();
        let entry = state.ring.entries().last().unwrap();
        assert_eq!(entry.cpu_percent, Some(200.0));
        assert_eq!(entry.sched_samples, 15);
        assert!(entry.fired.contains(&Signal::CpuUsage));
        assert_eq!(state.ticks, 3);
        assert_eq!(state.incidents.total, 1);
        assert_eq!(state.incidents.empty_message(), None);
        let bundle = std::fs::read_dir(&output)
            .unwrap()
            .next()
            .unwrap()
            .unwrap()
            .path();
        let manifest: Value =
            serde_json::from_slice(&std::fs::read(bundle.join("manifest.json")).unwrap()).unwrap();
        let complete: Value =
            serde_json::from_slice(&std::fs::read(bundle.join("complete.json")).unwrap()).unwrap();
        let diagnosis: Value =
            serde_json::from_slice(&std::fs::read(bundle.join("diagnosis.json")).unwrap()).unwrap();
        let history: Value =
            serde_json::from_slice(&std::fs::read(bundle.join("intervals.json")).unwrap()).unwrap();
        assert_eq!(manifest["schema"], DAEMON_SCHEMA);
        assert_eq!(complete["schema"], DAEMON_SCHEMA);
        assert_eq!(diagnosis["schema"], DAEMON_SCHEMA);
        assert_eq!(manifest["triggered_by"][0]["measured"], 200.0);
        assert_eq!(history[0]["cpu_percent"], 100.0);
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn daemon_report_v2_and_v1_bundle_restoration() {
        let mut ring = Ring::new(Duration::from_secs(60), Duration::from_secs(1));
        ring.push(RingEntry::default());
        let envelope = daemon_envelope(
            "daemon",
            1,
            None,
            Duration::from_secs(1),
            false,
            false,
            crate::json_payloads::daemon_json(&ring, 0.0, 0, 1),
        );
        let document = serde_json::to_value(envelope).unwrap();
        assert_eq!(document["schema"], "rand-fast/v2");
        assert!(document["data"]["intervals_detail"][0]["cpu_percent"].is_null());
        let dir = temp_dir("restore_v1_cpu");
        let bundle = dir.join("incident-000000001000s");
        std::fs::create_dir(&bundle).unwrap();
        std::fs::write(bundle.join("complete.json"), r#"{"schema":"rand-fast/v1"}"#).unwrap();
        std::fs::write(bundle.join("manifest.json"), r#"{"schema":"rand-fast/v1"}"#).unwrap();
        std::fs::write(
            bundle.join("intervals.json"),
            r#"[{"at_s":1.0,"cpu_percent":87.5}]"#,
        )
        .unwrap();
        let restored = restore_ring(&dir, Duration::from_secs(60));
        assert_eq!(restored.entries.len(), 1);
        assert_eq!(restored.entries[0].cpu_percent, Some(87.5));
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn interval_latency_spike_recovery_empty_and_final_tick() {
        use crate::runtime::EventHandler;
        let dir = temp_dir("interval-latency");
        let mut args = default_args(&dir);
        args.trigger_psi_some = "off".parse().unwrap();
        args.trigger_psi_full = "off".parse().unwrap();
        let mut state = RecorderState {
            ring: Ring::new(Duration::from_secs(60), Duration::from_secs(1)),
            previous: PreviousTick::default(),
            peak_cpu_pct: 0.0,
            peak_memory_bytes: 0,
            ticks: 0,
            incidents: Incidents::default(),
            incident_write_failed: false,
            slow_sched: Vec::new(),
            slow_io: Vec::new(),
            restored: Restored::default(),
            time_offset: Duration::ZERO,
        };
        let mut sched = RecorderScheduler::default();
        let mut io = RecorderIo::default();
        let mut net = RecorderNetwork::default();
        let mut sched_event: SchedulerLatencyEvent = bytemuck::Zeroable::zeroed();
        let mut io_event: IoEvent = bytemuck::Zeroable::zeroed();
        for (i, latency) in [1_000_000, 40_000_000, 1_000_000, 0, 2_000_000]
            .into_iter()
            .enumerate()
        {
            if latency != 0 {
                sched_event.latency_ns = latency;
                io_event.latency_ns = latency;
                for _ in 0..100 {
                    sched.on_event(sched_event);
                    io.on_event(io_event);
                }
            }
            if i == 1 {
                sched.on_lost(2);
                io.on_queue_lost(3);
                net.on_lost(4);
                io_event.op = fast_common::IO_OP_UNMATCHED;
                io.on_event(io_event);
                io_event.op = 0;
            }
            // The last snapshot represents a short final interval.
            let at = if i == 4 {
                Duration::from_millis(4250)
            } else {
                Duration::from_secs(i as u64 + 1)
            };
            tick(
                args.pid,
                Instant::now(),
                at,
                vec![
                    ("sched", scheduler_snapshot(&mut sched)),
                    ("io", io_snapshot(&mut io)),
                    ("net", network_snapshot(&mut net)),
                ],
                &mut state,
                &args,
            )
            .unwrap();
            if i == 1 {
                assert_eq!(state.slow_sched, vec![40_000; SLOW_SAMPLE_COUNT]);
                assert_eq!(state.slow_io, vec![40_000; SLOW_SAMPLE_COUNT]);
            }
        }
        let entries: Vec<_> = state.ring.entries().collect();
        assert_eq!(entries.len(), 5);
        assert!(entries[0].fired.is_empty());
        assert!(entries[1].fired.contains(&Signal::SchedulerP95));
        assert!(entries[1].fired.contains(&Signal::IoP99));
        assert_eq!(
            (entries[1].sched_samples, entries[1].io_samples),
            (100, 100)
        );
        assert_eq!(
            (
                entries[1].lost,
                entries[1].queue_lost,
                entries[1].io_unmatched
            ),
            (9, 3, 1)
        );
        assert!(entries[2].fired.is_empty());
        assert!(entries[2].sched_p95_us < 10_000 && entries[2].io_p99_us < 25_000);
        assert_eq!((entries[2].lost, entries[2].io_unmatched), (0, 0));
        assert_eq!((entries[3].sched_samples, entries[3].io_samples), (0, 0));
        assert_eq!((entries[3].sched_p95_us, entries[3].io_p99_us), (0, 0));
        assert_eq!(
            (entries[4].sched_samples, entries[4].io_samples),
            (100, 100)
        );
        assert!(entries[4].at >= Duration::from_millis(4250));
        assert_eq!(state.slow_sched, vec![2_000; SLOW_SAMPLE_COUNT]);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn failed_incident_writes_are_disabled_without_losing_interval_state() {
        let dir = temp_dir("failed-incident");
        std::fs::create_dir_all(&dir).unwrap();
        let output_file = dir.join("not-a-directory");
        std::fs::write(&output_file, "x").unwrap();
        let mut args = default_args(&output_file);
        args.trigger_psi_some = "off".parse().unwrap();
        args.trigger_psi_full = "off".parse().unwrap();
        let mut state = RecorderState {
            ring: Ring::new(Duration::from_secs(10), Duration::from_secs(1)),
            previous: PreviousTick::default(),
            peak_cpu_pct: 0.0,
            peak_memory_bytes: 0,
            ticks: 0,
            incidents: Incidents::default(),
            incident_write_failed: false,
            slow_sched: Vec::new(),
            slow_io: Vec::new(),
            restored: Restored::default(),
            time_offset: Duration::ZERO,
        };
        let snapshot = || {
            vec![(
                "sched",
                serde_json::json!({"p95_us": 100_000, "samples": 5, "lost": 2}),
            )]
        };
        let error = tick(
            args.pid,
            Instant::now(),
            Duration::from_secs(1),
            snapshot(),
            &mut state,
            &args,
        )
        .unwrap_err();
        assert!(error.to_string().contains("disabled"));
        assert!(state.incident_write_failed);
        assert_eq!(state.ring.entries().last().unwrap().lost, 2);
        tick(
            args.pid,
            Instant::now(),
            Duration::from_secs(2),
            snapshot(),
            &mut state,
            &args,
        )
        .unwrap();
        assert_eq!(state.ring.entries().last().unwrap().lost, 0);
        assert_eq!(state.ring.entries().count(), 2);
        assert_eq!(state.incidents.total, 0);
        assert_eq!(state.incidents.write_failures, 1);
        assert_eq!(state.incidents.skipped, 1);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn rotation_evicts_oldest_at_entry_limit_and_recording_continues() {
        let dir = temp_dir("rotation-long-run");
        std::fs::create_dir_all(&dir).unwrap();
        // Small incidents can reach the entry limit well before the byte cap.
        for i in 0..MAX_ROTATION_ENTRIES - 2 {
            std::fs::create_dir(dir.join(format!("incident-{i:012}s"))).unwrap();
        }
        let args = default_args(&dir);
        let ring = Ring::new(Duration::from_secs(60), Duration::from_secs(1));
        let slow = SlowSamples {
            sched_us: vec![],
            io_us: vec![],
        };
        let triggers = Triggers::from_args(&args);
        for i in 0..5 {
            let mut entry = slow_io_entry();
            entry.at = Duration::from_secs(100_000 + i);
            let completed = write_incident(&ring, entry, &triggers, &args, &slow).unwrap();
            assert!(completed.rotation_error.is_none());
            assert!(std::fs::read_dir(&dir).unwrap().count() < MAX_ROTATION_ENTRIES);
        }
        assert!(!dir.join("incident-000000000000s").exists());
        assert!(
            dir.join(format!("incident-{}", stamp(Duration::from_secs(100_004))))
                .join("complete.json")
                .exists()
        );
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn completed_incident_and_rotation_failure_are_reported_separately() {
        let dir = temp_dir("rotation-failed-after-complete");
        let bad = dir.join("incident-old");
        std::fs::create_dir_all(&bad).unwrap();
        for i in 0..=MAX_BUNDLE_FILES {
            std::fs::write(bad.join(i.to_string()), "x").unwrap();
        }
        let mut args = default_args(&dir);
        args.trigger_psi_some = "off".parse().unwrap();
        args.trigger_psi_full = "off".parse().unwrap();
        let mut state = RecorderState {
            ring: Ring::new(Duration::from_secs(10), Duration::from_secs(1)),
            previous: PreviousTick::default(),
            peak_cpu_pct: 0.0,
            peak_memory_bytes: 0,
            ticks: 0,
            incidents: Incidents::default(),
            incident_write_failed: false,
            slow_sched: Vec::new(),
            slow_io: Vec::new(),
            restored: Restored::default(),
            time_offset: Duration::ZERO,
        };
        let snapshot = || {
            vec![(
                "sched",
                serde_json::json!({"p95_us": 100_000, "samples": 5}),
            )]
        };
        let error = tick(
            args.pid,
            Instant::now(),
            Duration::from_secs(1),
            snapshot(),
            &mut state,
            &args,
        )
        .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("incident completed, but rotation failed")
        );
        assert_eq!(state.incidents.total, 1);
        assert_eq!(state.incidents.rotation_failures, 1);
        assert_eq!(state.incidents.write_failures, 0);
        assert!(state.incident_write_failed);
        assert!(
            std::fs::read_dir(&dir)
                .unwrap()
                .flatten()
                .any(|e| e.path() != bad && e.path().join("complete.json").exists())
        );
        tick(
            args.pid,
            Instant::now(),
            Duration::from_secs(2),
            snapshot(),
            &mut state,
            &args,
        )
        .unwrap();
        assert_eq!(state.incidents.skipped, 1);
        let json = crate::json_payloads::daemon_json(
            &state.ring,
            0.0,
            0,
            state.ticks,
            state.incidents.total,
            state.incidents.write_failures,
            state.incidents.rotation_failures,
            state.incidents.skipped,
            state.incident_write_failed,
        );
        let json = serde_json::to_value(json).unwrap();
        assert_eq!(json["incidents_written"], 1);
        assert_eq!(json["incident_rotation_failures"], 1);
        assert_eq!(json["incidents_skipped"], 1);
        assert_eq!(json["incident_writes_disabled"], true);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn rotation_rejects_unbounded_bundle_contents() {
        let dir = temp_dir("rotation-files-limit");
        let bundle = dir.join("incident");
        std::fs::create_dir_all(&bundle).unwrap();
        for i in 0..=MAX_BUNDLE_FILES {
            std::fs::write(bundle.join(i.to_string()), "x").unwrap();
        }
        assert!(rotate(&dir, 0, &bundle).is_err());
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn tick_timestamp_includes_time_to_sample_cpu_counters() {
        let dir = temp_dir("counter-timing");
        let mut args = default_args(&dir);
        args.trigger_psi_some = "off".parse().unwrap();
        args.trigger_psi_full = "off".parse().unwrap();
        let mut state = RecorderState {
            ring: Ring::new(Duration::from_secs(10), Duration::from_secs(1)),
            previous: PreviousTick::default(),
            peak_cpu_pct: 0.0,
            peak_memory_bytes: 0,
            ticks: 0,
            incidents: Incidents::default(),
            incident_write_failed: false,
            slow_sched: Vec::new(),
            slow_io: Vec::new(),
            restored: Restored::default(),
            time_offset: Duration::ZERO,
        };
        tick(
            args.pid,
            Instant::now() - Duration::from_millis(200),
            Duration::from_secs(1),
            Vec::new(),
            &mut state,
            &args,
        )
        .unwrap();
        assert!(state.previous.at >= Duration::from_millis(1200));
        assert_eq!(state.ring.entries().last().unwrap().at, state.previous.at);
    }

    #[test]
    fn interval_latency_histogram_is_bounded_and_has_documented_error() {
        let mut stats = IntervalLatency::default();
        let capacity = stats.slowest.capacity();
        for interval in 0..20 {
            for i in 0..100_000u64 {
                stats.record(i * 13 + interval);
            }
            assert_eq!(stats.count, 100_000);
            assert_eq!(stats.slowest.len(), SLOW_SAMPLE_COUNT);
            assert_eq!(stats.slowest.capacity(), capacity);
            let actual = (99_000u64 - 1) * 13 + interval;
            let estimate = stats.percentile_ns(99);
            assert!(estimate <= actual && estimate as u128 * 8 >= actual as u128 * 7);
            let (p99, count, slowest) = stats.take_snapshot(99);
            assert_eq!(p99, estimate / 1000);
            assert_eq!(count, 100_000);
            assert_eq!(slowest.len(), SLOW_SAMPLE_COUNT);
            assert_eq!(stats.take_snapshot(99), (0, 0, Vec::new()));
        }
        for value in [0, 1, 15, 16, 17, u64::MAX] {
            stats.record(value);
            let estimate = stats.percentile_ns(99);
            assert!(estimate <= value && estimate as u128 * 8 >= value as u128 * 7);
            stats.take_snapshot(99);
        }
    }

    #[test]
    fn tick_records_all_stream_loss_deltas_and_restores_them() {
        use crate::runtime::EventHandler;

        let dir = temp_dir("stream_loss_deltas");
        let mut args = default_args(&dir);
        args.trigger_sched_p95 = "off".parse().unwrap();
        args.trigger_io_p99 = "off".parse().unwrap();
        args.trigger_retrans = "off".parse().unwrap();
        args.trigger_psi_some = "off".parse().unwrap();
        args.trigger_psi_full = "off".parse().unwrap();
        let mut state = RecorderState {
            ring: Ring::new(args.window, args.interval),
            previous: PreviousTick::default(),
            peak_cpu_pct: 0.0,
            peak_memory_bytes: 0,
            ticks: 0,
            incidents: Incidents::default(),
            slow_sched: Vec::new(),
            slow_io: Vec::new(),
            restored: Restored::default(),
            time_offset: Duration::ZERO,
        };
        let mut net = network::NetStats::default();
        let started = Instant::now();
        for (second, sched, io, net_increment) in [(1, 5, 7, 11), (2, 8, 12, 13), (3, 9, 12, 2)] {
            EventHandler::<TcpEvent>::on_lost(&mut net, net_increment);
            let summary = vec![
                ("sched", serde_json::json!({"lost": sched})),
                ("io", serde_json::json!({"lost": io})),
                ("net", net_snapshot(&net)),
            ];
            tick(
                std::process::id(),
                started,
                Duration::from_secs(second),
                summary,
                &mut state,
                &args,
            )
            .unwrap();
        }
        let entries: Vec<_> = state.ring.entries().collect();
        assert_eq!(entries.len(), 2);
        assert_eq!(
            entries[0].lost_by_stream,
            Some(LostByStream {
                sched: 3,
                io: 5,
                net: 13
            })
        );
        assert_eq!(entries[0].lost, 21);
        assert_eq!(
            entries[1].lost_by_stream,
            Some(LostByStream {
                sched: 1,
                io: 0,
                net: 2
            })
        );
        assert_eq!(entries[1].lost, 3);
        let json = entries[0].to_json();
        assert_eq!(json["lost_events"], 21);
        assert_eq!(json["lost_events_by_stream"]["net"], 13);
        assert_eq!(ring_entry_from_json(&json).unwrap(), *entries[0]);
        let legacy =
            ring_entry_from_json(&serde_json::json!({"at_s": 1, "lost_events": 9})).unwrap();
        assert_eq!(legacy.lost, 9);
        assert_eq!(legacy.lost_by_stream, None);

        // A reset in one stream must not cancel losses in another stream.
        for (second, sched, io, net) in [
            (4, 100, 0, 0),
            (5, 0, 50, 0),
            (6, 0, 0, 0),
            (7, u64::MAX, 1, 1),
        ] {
            let summary = vec![
                ("sched", serde_json::json!({"lost": sched})),
                ("io", serde_json::json!({"lost": io})),
                ("net", serde_json::json!({"lost": net})),
            ];
            tick(
                std::process::id(),
                started,
                Duration::from_secs(second),
                summary,
                &mut state,
                &args,
            )
            .unwrap();
        }
        let entries: Vec<_> = state.ring.entries().collect();
        assert_eq!(entries[3].lost, 50);
        assert_eq!(
            entries[3].lost_by_stream,
            Some(LostByStream {
                sched: 0,
                io: 50,
                net: 0
            })
        );
        assert_eq!(entries[5].lost, u64::MAX);
        assert_eq!(
            entries[5].lost_by_stream,
            Some(LostByStream {
                sched: u64::MAX,
                io: 1,
                net: 1
            })
        );
        let _ = std::fs::remove_dir_all(dir);
    }

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
            incidents: Incidents::default(),
            incident_write_failed: false,
            slow_sched: Vec::new(),
            slow_io: Vec::new(),
            restored: Restored::default(),
            time_offset: Duration::ZERO,
        };
        assert_eq!(state.peak_cpu_pct, 0.0);
        assert_eq!(state.peak_memory_bytes, 0);
        assert_eq!(state.ticks, 0);
        assert_eq!(state.incidents.total, 0);
    }

    fn default_args(output: &std::path::Path) -> DaemonArgs {
        DaemonArgs {
            pid: 4242,
            duration: Duration::from_secs(1),
            interval: Duration::from_secs(1),
            window: Duration::from_secs(60),
            trigger_sched_p95: "10ms".parse().expect("threshold"),
            trigger_io_p99: "25ms".parse().expect("threshold"),
            trigger_retrans: "8".parse().expect("threshold"),
            trigger_psi_some: "10".parse().expect("threshold"),
            trigger_psi_full: "5".parse().expect("threshold"),
            trigger_cpu: "off".parse().expect("threshold"),
            output: output.to_path_buf(),
            max_disk_bytes: 512 * 1024 * 1024,
            restore: true,
            format: crate::cli::FormatArg {
                format: Format::Text,
            },
        }
    }

    fn slow_io_entry() -> RingEntry {
        RingEntry {
            at: Duration::from_secs(12),
            sched_p95_us: 80,
            sched_samples: 500,
            io_p99_us: 900_000,
            io_samples: 30,
            fired: vec![Signal::IoP99],
            ..RingEntry::default()
        }
    }

    #[test]
    fn a_bundle_says_which_trigger_fired_and_on_what() {
        // The point of a bundle: read it later with no other context and find
        // out what tripped it, by how much, and against which threshold.
        let dir = temp_dir("bundle_says_which_trigger");
        let args = default_args(&dir);
        let triggers = Triggers::from_args(&args);
        let mut ring = Ring::new(Duration::from_secs(60), Duration::from_secs(1));
        ring.push(RingEntry {
            at: Duration::from_secs(11),
            sched_p95_us: 40,
            ..RingEntry::default()
        });
        let slow = SlowSamples {
            sched_us: vec![],
            io_us: vec![],
        };
        write_incident(&ring, slow_io_entry(), &triggers, &args, &slow).expect("write bundle");

        let bundle = std::fs::read_dir(&dir)
            .expect("read output dir")
            .next()
            .expect("one bundle")
            .expect("entry")
            .path();
        let manifest: Value = serde_json::from_str(
            &std::fs::read_to_string(bundle.join("manifest.json")).expect("read manifest"),
        )
        .expect("parse manifest");

        let triggered = &manifest["triggered_by"];
        assert_eq!(triggered.as_array().map(Vec::len), Some(1));
        assert_eq!(triggered[0]["signal"], "io_p99");
        assert_eq!(triggered[0]["unit"], "microseconds");
        assert_eq!(triggered[0]["measured"], 900_000.0);
        assert_eq!(triggered[0]["threshold"], 25_000.0);
        // The thresholds that were in force belong in the bundle too, or a
        // reader cannot tell a 900ms stall from a badly configured trigger.
        let thresholds = manifest["thresholds"].as_array().expect("thresholds");
        assert!(thresholds.iter().any(|entry| entry["signal"] == "retrans"));

        // The history that led up to the trigger travels with it.
        let intervals: Value = serde_json::from_str(
            &std::fs::read_to_string(bundle.join("intervals.json")).expect("read intervals"),
        )
        .expect("parse intervals");
        assert_eq!(intervals.as_array().map(Vec::len), Some(1));

        let text = std::fs::read_to_string(bundle.join("summary.txt")).expect("read summary");
        assert!(text.contains("io_p99"), "summary names the trigger: {text}");
        assert!(text.contains("900000"), "summary states the value: {text}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn two_triggers_in_one_second_do_not_overwrite_each_other() {
        // A recorder that drops the earlier bundle loses the first incident of
        // a burst, which is the one that usually explains the rest.
        let dir = temp_dir("triggers_do_not_overwrite");
        let args = default_args(&dir);
        let triggers = Triggers::from_args(&args);
        let ring = Ring::new(Duration::from_secs(60), Duration::from_secs(1));
        let slow = SlowSamples {
            sched_us: vec![],
            io_us: vec![],
        };
        write_incident(&ring, slow_io_entry(), &triggers, &args, &slow).expect("first");
        write_incident(&ring, slow_io_entry(), &triggers, &args, &slow).expect("second");

        let count = std::fs::read_dir(&dir).expect("read output dir").count();
        assert_eq!(count, 2, "both bundles survive");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A scratch directory under the target dir, removed by the test itself.
    fn temp_dir(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("fast-{name}"));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("create scratch dir");
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).unwrap();
        dir
    }

    #[test]
    fn bundle_names_sort_in_time_order() {
        // Rotation deletes the oldest first and a restart recovers from the
        // newest, so both read the names as a timeline. A human-readable stamp
        // does not sort that way: "10s" comes after "2s", which would make a
        // restart recover a two-second-old bundle and rotation delete a
        // ten-second-old one.
        let mut stamps: Vec<String> = (0..12)
            .map(|second| stamp(Duration::from_secs(second)))
            .collect();
        let sorted = stamps.clone();
        stamps.sort();
        assert_eq!(stamps, sorted, "ascending time sorts into ascending name");

        let newest = stamps.iter().max().expect("a stamp");
        assert_eq!(
            newest,
            &stamp(Duration::from_secs(11)),
            "the newest is the maximum, not the largest digit count"
        );

        // Sub-second resolution has to keep working, or two triggers in the
        // same second would collide on the name.
        assert_ne!(
            stamp(Duration::from_millis(1_500)),
            stamp(Duration::from_secs(1)),
            "milliseconds are part of the stamp"
        );
    }

    #[test]
    fn a_bundle_carries_a_bounded_number_of_intervals() {
        // A bundle whose size grew with --window could not be bounded by
        // --max-disk-bytes, because the one incident that is never deleted
        // would grow with it. The run-up to a trigger is the recent history,
        // so the bound drops the oldest.
        let dir = temp_dir("bundle_is_bounded");
        let args = default_args(&dir);
        let triggers = Triggers::from_args(&args);
        let slow = SlowSamples {
            sched_us: vec![],
            io_us: vec![],
        };
        // A window far wider than the bound, so the ring holds more than a
        // bundle is allowed to.
        let mut ring = Ring::new(
            Duration::from_secs(BUNDLE_MAX_INTERVALS as u64 * 4),
            Duration::from_secs(1),
        );
        for second in 1..=(BUNDLE_MAX_INTERVALS as u64 * 3) {
            ring.push(RingEntry {
                at: Duration::from_secs(second),
                sched_p95_us: 40,
                ..RingEntry::default()
            });
        }
        let mut entry = slow_io_entry();
        entry.at = Duration::from_secs(BUNDLE_MAX_INTERVALS as u64 * 3 + 1);
        write_incident(&ring, entry, &triggers, &args, &slow).expect("write bundle");

        let bundle = std::fs::read_dir(&dir)
            .expect("read dir")
            .next()
            .expect("one bundle")
            .expect("entry")
            .path();
        let intervals: Value = serde_json::from_slice(
            &std::fs::read(bundle.join("intervals.json")).expect("read intervals"),
        )
        .expect("parse");
        assert_eq!(
            intervals.as_array().map(Vec::len),
            Some(BUNDLE_MAX_INTERVALS),
            "the bundle is bounded regardless of the window"
        );

        // The newest run-up is what is kept, and the manifest says so rather
        // than letting a reader assume it is the whole window.
        let manifest: Value = serde_json::from_slice(
            &std::fs::read(bundle.join("manifest.json")).expect("read manifest"),
        )
        .expect("parse");
        assert_eq!(
            manifest["history"]["intervals_carried"],
            BUNDLE_MAX_INTERVALS
        );
        assert_eq!(manifest["history"]["interval_limit"], BUNDLE_MAX_INTERVALS);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_bundle_holds_the_window_the_samples_and_a_diagnosis() {
        // The three things the issue asks a bundle to contain, checked in the
        // files rather than in the code that writes them.
        let dir = temp_dir("bundle_contents");
        let args = default_args(&dir);
        let triggers = Triggers::from_args(&args);
        let mut ring = Ring::new(Duration::from_secs(60), Duration::from_secs(1));
        for second in 1..=3 {
            ring.push(RingEntry {
                at: Duration::from_secs(second),
                sched_p95_us: 40 * second,
                ..RingEntry::default()
            });
        }
        let slow = SlowSamples {
            sched_us: vec![9_000, 5_000, 120],
            io_us: vec![40_000],
        };
        write_incident(&ring, slow_io_entry(), &triggers, &args, &slow).expect("write bundle");

        let bundle = std::fs::read_dir(&dir)
            .expect("read output dir")
            .next()
            .expect("one bundle")
            .expect("entry")
            .path();

        // The window: the intervals that led up to the trigger, not just the one
        // that tripped it.
        let intervals: Value = serde_json::from_slice(
            &std::fs::read(bundle.join("intervals.json")).expect("read intervals"),
        )
        .expect("parse");
        assert_eq!(intervals.as_array().map(Vec::len), Some(3));

        // The slow samples, longest first, as measured rather than as a
        // percentile.
        let samples: Value = serde_json::from_slice(
            &std::fs::read(bundle.join("slow-samples.json")).expect("read samples"),
        )
        .expect("parse");
        assert_eq!(samples["sched_us"], serde_json::json!([9_000, 5_000, 120]));

        // The diagnosis, which must also say what it did not measure.
        let diagnosis: Value = serde_json::from_slice(
            &std::fs::read(bundle.join("diagnosis.json")).expect("read diagnosis"),
        )
        .expect("parse");
        assert!(diagnosis["causes"].is_array());
        let missing = diagnosis["not_collected"]
            .as_array()
            .expect("not_collected");
        assert!(
            !missing.is_empty(),
            "the limits of the diagnosis are stated"
        );

        // The marker that distinguishes a finished bundle from a directory a
        // recorder was killed while writing.
        let complete: Value = serde_json::from_slice(
            &std::fs::read(bundle.join("complete.json")).expect("read marker"),
        )
        .expect("parse");
        assert!(complete["files"].is_array());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_restart_keeps_the_window_from_the_previous_run() {
        // Kill and restart: the acceptance criterion. The new run must not
        // start with an empty window, and must not pretend its first interval
        // is the first thing that ever happened.
        let dir = temp_dir("restart_keeps_window");
        let args = default_args(&dir);
        let triggers = Triggers::from_args(&args);
        let slow = SlowSamples {
            sched_us: vec![],
            io_us: vec![],
        };
        let mut ring = Ring::new(Duration::from_secs(60), Duration::from_secs(1));
        for second in 1..=3 {
            ring.push(RingEntry {
                at: Duration::from_secs(second),
                sched_p95_us: 40 * second,
                ..RingEntry::default()
            });
        }
        write_incident(&ring, slow_io_entry(), &triggers, &args, &slow).expect("write bundle");

        let restored = restore_ring(&dir, Duration::from_secs(60));
        assert_eq!(restored.entries.len(), 3, "the window survived the restart");
        assert_eq!(restored.previous_at, Duration::from_secs(3));
        // Nothing is re-counted as a fresh incident: that bundle already exists.
        assert!(restored.entries.iter().all(|entry| entry.fired.is_empty()));

        // The next run continues the same timeline, so the window does not read
        // as though time ran backwards.
        let next_tick = Duration::from_secs(1) + restored.previous_at;
        assert_eq!(next_tick, Duration::from_secs(4));
        assert!(next_tick > restored.entries.last().expect("last").at);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_partial_bundle_is_not_restored_from() {
        // A recorder killed mid-write leaves a directory with no marker. Reading
        // it would restore a window that stops short of the end with no way to
        // tell that it does.
        let dir = temp_dir("partial_not_restored");
        let bundle = dir.join("incident-9s");
        std::fs::create_dir_all(&bundle).expect("create partial bundle");
        std::fs::write(bundle.join("intervals.json"), "[]").expect("write intervals");
        assert_eq!(
            restore_ring(&dir, Duration::from_secs(60)),
            Restored::default()
        );

        // A complete marker makes it readable again.
        std::fs::write(bundle.join("complete.json"), "{}").expect("write marker");
        assert!(
            restore_ring(&dir, Duration::from_secs(60))
                .entries
                .is_empty()
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn rotation_drops_the_oldest_bundles_until_the_directory_fits() {
        // The acceptance criterion: the directory is brought back under its cap
        // by dropping the oldest bundles. The cap is set here rather than left
        // at the roomy default, where nothing would ever be rotated and the
        // check would pass without testing anything.
        let dir = temp_dir("rotation_caps_disk");
        let mut args = default_args(&dir);
        let triggers = Triggers::from_args(&args);
        let slow = SlowSamples {
            sched_us: vec![],
            io_us: vec![],
        };
        let ring = Ring::new(Duration::from_secs(60), Duration::from_secs(1));

        // A cap of one bundle plus a little, so each new incident evicts
        // exactly the oldest one.
        let one_bundle = directory_size_of_bundle(&dir, &ring, &triggers, &args, &slow);
        let cap = one_bundle * 3 / 2;
        args.max_disk_bytes = cap;

        let mut totals = Vec::new();
        for second in 1..=4 {
            let mut entry = slow_io_entry();
            entry.at = Duration::from_secs(second);
            write_incident(&ring, entry, &triggers, &args, &slow).expect("write bundle");
            let total = directory_total(&dir).expect("size");
            assert!(
                total <= cap,
                "the directory went over its cap after interval {second}: {total} > {cap}"
            );
            totals.push(total);
        }
        // It fills up and then stays put, instead of growing with every incident
        // for the life of the recorder.
        assert_eq!(
            totals[3], totals[2],
            "the total stops growing rather than tracking the incident count: {totals:?}"
        );
        let names = bundle_names(&dir);
        // The stamp is a padded millisecond count, so the check has to match
        // the whole name rather than a fragment: "4s" is not a substring of
        // "000000004000s", which is the point of the padded form.
        assert!(
            names
                .iter()
                .any(|name| name.ends_with(&stamp(Duration::from_secs(4)))),
            "the newest is kept: {names:?}"
        );
        assert!(
            !names
                .iter()
                .any(|name| name.ends_with(&stamp(Duration::from_secs(1)))),
            "the oldest is dropped: {names:?}"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn rotation_never_deletes_the_incident_it_was_called_for() {
        // A cap smaller than one incident is a configuration mistake, not a
        // licence to throw away the evidence. Deleting the bundle that was just
        // written leaves a recorder that reports incidents and stores none,
        // which is the failure mode a cap is supposed to prevent.
        let dir = temp_dir("rotation_keeps_current");
        let mut args = default_args(&dir);
        args.max_disk_bytes = 64;
        let triggers = Triggers::from_args(&args);
        let slow = SlowSamples {
            sched_us: vec![],
            io_us: vec![],
        };
        let ring = Ring::new(Duration::from_secs(60), Duration::from_secs(1));
        let mut entry = slow_io_entry();
        entry.at = Duration::from_secs(2);
        write_incident(&ring, entry, &triggers, &args, &slow).expect("write bundle");

        let names = bundle_names(&dir);
        assert_eq!(names.len(), 1, "the incident survives: {names:?}");
        assert!(
            names[0].ends_with(&stamp(Duration::from_secs(2))),
            "and it is the one just written: {names:?}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Writes one bundle into a scratch directory and returns its size.
    fn directory_size_of_bundle(
        dir: &std::path::Path,
        ring: &Ring,
        triggers: &Triggers,
        args: &DaemonArgs,
        slow: &SlowSamples,
    ) -> u64 {
        let mut entry = slow_io_entry();
        entry.at = Duration::from_secs(99);
        write_incident(ring, entry, triggers, args, slow).expect("write bundle");
        let size = directory_total(dir).expect("size");
        let _ = std::fs::remove_dir_all(dir);
        std::fs::create_dir_all(dir).expect("recreate scratch dir");
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(dir, fs::Permissions::from_mode(0o700)).unwrap();
        size
    }

    /// The bundle directory names under an output directory, sorted.
    fn bundle_names(dir: &std::path::Path) -> Vec<String> {
        let mut names: Vec<String> = std::fs::read_dir(dir)
            .expect("read dir")
            .filter_map(Result::ok)
            .filter_map(|entry| entry.file_name().into_string().ok())
            .collect();
        names.sort();
        names
    }

    #[test]
    fn a_restored_entry_survives_a_round_trip_through_json() {
        // A bundle that cannot be read back is a bundle that is only useful at
        // the moment it was written.
        let original = RingEntry {
            at: Duration::from_millis(1_500),
            sched_p95_us: 900,
            sched_samples: 12,
            cpu_percent: Some(87.5),
            io_p99_us: 40,
            io_samples: 7,
            io_unmatched: 2,
            retrans: 3,
            psi_some_pct: Some(2.5),
            psi_full_pct: None,
            lost: 1,
            lost_by_stream: Some(LostByStream {
                sched: 0,
                io: 0,
                net: 1,
            }),
            cpu_cost_pct: 0.5,
            memory_bytes: 4096,
            fired: vec![],
        };
        let restored = ring_entry_from_json(&original.to_json()).expect("round trip");
        assert_eq!(restored, original);
    }

    #[test]
    fn restored_intervals_ignore_invalid_timestamps_without_panicking() {
        for timestamp in [-1.0, f64::MAX] {
            let value = serde_json::json!({ "at_s": timestamp });
            assert!(ring_entry_from_json(&value).is_none());
        }
    }

    #[test]
    fn restore_skips_invalid_timestamps_and_keeps_valid_history() {
        let dir = temp_dir("restore_invalid_timestamps");
        let bundle = dir.join("incident-with-bad-intervals");
        std::fs::create_dir_all(&bundle).expect("create bundle");
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&bundle, fs::Permissions::from_mode(0o700)).unwrap();
        std::fs::write(bundle.join("complete.json"), "{}").expect("write completion marker");
        let intervals = serde_json::json!([
            {"at_s": -1.0},
            {"at_s": 10.0},
            {"at_s": f64::MAX}
        ]);
        std::fs::write(bundle.join("intervals.json"), intervals.to_string())
            .expect("write intervals");

        let restored = restore_ring(&dir, Duration::from_secs(60));
        assert_eq!(restored.entries.len(), 1);
        assert_eq!(restored.entries[0].at, Duration::from_secs(10));
        assert_eq!(restored.previous_at, Duration::from_secs(10));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn incidents_are_tallied_per_signal() {
        // The summary has to say which trigger fired and how often, which is
        // only knowable if the tally is kept as the run goes rather than
        // reconstructed from files that may not have been written.
        let mut incidents = Incidents::default();
        incidents.record(&[Signal::IoP99, Signal::SchedulerP95]);
        incidents.record(&[Signal::IoP99]);
        // A quiet interval writes nothing, so it is not an incident. Counting
        // it would report a bundle that was never written.
        incidents.record(&[]);
        incidents.record(&[]);
        assert_eq!(incidents.total, 2);
        assert_eq!(
            incidents.signals(),
            vec![(Signal::IoP99, 2), (Signal::SchedulerP95, 1)]
        );
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
            incidents: Incidents::default(),
            incident_write_failed: false,
            slow_sched: Vec::new(),
            slow_io: Vec::new(),
            restored: Restored::default(),
            time_offset: Duration::ZERO,
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
        assert!(read_self_cpu_ticks().expect("parse own ticks") >= expected);
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
