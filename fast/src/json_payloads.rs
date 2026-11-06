//! The `data` object each command emits in JSON mode.
//!
//! Keeping the payloads together rather than inline in each command means the
//! whole schema can be read in one place, and that the naming rules the
//! envelope documents are applied uniformly: latencies in microseconds with a
//! `_us` suffix, rates per second with `_per_s`, byte counts in bytes with
//! `_bytes`. V2 uses null for explicitly unavailable measurements, including
//! TCP data and daemon interval CPU usage.

use std::time::Duration;

use serde::Serialize;

use crate::{
    diagnose::Evidence,
    memory::{Rates, Verdict},
    network::{NetReport, format_address},
    offcpu::OffCpuStats,
};

// --- net -------------------------------------------------------------------

/// The `net` command's `data` object.
///
/// `tcp_available` reports whether ownership was established, not whether
/// traffic happened: a target with no TCP sockets is available with zero
/// samples. `tcp_reason` explains every unavailable measurement, and the
/// per-signal blocks say which signal is missing when only one is.
#[derive(Debug, Clone, Serialize)]
pub struct NetJson {
    /// Whether TCP ownership attribution was established for this run.
    pub tcp_available: bool,
    /// Why attribution or a measurement is unavailable, when it is.
    pub tcp_reason: Option<String>,
    /// Ordinary RTT samples observed.
    pub samples: Option<u64>,
    /// Retransmissions observed.
    pub retransmissions: Option<u64>,
    /// Records the kernel dropped from a perf buffer.
    pub lost_events: u64,
    /// How attribution went, including what was excluded.
    pub attribution: AttributionJson,
    /// Connection-establishment measurements.
    pub connection_latency: ConnectionLatencyJson,
    /// One row per owned connection, slowest first.
    pub endpoints: Vec<EndpointJson>,
}

/// Counts describing the ownership evidence behind a report.
#[derive(Debug, Clone, Serialize)]
pub struct AttributionJson {
    /// Connections published in `endpoints`.
    pub owned_endpoints: u64,
    /// Connections removed because the target stopped holding the socket.
    pub excluded_endpoints: u64,
    /// Listener addresses bound by more than one socket, so unattributable.
    pub ambiguous_listeners: u64,
    /// Owner records the kernel could not write because the map was full.
    pub owner_drops: u64,
    /// RTT samples dropped because no owner record matched.
    pub unattributed_rtt: u64,
    /// Retransmissions dropped because no owner record matched.
    pub unattributed_retrans: u64,
    /// Endpoints dropped because the target's socket table never corroborated
    /// them.
    pub unverified_endpoints: u64,
    /// RTT samples suppressed by the per-connection sampling interval.
    pub rate_limited_samples: u64,
    /// Client handshakes the kernel started tracking.
    pub handshakes_tracked: u64,
    /// Tracked handshakes that reached `TCP_ESTABLISHED`.
    pub handshakes_established: u64,
    /// Tracked handshakes that closed before establishing.
    pub handshakes_failed: u64,
}

/// Connection-establishment measurements.
#[derive(Debug, Clone, Serialize)]
pub struct ConnectionLatencyJson {
    /// Whether at least one handshake was measured.
    pub available: bool,
    /// Why not, when not.
    pub reason: Option<String>,
    /// Completed handshakes.
    pub connects: u64,
    /// Connects that closed before establishing.
    pub failures: u64,
    /// Median handshake duration.
    pub p50_us: Option<u64>,
    /// 95th percentile handshake duration.
    pub p95_us: Option<u64>,
    /// 99th percentile handshake duration.
    pub p99_us: Option<u64>,
}

/// One connection row.
#[derive(Debug, Clone, Serialize)]
pub struct EndpointJson {
    /// Address family, 2 for IPv4 and 10 for IPv6.
    pub family: u16,
    /// Whether the connection was opened by the target or accepted by it.
    pub role: &'static str,
    /// `created` when the kernel saw the target create the connection,
    /// `seeded` when the target's descriptor table is the evidence.
    pub origin: &'static str,
    /// Whether the target's own socket table corroborated the connection.
    pub ownership_verified: bool,
    /// Source address, printable form.
    pub source: String,
    /// Destination address, printable form.
    pub destination: String,
    /// Source port.
    pub source_port: u16,
    /// Destination port.
    pub destination_port: u16,
    /// RTT samples on this connection.
    pub samples: u64,
    /// Median RTT.
    pub p50_us: u64,
    /// 95th percentile RTT.
    pub p95_us: u64,
    /// 99th percentile RTT.
    pub p99_us: u64,
    /// Retransmissions on this connection.
    pub retransmissions: u64,
    /// Retransmissions per second of collection time.
    pub retransmissions_per_second: f64,
    /// Always null: transmitted segment counts are not collected. The field is
    /// retained in v2, but its former v1 numeric value was invalid.
    pub retrans_ratio: Option<f64>,
    /// Highest congestion window seen, in segments.
    pub max_cwnd: u64,
    /// Highest receive window seen, in bytes.
    pub max_rcv_wnd_bytes: u64,
    /// Handshakes measured on this connection.
    pub connect_samples: u64,
    /// Median handshake duration on this connection.
    pub connect_p50_us: Option<u64>,
    /// 95th percentile handshake duration on this connection.
    pub connect_p95_us: Option<u64>,
    /// Handshakes on this connection that closed before establishing.
    pub connect_failures: u64,
}

/// Builds the `net` document's `data` object.
pub fn network_json(report: &NetReport<'_>) -> NetJson {
    let stats = report.stats;
    let counters = report.counters;
    let available = report.available;
    let mut endpoints = Vec::new();
    for endpoint in stats.slowest_endpoints() {
        let (p50, p95, p99) = endpoint.rtt_percentiles();
        let (connect_p50, connect_p95, _) = endpoint.connect_percentiles();
        let role = if report.is_listener_port(endpoint.key.dport) {
            "server"
        } else {
            "client"
        };
        let created = stats.was_created(&endpoint.key);
        endpoints.push(EndpointJson {
            family: endpoint.key.family,
            role,
            origin: if created { "created" } else { "seeded" },
            ownership_verified: created || report.is_verified(&endpoint.key),
            source: format_address(endpoint.key.family, endpoint.key.saddr),
            destination: format_address(endpoint.key.family, endpoint.key.daddr),
            source_port: endpoint.key.sport,
            destination_port: endpoint.key.dport,
            samples: endpoint.rtts.len() as u64,
            p50_us: u64::from(p50),
            p95_us: u64::from(p95),
            p99_us: u64::from(p99),
            retransmissions: endpoint.retrans,
            retransmissions_per_second: endpoint.retrans_per_second(report.elapsed),
            retrans_ratio: None,
            max_cwnd: u64::from(endpoint.max_cwnd),
            max_rcv_wnd_bytes: u64::from(endpoint.max_rcv_wnd),
            connect_samples: endpoint.connects,
            connect_p50_us: (!endpoint.connect_us.is_empty()).then_some(u64::from(connect_p50)),
            connect_p95_us: (!endpoint.connect_us.is_empty()).then_some(u64::from(connect_p95)),
            connect_failures: endpoint.connect_failures,
        });
    }
    let (p50, p95, p99) = stats.connect_percentiles();
    let measured = report.connect_available;
    NetJson {
        tcp_available: available,
        tcp_reason: report.reason.clone(),
        samples: available.then(|| stats.samples()),
        retransmissions: available.then(|| stats.retrans()),
        lost_events: stats.lost(),
        attribution: AttributionJson {
            owned_endpoints: stats.endpoints_len() as u64,
            excluded_endpoints: report.excluded(),
            ambiguous_listeners: report.ambiguous_listeners() as u64,
            owner_drops: counters.drops,
            unattributed_rtt: counters.unmatched_rtt,
            unattributed_retrans: counters.unmatched_retrans,
            unverified_endpoints: report.unverified,
            rate_limited_samples: counters.rate_limited,
            handshakes_tracked: counters.pending_inserted,
            handshakes_established: counters.pending_established,
            handshakes_failed: counters.pending_failed,
        },
        connection_latency: ConnectionLatencyJson {
            available: measured,
            reason: report.connect_reason.clone(),
            connects: stats.connects(),
            failures: stats.connect_failures(),
            p50_us: measured.then(|| u64::from(p50)),
            p95_us: measured.then(|| u64::from(p95)),
            p99_us: measured.then(|| u64::from(p99)),
        },
        endpoints,
    }
}

// --- daemon -----------------------------------------------------------------

/// The `daemon` command's `data` object.
#[derive(Debug, Clone, Serialize)]
pub struct DaemonJson {
    /// Whether TCP ownership attribution was established for the latest
    /// recorded interval.
    pub tcp_available: bool,
    /// Why it was not, when it was not.
    pub tcp_reason: Option<String>,
    /// How long the recorder ran, in seconds.
    pub ran_s: f64,
    /// The rolling window the ring covers, in seconds.
    pub window_s: f64,
    /// How often an interval was recorded, in seconds.
    pub interval_s: f64,
    /// Entries the ring holds at most.
    pub ring_entries: usize,
    /// Intervals actually recorded.
    pub intervals: u64,
    /// Peak recorder CPU cost, as a percentage of one CPU.
    pub recorder_cpu_pct: f64,
    /// Documented CPU budget, as a percentage of one CPU.
    pub budget_cpu_pct: f64,
    /// True when the peak recorder CPU cost stayed inside the budget.
    pub within_cpu_budget: bool,
    /// Peak recorder resident set, in bytes.
    pub recorder_memory_bytes: u64,
    /// Documented memory budget, in bytes, for the ongoing recording.
    pub budget_recording_bytes: u64,
    /// True when the peak resident set stayed inside the budget.
    pub within_memory_budget: bool,
    /// Where incidents are written.
    pub output_dir: String,
    /// Completed incident bundles, even if later rotation failed.
    pub incidents_written: u64,
    /// Failed bundle writes before completion.
    pub incident_write_failures: u64,
    /// Rotation failures after a bundle completed.
    pub incident_rotation_failures: u64,
    /// Fired intervals skipped because incident writing was disabled.
    pub incidents_skipped: u64,
    /// Whether incident writing is disabled for the remainder of this run.
    pub incident_writes_disabled: bool,
    /// Semantics for newly collected interval values.
    pub measurement_semantics: &'static str,
    /// The most recent intervals, oldest first.
    pub intervals_detail: Vec<serde_json::Value>,
}

/// Builds the `daemon` document's `data` object.
#[allow(clippy::too_many_arguments)]
pub fn daemon_json(
    ring: &crate::daemon::Ring,
    peak_cpu_pct: f64,
    peak_memory_bytes: u64,
    ticks: u64,
    incidents_written: u64,
    incident_write_failures: u64,
    incident_rotation_failures: u64,
    incidents_skipped: u64,
    incident_writes_disabled: bool,
) -> DaemonJson {
    let window = ring.window();
    let entry = ring.entries().next();
    let interval = entry.map_or(Duration::from_secs(1), |e| {
        e.at.checked_sub(Duration::ZERO)
            .map_or(Duration::from_secs(1), |_| {
                ring.entries()
                    .nth(1)
                    .map(|next| next.at.saturating_sub(e.at))
                    .unwrap_or(Duration::from_secs(1))
            })
    });
    DaemonJson {
        tcp_available: entry.is_some_and(|entry| entry.tcp_available),
        tcp_reason: entry.and_then(|entry| entry.tcp_reason.clone()),
        ran_s: ring.entries().last().map_or(0.0, |e| e.at.as_secs_f64()),
        window_s: window.as_secs_f64(),
        interval_s: interval.as_secs_f64(),
        ring_entries: ring.max_entries(),
        intervals: ticks,
        recorder_cpu_pct: peak_cpu_pct,
        budget_cpu_pct: crate::daemon::BUDGET_CPU_PCT,
        within_cpu_budget: peak_cpu_pct <= crate::daemon::BUDGET_CPU_PCT,
        recorder_memory_bytes: peak_memory_bytes,
        budget_recording_bytes: crate::daemon::BUDGET_RECORDING_BYTES,
        within_memory_budget: peak_memory_bytes <= crate::daemon::BUDGET_RECORDING_BYTES,
        output_dir: String::new(),
        incidents_written,
        incident_write_failures,
        incident_rotation_failures,
        incidents_skipped,
        incident_writes_disabled,
        measurement_semantics: crate::daemon::MEASUREMENT_SEMANTICS,
        intervals_detail: ring
            .entries()
            .rev()
            .take(10)
            .map(|entry| entry.to_json())
            .collect(),
    }
}

// --- cpu --------------------------------------------------------------------

/// The `cpu` command's `data` object.
#[derive(Debug, Clone, Serialize)]
pub struct CpuJson {
    /// On-CPU samples collected.
    pub samples: u64,
    /// Records the kernel dropped from the perf buffer.
    pub lost_events: u64,
    /// On-CPU usage as a percentage of one CPU. Absent when /proc could not
    /// be read, which is a different thing from zero.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub usage_pct: Option<f64>,
    /// The hottest stacks, most samples first.
    pub hot_stacks: Vec<HotStackJson>,
}

/// One on-CPU stack.
#[derive(Debug, Clone, Serialize)]
pub struct HotStackJson {
    /// Kernel stack id.
    pub kernel_stack_id: i64,
    /// User stack id, or -1 when no user stack was captured.
    pub user_stack_id: i64,
    /// Samples on this stack.
    pub samples: u64,
    /// This stack's share of all on-CPU samples.
    pub share: f64,
}

/// Builds the `cpu` document's `data` object.
pub fn cpu_json(stats: &crate::cpu::CpuStats) -> CpuJson {
    let total = stats.sample_count() as u64;
    CpuJson {
        samples: total,
        lost_events: stats.lost(),
        usage_pct: stats.cpu_percent(),
        hot_stacks: stats
            .hot_stacks(crate::cpu::HOT_STACKS_JSON)
            .into_iter()
            .map(|((kernel_id, user_id), count)| HotStackJson {
                kernel_stack_id: kernel_id,
                user_stack_id: user_id,
                samples: count as u64,
                share: if total == 0 {
                    0.0
                } else {
                    count as f64 / total as f64
                },
            })
            .collect(),
    }
}

// --- io ---------------------------------------------------------------------

/// The `io` command's `data` object.
#[derive(Debug, Clone, Serialize)]
pub struct IoJson {
    /// Completions observed.
    pub samples: u64,
    /// Records the kernel dropped from the perf buffer.
    pub lost_events: u64,
    /// Target requests that could not be tracked because the in-flight map was full.
    pub unmatched_requests: u64,
    /// The slow threshold this run used.
    pub threshold_us: u64,
    /// Median latency.
    pub p50_us: u64,
    /// 95th percentile latency.
    pub p95_us: u64,
    /// 99th percentile latency.
    pub p99_us: u64,
    /// Longest single latency.
    pub max_us: u64,
    /// Completions over the threshold.
    pub slow_over_threshold: u64,
    /// Bytes the process read over the window, from /proc.
    pub rchar_bytes: u64,
    /// Bytes the process wrote over the window, from /proc.
    pub wchar_bytes: u64,
    /// The slowest completions over the threshold, longest first.
    pub slowest: Vec<SlowIoJson>,
    /// One row per block device.
    pub devices: Vec<IoDeviceJson>,
}

/// One slow completion.
#[derive(Debug, Clone, Serialize)]
pub struct SlowIoJson {
    /// Thread that issued the request.
    pub tid: u32,
    /// Sectors transferred.
    pub sectors: u32,
    /// Latency of this completion.
    pub latency_us: u64,
}

/// One block device's I/O.
#[derive(Debug, Clone, Serialize)]
pub struct IoDeviceJson {
    /// Kernel device id, as the tracepoint reports it.
    pub device: u32,
    /// Completions on this device.
    pub samples: u64,
    /// Read completions.
    pub reads: u64,
    /// Write completions.
    pub writes: u64,
    /// Completions of operations other than read/write, including flushes.
    pub other: u64,
    /// Sectors read.
    pub read_sectors: u64,
    /// Sectors written.
    pub write_sectors: u64,
    /// Sectors transferred by other operations.
    pub other_sectors: u64,
    /// Median latency on this device.
    pub p50_us: u64,
    /// 95th percentile latency on this device.
    pub p95_us: u64,
    /// 99th percentile latency on this device.
    pub p99_us: u64,
    /// Longest single latency on this device.
    pub max_us: u64,
}

/// Builds the `io` document's `data` object.
pub fn io_json(stats: &crate::io::IoStats, rchar_bytes: u64, wchar_bytes: u64) -> IoJson {
    let summary = stats.summary();
    IoJson {
        samples: stats.sample_count() as u64,
        lost_events: stats.lost(),
        unmatched_requests: stats.unmatched(),
        threshold_us: stats.threshold_ns() / 1_000,
        p50_us: summary.map_or(0, |s| s.p50_ns / 1_000),
        p95_us: summary.map_or(0, |s| s.p95_ns / 1_000),
        p99_us: summary.map_or(0, |s| s.p99_ns / 1_000),
        max_us: summary.map_or(0, |s| s.max_ns / 1_000),
        slow_over_threshold: stats.slow_count(),
        rchar_bytes,
        wchar_bytes,
        slowest: stats
            .slow_top()
            .into_iter()
            .map(|(tid, sectors, latency_ns)| SlowIoJson {
                tid,
                sectors,
                latency_us: latency_ns / 1_000,
            })
            .collect(),
        devices: stats
            .devices()
            .into_iter()
            .map(|(device, device_stats)| {
                let mut latencies = device_stats.latencies.clone();
                latencies.sort_unstable();
                let pick = |percentile: usize| -> u64 {
                    if latencies.is_empty() {
                        return 0;
                    }
                    let rank = (latencies.len() * percentile).div_ceil(100);
                    latencies[rank.saturating_sub(1)]
                };
                IoDeviceJson {
                    device,
                    samples: latencies.len() as u64,
                    reads: device_stats.read.count,
                    writes: device_stats.write.count,
                    other: device_stats.other.count,
                    read_sectors: device_stats.read.sectors,
                    write_sectors: device_stats.write.sectors,
                    other_sectors: device_stats.other.sectors,
                    p50_us: pick(50) / 1_000,
                    p95_us: pick(95) / 1_000,
                    p99_us: pick(99) / 1_000,
                    max_us: latencies.last().copied().unwrap_or(0) / 1_000,
                }
            })
            .collect(),
    }
}

// --- off-cpu ----------------------------------------------------------------

/// The `off-cpu` command's `data` object.
#[derive(Debug, Clone, Serialize)]
pub struct OffCpuJson {
    /// Waits observed.
    pub samples: u64,
    /// Records the kernel dropped from the perf buffer.
    pub lost_events: u64,
    /// Pending thread states remaining after collection stopped.
    pub pending_at_stop: u64,
    /// Pending states classified as unknown rather than interruptible/I/O waits.
    pub pending_unknown_at_stop: u64,
    /// Summed off-CPU time.
    pub total_us: u64,
    /// Median wait.
    pub p50_us: u64,
    /// 95th percentile wait.
    pub p95_us: u64,
    /// 99th percentile wait.
    pub p99_us: u64,
    /// One row per wait reason, longest first.
    pub reasons: Vec<ReasonJson>,
    /// The wait stacks, longest total time first.
    pub stacks: Vec<WaitStackJson>,
}

/// One wait reason.
#[derive(Debug, Clone, Serialize)]
pub struct ReasonJson {
    /// Stable reason name, for example "futex / lock".
    pub reason: &'static str,
    /// Waits with this reason.
    pub samples: u64,
    /// Summed wait time in this reason.
    pub total_us: u64,
    /// This reason's share of the total off-CPU time.
    pub share: f64,
}

/// One wait stack, with its blocking frames symbolized where possible.
#[derive(Debug, Clone, Serialize)]
pub struct WaitStackJson {
    /// Kernel stack id, for correlating with a symbolized report.
    pub stack_id: i64,
    /// Waits that ended in this stack.
    pub samples: u64,
    /// Summed wait time in this stack.
    pub total_us: u64,
    /// Longest single wait in this stack.
    pub max_us: u64,
    /// The resolved reason for this stack.
    pub reason: &'static str,
    /// Symbolized blocking frames, innermost first. Empty when the stack could
    /// not be read, which is a different thing from an empty stack.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub frames: Vec<String>,
}

/// Builds the `off-cpu` document's `data` object.
pub fn offcpu_json(stats: &OffCpuStats) -> OffCpuJson {
    let total = stats.total_ns();
    let (p50, p95, p99) = stats.percentiles();
    OffCpuJson {
        samples: stats.sample_count() as u64,
        lost_events: stats.lost(),
        pending_at_stop: stats.pending_at_stop() as u64,
        pending_unknown_at_stop: stats.pending_unknown_at_stop() as u64,
        total_us: total / 1_000,
        p50_us: p50 / 1_000,
        p95_us: p95 / 1_000,
        p99_us: p99 / 1_000,
        reasons: stats
            .reasons_by_total_time()
            .into_iter()
            .map(|(reason, totals)| ReasonJson {
                reason: reason.label(),
                samples: totals.samples as u64,
                total_us: totals.total_ns / 1_000,
                share: if total == 0 {
                    0.0
                } else {
                    totals.total_ns as f64 / total as f64
                },
            })
            .collect(),
        stacks: stats
            .stacks_by_total_time()
            .into_iter()
            .take(crate::offcpu::MAX_STACKS_JSON)
            .map(|(stack_id, stack)| WaitStackJson {
                stack_id,
                samples: stack.samples as u64,
                total_us: stack.total_ns / 1_000,
                max_us: stack.max_ns / 1_000,
                reason: stack.reason.label(),
                frames: Vec::new(),
            })
            .collect(),
    }
}

// --- memory -----------------------------------------------------------------

/// The `memory` command's `data` object.
#[derive(Debug, Clone, Serialize)]
pub struct MemoryJson {
    /// The verdict the measurements support.
    pub verdict: &'static str,
    /// Why the verdict was reached, one entry per crossed threshold.
    pub reasons: Vec<String>,
    /// True when the kernel exposes PSI, which decides whether a zero means
    /// "no pressure" or "cannot tell".
    pub psi_available: bool,
    /// Memory PSI some, in percent. Absent when PSI is unavailable.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub psi_some_pct: Option<f32>,
    /// Memory PSI full, in percent. Absent when PSI is unavailable.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub psi_full_pct: Option<f32>,
    /// User page faults counted in the kernel over the window.
    pub kernel_faults: u64,
    /// Direct reclaim attempts the process entered over the window.
    pub kernel_reclaims: u64,
    /// Minor faults per second, from process accounting.
    pub minor_faults_per_s: f64,
    /// Major faults per second, from process accounting.
    pub major_faults_per_s: f64,
    /// Swap in use at the end of the window.
    pub swap_bytes: u64,
}

/// Builds the `memory` document's `data` object.
pub fn memory_json(
    rates: Option<&Rates>,
    psi_available: bool,
    last: &crate::memory::Sample,
) -> MemoryJson {
    let (verdict, reasons) = match rates {
        Some(rates) => {
            let (verdict, reasons) = Verdict::assess(rates, psi_available);
            (verdict, reasons)
        }
        None => (Verdict::Idle, Vec::new()),
    };
    let rates = rates.cloned().unwrap_or_default();
    MemoryJson {
        verdict: verdict.label(),
        reasons,
        psi_available,
        psi_some_pct: psi_available.then_some(rates.psi_some_pct),
        psi_full_pct: psi_available.then_some(rates.psi_full_pct),
        kernel_faults: last.kernel.faults,
        kernel_reclaims: last.kernel.reclaims,
        minor_faults_per_s: rates.minor_per_s,
        major_faults_per_s: rates.major_per_s,
        swap_bytes: rates.swap_kb.saturating_mul(1024),
    }
}

// --- diagnose ---------------------------------------------------------------

/// The `diagnose` command's `data` object.
#[derive(Debug, Clone, Serialize)]
pub struct DiagnoseJson {
    /// The measurements the ranking was computed from, so a consumer can
    /// recompute or re-weight them without re-running the collection.
    pub measured: serde_json::Value,
    /// Records the kernel dropped, one entry per stream that lost any.
    pub lost_events: Vec<LostJson>,
    /// The ranked causes, highest share first.
    pub causes: Vec<CauseJson>,
}

/// One stream that lost records.
#[derive(Debug, Clone, Serialize)]
pub struct LostJson {
    /// The stream, named as in the human report.
    pub stream: &'static str,
    /// Records dropped.
    pub count: u64,
}

/// One ranked cause.
#[derive(Debug, Clone, Serialize)]
pub struct CauseJson {
    /// Stable cause name.
    pub cause: &'static str,
    /// Share of the measured slowdown attributed to this cause, 0 to 100.
    pub confidence_pct: f32,
    /// The measurements behind the number.
    pub evidence: Vec<String>,
}

/// Builds the `diagnose` document's `data` object.
pub fn diagnose_json(evidence: &Evidence) -> DiagnoseJson {
    let mut measured = serde_json::to_value(evidence).expect("evidence is serializable");
    if !evidence.tcp_available {
        // Unavailable measurements are explicitly null rather than zero, so a
        // consumer can tell "nothing happened" from "nothing was measured".
        for field in [
            "net_samples",
            "retransmissions",
            "retrans_ratio",
            "retrans_per_second",
            "net_rtt_p95_us",
            "net_connect_p95_us",
        ] {
            measured[field] = serde_json::Value::Null;
        }
    }
    DiagnoseJson {
        measured,
        lost_events: evidence
            .lost
            .iter()
            .map(|(stream, count)| LostJson {
                stream,
                count: *count,
            })
            .collect(),
        causes: crate::scoring::score(evidence)
            .into_iter()
            .map(|diagnosis| CauseJson {
                cause: diagnosis.cause,
                confidence_pct: diagnosis.confidence,
                evidence: diagnosis.evidence,
            })
            .collect(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        network::{NetReport, NetStats},
        offcpu::WaitReason,
    };
    use serde_json::Value;

    fn value_of<T: Serialize>(payload: &T) -> Value {
        serde_json::to_value(payload).expect("the payload must serialize")
    }

    #[test]
    fn net_json_of_an_empty_run_is_still_well_formed() {
        let stats = NetStats::default();
        let counters = crate::tcp::TcpCounters::default();
        let value = value_of(&network_json(&NetReport::for_test(
            &stats,
            &counters,
            std::time::Duration::from_secs(1),
        )));
        assert_eq!(value["tcp_available"], false);
        assert!(value["samples"].is_null());
        assert!(value["retransmissions"].is_null());
        assert_eq!(value["endpoints"].as_array().unwrap().len(), 0);
        assert_eq!(value["attribution"]["owned_endpoints"], 0);
        assert_eq!(value["connection_latency"]["available"], false);
    }

    #[test]
    fn offcpu_json_reports_microseconds_and_shares() {
        let mut stats = OffCpuStats::default();
        for wait in [1_000u64, 2_000, 3_000] {
            stats.record_with(
                fast_common::OffCpuEvent {
                    wait_ns: wait,
                    stack_id: 7,
                    tid: 1,
                    reason: fast_common::OFFCPU_REASON_WAIT,
                    _pad: 0,
                    _pad2: 0,
                },
                WaitReason::Futex,
            );
        }
        stats.set_pending_at_stop(2, 1);
        let value = value_of(&offcpu_json(&stats));
        assert_eq!(value["samples"], serde_json::json!(3));
        assert_eq!(value["pending_at_stop"], serde_json::json!(2));
        assert_eq!(value["pending_unknown_at_stop"], serde_json::json!(1));
        assert_eq!(value["total_us"], serde_json::json!(6));
        assert_eq!(
            value["reasons"][0]["reason"],
            serde_json::json!("futex / lock")
        );
        assert_eq!(value["reasons"][0]["total_us"], serde_json::json!(6));
        assert_eq!(value["stacks"][0]["stack_id"], serde_json::json!(7));
    }

    #[test]
    fn memory_json_omits_psi_when_the_kernel_has_none() {
        // An absent PSI must not appear as a zero, which would read as "no
        // pressure" when it means "cannot tell".
        let rates = Rates::default();
        let last = crate::memory::Sample::default();
        let value = value_of(&memory_json(Some(&rates), false, &last));
        assert_eq!(value["psi_available"], serde_json::json!(false));
        assert!(value.get("psi_some_pct").is_none());
        assert!(value.get("psi_full_pct").is_none());
    }

    #[test]
    fn memory_json_carries_psi_when_available() {
        let rates = Rates {
            psi_some_pct: 2.5,
            psi_full_pct: 1.0,
            ..Rates::default()
        };
        let value = value_of(&memory_json(
            Some(&rates),
            true,
            &crate::memory::Sample::default(),
        ));
        assert_eq!(value["psi_some_pct"], serde_json::json!(2.5));
    }

    #[test]
    fn memory_json_converts_swap_to_bytes() {
        let rates = Rates {
            swap_kb: 4,
            ..Rates::default()
        };
        let value = value_of(&memory_json(
            Some(&rates),
            false,
            &crate::memory::Sample::default(),
        ));
        assert_eq!(value["swap_bytes"], serde_json::json!(4096));
    }

    #[test]
    fn diagnose_json_repeats_the_evidence_the_ranking_used() {
        // The whole point of emitting `measured` is that a consumer can check
        // the ranking rather than trust it.
        let evidence = Evidence {
            offcpu_samples: 1_000,
            offcpu_total_us: 100_000,
            offcpu_futex_ratio: 0.9,
            net_samples: 12,
            retransmissions: 2,
            tcp_available: true,
            ..Evidence::default()
        };
        let value = value_of(&diagnose_json(&evidence));
        assert_eq!(value["measured"]["retransmissions"], 2);
        assert_eq!(value["measured"].get("retrans_ratio"), Some(&Value::Null));
        assert_eq!(
            value["measured"]["offcpu_samples"],
            serde_json::json!(1_000)
        );
        assert_eq!(
            value["causes"][0]["cause"],
            serde_json::json!("Lock contention")
        );
        assert!(
            value["causes"][0]["evidence"][0]
                .as_str()
                .unwrap()
                .contains("futex"),
            "the cause must carry its evidence"
        );
    }

    #[test]
    fn diagnose_json_uses_null_for_unavailable_tcp_measurements() {
        let evidence = Evidence {
            net_samples: 123,
            retrans_ratio: Some(0.5),
            tcp_available: false,
            ..Evidence::default()
        };
        let value = value_of(&diagnose_json(&evidence));
        assert_eq!(value["measured"]["tcp_available"], false);
        assert!(value["measured"]["net_samples"].is_null());
        assert!(value["measured"]["retrans_ratio"].is_null());
    }

    #[test]
    fn diagnose_json_lists_lost_streams() {
        let evidence = Evidence {
            lost: vec![("off-cpu", 12)],
            ..Evidence::default()
        };
        let value = value_of(&diagnose_json(&evidence));
        assert_eq!(
            value["lost_events"][0]["stream"],
            serde_json::json!("off-cpu")
        );
        assert_eq!(value["lost_events"][0]["count"], serde_json::json!(12));
    }

    #[test]
    fn cpu_json_omits_usage_when_proc_is_unavailable() {
        // Zero usage and unknown usage are different, so an absent reading is
        // omitted rather than reported as 0.0.
        let value = value_of(&cpu_json(&crate::cpu::CpuStats::default()));
        assert_eq!(value["samples"], serde_json::json!(0));
        assert!(
            value.get("usage_pct").is_none() || value["usage_pct"].is_null(),
            "usage must not be a fabricated zero: {value}"
        );
    }

    #[test]
    fn io_json_carries_per_device_rows_and_unmatched_requests() {
        let mut stats = crate::io::IoStats::new(10_000_000);
        crate::runtime::EventHandler::on_event(
            &mut stats,
            fast_common::IoEvent {
                latency_ns: 0,
                tid: 42,
                dev: 0,
                sectors: 0,
                op: fast_common::IO_OP_UNMATCHED,
            },
        );
        crate::runtime::EventHandler::on_event(
            &mut stats,
            fast_common::IoEvent {
                latency_ns: 1_000,
                tid: 42,
                dev: 0x0801,
                sectors: 0,
                op: 2,
            },
        );
        let value = value_of(&io_json(&stats, 100, 200));
        assert_eq!(value["samples"], serde_json::json!(1));
        assert_eq!(value["unmatched_requests"], serde_json::json!(1));
        assert_eq!(value["devices"][0]["other"], serde_json::json!(1));
        assert_eq!(value["rchar_bytes"], serde_json::json!(100));
        assert_eq!(value["wchar_bytes"], serde_json::json!(200));
        assert_eq!(value["threshold_us"], serde_json::json!(10_000));
        assert_eq!(value["devices"].as_array().unwrap().len(), 1);
    }

    #[test]
    fn every_payload_serializes() {
        // A payload that cannot serialize would make --format json fail at
        // runtime, which is the worst place to find out.
        let stats = NetStats::default();
        let counters = crate::tcp::TcpCounters::default();
        value_of(&network_json(&NetReport::for_test(
            &stats,
            &counters,
            std::time::Duration::from_secs(1),
        )));
        value_of(&offcpu_json(&OffCpuStats::default()));
        value_of(&memory_json(None, false, &crate::memory::Sample::default()));
        value_of(&diagnose_json(&Evidence::default()));
        value_of(&cpu_json(&crate::cpu::CpuStats::default()));
        value_of(&io_json(&crate::io::IoStats::new(10_000_000), 0, 0));
    }
}
