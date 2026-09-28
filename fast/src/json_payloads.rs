//! The `data` object each command emits in JSON mode.
//!
//! Keeping the payloads together rather than inline in each command means the
//! whole schema can be read in one place, and that the naming rules the
//! envelope documents are applied uniformly: latencies in microseconds with a
//! `_us` suffix, rates per second with `_per_s`, byte counts in bytes with
//! `_bytes`, and an unknown value omitted rather than serialised as null.

use serde::Serialize;

use crate::{
    diagnose::Evidence,
    memory::{Rates, Verdict},
    network::NetStats,
    offcpu::OffCpuStats,
};

// --- net -------------------------------------------------------------------

/// The `net` command's `data` object.
#[derive(Debug, Clone, Serialize)]
pub struct NetJson {
    /// Ordinary RTT samples observed.
    pub samples: u64,
    /// Retransmissions observed.
    pub retransmissions: u64,
    /// Records the kernel dropped from the perf buffer.
    pub lost_events: u64,
    /// One row per remote endpoint, slowest first.
    pub endpoints: Vec<EndpointJson>,
}

/// One remote endpoint.
#[derive(Debug, Clone, Serialize)]
pub struct EndpointJson {
    /// Address family, 2 for IPv4 and 10 for IPv6.
    pub family: u16,
    /// Source address, printable form.
    pub source: String,
    /// Destination address, printable form.
    pub destination: String,
    /// Source port.
    pub source_port: u16,
    /// Destination port.
    pub destination_port: u16,
    /// RTT samples on this endpoint.
    pub samples: u64,
    /// Median RTT.
    pub p50_us: u64,
    /// 95th percentile RTT.
    pub p95_us: u64,
    /// 99th percentile RTT.
    pub p99_us: u64,
    /// Retransmissions on this endpoint.
    pub retransmissions: u64,
    /// Retransmissions over observed segments, from 0.0 to 1.0.
    pub retrans_ratio: f64,
    /// Highest congestion window seen, in segments.
    pub max_cwnd: u64,
    /// Highest receive window seen, in bytes.
    pub max_rcv_wnd_bytes: u64,
}

/// Builds the `net` document's `data` object.
pub fn network_json(stats: &NetStats) -> NetJson {
    NetJson {
        samples: stats.samples(),
        retransmissions: stats.retrans(),
        lost_events: stats.lost(),
        endpoints: stats
            .slowest_endpoints()
            .into_iter()
            .map(|endpoint| {
                let (p50, p95, p99) = endpoint.rtt_percentiles();
                EndpointJson {
                    family: endpoint.family,
                    source: crate::network::format_address(endpoint.family, endpoint.saddr),
                    destination: crate::network::format_address(endpoint.family, endpoint.daddr),
                    source_port: endpoint.sport,
                    destination_port: endpoint.dport,
                    samples: endpoint.rtts.len() as u64,
                    p50_us: p50 as u64,
                    p95_us: p95 as u64,
                    p99_us: p99 as u64,
                    retransmissions: endpoint.retrans,
                    retrans_ratio: endpoint.retrans_ratio(),
                    max_cwnd: endpoint.max_cwnd as u64,
                    max_rcv_wnd_bytes: endpoint.max_rcv_wnd as u64,
                }
            })
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
    /// Sectors read.
    pub read_sectors: u64,
    /// Sectors written.
    pub write_sectors: u64,
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
                    read_sectors: device_stats.read.sectors,
                    write_sectors: device_stats.write.sectors,
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
    pub measured: Evidence,
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
    DiagnoseJson {
        measured: evidence.clone(),
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
    use crate::offcpu::WaitReason;
    use serde_json::Value;

    fn value_of<T: Serialize>(payload: &T) -> Value {
        serde_json::to_value(payload).expect("the payload must serialize")
    }

    #[test]
    fn net_json_names_every_field_with_a_unit() {
        let mut stats = NetStats::default();
        for rtt in [100u32, 200, 300] {
            crate::runtime::EventHandler::on_event(
                &mut stats,
                fast_common::TcpEvent {
                    tid: 1,
                    family: fast_common::AF_INET,
                    retrans: 0,
                    _pad: 0,
                    sport: 1234,
                    dport: 80,
                    rtt_us: rtt,
                    snd_cwnd: 10,
                    rcv_wnd: 4096,
                    saddr: {
                        let mut a = [0u8; 16];
                        a[0] = 127;
                        a
                    },
                    daddr: {
                        let mut a = [0u8; 16];
                        a[0] = 10;
                        a
                    },
                },
            );
        }
        let value = value_of(&network_json(&stats));
        assert_eq!(value["samples"], serde_json::json!(3));
        let endpoint = &value["endpoints"][0];
        // Latencies are microseconds and windows are named with their unit, so
        // a consumer never has to guess.
        assert!(endpoint.get("p50_us").is_some());
        assert!(endpoint.get("retrans_ratio").is_some());
        assert_eq!(endpoint["max_rcv_wnd_bytes"], serde_json::json!(4096));
    }

    #[test]
    fn net_json_of_an_empty_run_is_still_well_formed() {
        let value = value_of(&network_json(&NetStats::default()));
        assert_eq!(value["samples"], serde_json::json!(0));
        assert_eq!(value["endpoints"].as_array().unwrap().len(), 0);
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
        let value = value_of(&offcpu_json(&stats));
        assert_eq!(value["samples"], serde_json::json!(3));
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
            ..Evidence::default()
        };
        let value = value_of(&diagnose_json(&evidence));
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
    fn io_json_carries_per_device_rows() {
        let stats = crate::io::IoStats::new(10_000_000);
        let value = value_of(&io_json(&stats, 100, 200));
        assert_eq!(value["rchar_bytes"], serde_json::json!(100));
        assert_eq!(value["wchar_bytes"], serde_json::json!(200));
        assert_eq!(value["threshold_us"], serde_json::json!(10_000));
        assert_eq!(value["devices"].as_array().unwrap().len(), 0);
    }

    #[test]
    fn every_payload_serializes() {
        // A payload that cannot serialize would make --format json fail at
        // runtime, which is the worst place to find out.
        value_of(&network_json(&NetStats::default()));
        value_of(&offcpu_json(&OffCpuStats::default()));
        value_of(&memory_json(None, false, &crate::memory::Sample::default()));
        value_of(&diagnose_json(&Evidence::default()));
        value_of(&cpu_json(&crate::cpu::CpuStats::default()));
        value_of(&io_json(&crate::io::IoStats::new(10_000_000), 0, 0));
    }
}
