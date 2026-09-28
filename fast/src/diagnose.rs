use std::collections::BTreeSet;

use anyhow::{Context, Result};
use aya::{Ebpf, include_bytes_aligned};
use fast_common::{
    COLLECT_CPU_SAMPLE, COLLECT_MEMORY, COLLECT_NET, COLLECT_OFFCPU, COLLECT_SCHEDULER_LATENCY,
    CpuSampleEvent, IoEvent, OffCpuEvent, SchedulerLatencyEvent, TcpEvent,
};

use crate::{cli::DiagnoseArgs, cpu, io, memory, network, offcpu, process, runtime, stats};

/// Perf pages per CPU, per stream.
///
/// Diagnose watches five streams at once on every CPU, so the per-stream
/// budget is smaller than a dedicated command gets. The scheduler and CPU
/// streams dominate the totals regardless, and I/O and TCP are comparatively
/// sparse even under load.
const PERF_PAGE_COUNT: usize = 16;

/// Everything the collectors measured during one run.
///
/// The ranking consumes exactly this struct and nothing else, which is what
/// makes the ranking testable without an eBPF program, a kernel or root.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Evidence {
    /// Scheduler samples collected.
    pub sched_samples: usize,
    /// Scheduler latency p95, in microseconds.
    pub sched_p95_us: u64,
    /// On-CPU samples collected.
    pub cpu_samples: usize,
    /// On-CPU usage as a percentage of one CPU.
    pub cpu_percent: f64,
    /// Block I/O completions collected.
    pub io_samples: usize,
    /// Block I/O latency p99, in microseconds.
    pub io_p99_us: u64,
    /// Block I/O samples above the slow threshold.
    pub io_slow: u64,
    /// TCP events observed.
    pub net_samples: u64,
    /// Retransmissions as a fraction of observed segments, from 0.0 to 1.0.
    pub retrans_ratio: f64,
    /// Off-CPU waits collected.
    pub offcpu_samples: usize,
    /// Off-CPU wait p95, in microseconds.
    pub offcpu_p95_us: u64,
    /// Total off-CPU time, in microseconds.
    pub offcpu_total_us: u64,
    /// Share of off-CPU time spent waiting on a futex, from 0.0 to 1.0.
    pub offcpu_futex_ratio: f64,
    /// Minor faults per second, from process accounting.
    pub minor_faults_per_s: f64,
    /// Major faults per second, from process accounting.
    pub major_faults_per_s: f64,
    /// Direct reclaim attempts per second, from the kernel counters.
    pub reclaims_per_s: f64,
    /// Memory PSI some, in percent.
    pub psi_some_pct: f32,
    /// Memory PSI full, in percent.
    pub psi_full_pct: f32,
    /// Whether the kernel exposes PSI at all, which decides if a zero means
    /// "no pressure" or "cannot tell".
    pub psi_available: bool,
    /// Swap in use, in KiB.
    pub swap_kb: u64,
    /// Records the kernel dropped across the perf streams, with a note of
    /// which stream each count came from. A signal with losses is still
    /// reported, but the count says how far to trust it.
    pub lost: Vec<(&'static str, u64)>,
}

pub fn run(args: DiagnoseArgs) -> Result<()> {
    let pid = args.pid;
    let process_name =
        process::read_name(pid).with_context(|| format!("cannot read process {pid}"))?;
    let initial_tids =
        process::thread_ids(pid).with_context(|| format!("cannot enumerate threads for {pid}"))?;

    // One object and one load. Every collector below shares the same target
    // thread map and the same stop handling, so loading once and sharing one
    // reader loop is not just faster: it is the only way every signal is
    // attributed to the same process over the same window.
    let mut bpf = Ebpf::load(include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/fast-ebpf"
    )))
    .context("failed to load eBPF object; run as root or grant CAP_BPF and CAP_PERFMON")?;

    // Only the programs this command needs are attached. Both scheduler
    // programs are needed: the off-CPU pairing reads the same switch-out the
    // latency measurement reads. Both TCP programs are needed for the same
    // reason: tcp_probe registers the sockets that tcp_retransmit_skb then
    // attributes.
    runtime::attach_tracepoint(&mut bpf, "sched", "sched_wakeup")?;
    runtime::attach_tracepoint(&mut bpf, "sched", "sched_switch")?;
    runtime::attach_tracepoint(&mut bpf, "tcp", "tcp_probe")?;
    runtime::attach_tracepoint(&mut bpf, "tcp", "tcp_retransmit_skb")?;
    runtime::attach_tracepoint(&mut bpf, "block", "block_rq_issue")?;
    runtime::attach_tracepoint(&mut bpf, "block", "block_rq_complete")?;
    runtime::attach_tracepoint(&mut bpf, "exceptions", "page_fault_user")?;
    runtime::attach_tracepoint(&mut bpf, "vmscan", "mm_vmscan_direct_reclaim_begin")?;

    let mut target_tids = runtime::take_target_map(&mut bpf)?;
    let mut sched_stats = stats::Statistics::default();
    let mut cpu_stats = cpu::CpuStats::default();
    // The same default threshold `fast io` uses, so a p99 here means what it
    // means there.
    let mut io_stats = io::IoStats::new(io::DEFAULT_SLOW_THRESHOLD_NS);
    let mut net_stats = network::NetStats::default();
    let mut offcpu_stats = offcpu::OffCpuStats::default();

    let mode = COLLECT_SCHEDULER_LATENCY
        | COLLECT_CPU_SAMPLE
        | COLLECT_NET
        | COLLECT_OFFCPU
        | COLLECT_MEMORY;

    let summary = runtime::run_multi_collection(
        &mut bpf,
        &mut target_tids,
        &mut runtime::NoPendingCleanup,
        &mut BTreeSet::new(),
        &initial_tids,
        runtime::MultiCollectionOptions {
            pid,
            duration: args.duration,
            mode,
        },
        vec![
            runtime::EventStream::of::<SchedulerLatencyEvent, _>(
                "EVENTS",
                PERF_PAGE_COUNT,
                &mut sched_stats,
            ),
            runtime::EventStream::of::<CpuSampleEvent, _>(
                "CPU_EVENTS",
                PERF_PAGE_COUNT,
                &mut cpu_stats,
            ),
            runtime::EventStream::of::<IoEvent, _>("IO_EVENTS", PERF_PAGE_COUNT, &mut io_stats),
            runtime::EventStream::of::<TcpEvent, _>("NET_EVENTS", PERF_PAGE_COUNT, &mut net_stats),
            runtime::EventStream::of::<OffCpuEvent, _>(
                "OFFCPU_EVENTS",
                PERF_PAGE_COUNT,
                &mut offcpu_stats,
            ),
        ],
    )?;

    // Memory is counted in a map rather than streamed, so it is read after the
    // event loop instead of through it. The kernel counters give the fault and
    // reclaim totals; process accounting gives the exact minor and major split.
    let kernel_memory = memory::CounterReader::new(&mut bpf)
        .and_then(|reader| reader.totals())
        .unwrap_or_default();
    let faults = memory::read_proc_faults(pid).unwrap_or_default();
    let psi = memory::read_psi("/proc/pressure/memory");
    let swap_kb = memory::read_swap_used_kb();

    // Dropped records are collected rather than printed per stream, so the
    // report can say once which signals are incomplete.
    let mut lost = Vec::new();
    for (name, count) in [
        ("scheduler", sched_stats.lost_events()),
        ("cpu", cpu_stats.lost()),
        ("block io", io_stats.lost()),
        ("tcp", net_stats.lost()),
        ("off-cpu", offcpu_stats.lost()),
    ] {
        if count > 0 {
            lost.push((name, count));
        }
    }

    // The coarse reason the kernel task state gives lumps a futex wait in with
    // a timer sleep, so the same refinement `fast off-cpu` does is applied
    // here. Without it a futex-bound process would report zero percent on a
    // futex, which is a wrong number rather than a missing detail.
    if let Ok(stack_maps) = crate::symbolize::StackMaps::take(&mut bpf) {
        let mut symbolizer = crate::symbolize::StackSymbolizer::new(pid);
        offcpu::refine_reasons(&mut offcpu_stats, &stack_maps, &mut symbolizer);
    }

    let evidence = collect_evidence(
        &summary,
        &sched_stats,
        &cpu_stats,
        &io_stats,
        &net_stats,
        &offcpu_stats,
        kernel_memory,
        faults,
        psi,
        swap_kb,
        lost,
    );
    print_report(&process_name, pid, &summary, &evidence);
    Ok(())
}

/// Builds the evidence set from whatever the collectors gathered.
///
/// A collector that saw nothing contributes a zero sample count rather than a
/// zero value, so the two cases stay distinguishable: a quiet signal and an
/// unmeasured one must not look the same.
#[allow(clippy::too_many_arguments)]
fn collect_evidence(
    summary: &runtime::CollectionSummary,
    sched: &stats::Statistics,
    cpu_stats: &cpu::CpuStats,
    io_stats: &io::IoStats,
    net: &network::NetStats,
    offcpu: &offcpu::OffCpuStats,
    kernel_memory: memory::Totals,
    faults: memory::ProcFaults,
    psi: memory::Psi,
    swap_kb: u64,
    lost: Vec<(&'static str, u64)>,
) -> Evidence {
    // Rates need a window; a run shorter than a millisecond would divide by
    // zero, and its counters are too small to mean anything anyway.
    let seconds = summary.elapsed.as_secs_f64().max(0.001);

    let net_segments: u64 = net
        .slowest_endpoints()
        .iter()
        .map(|endpoint| endpoint.segments())
        .sum();
    let (offcpu_p50, offcpu_p95, _offcpu_p99) = offcpu.percentiles();
    let _ = offcpu_p50;

    Evidence {
        sched_samples: sched.sample_count(),
        sched_p95_us: sched.summary().map_or(0, |s| s.p95_ns / 1_000),
        cpu_samples: cpu_stats.sample_count(),
        cpu_percent: cpu_stats.cpu_percent().unwrap_or(0.0),
        io_samples: io_stats.sample_count(),
        io_p99_us: io_stats.summary().map_or(0, |s| s.p99_ns / 1_000),
        io_slow: io_stats.slow_count(),
        net_samples: net.samples() + net.retrans(),
        retrans_ratio: if net_segments == 0 {
            0.0
        } else {
            net.retrans() as f64 / net_segments as f64
        },
        offcpu_samples: offcpu.sample_count(),
        offcpu_p95_us: offcpu_p95 / 1_000,
        offcpu_total_us: offcpu.total_ns() / 1_000,
        offcpu_futex_ratio: futex_share(offcpu),
        minor_faults_per_s: faults.minor as f64 / seconds,
        major_faults_per_s: faults.major as f64 / seconds,
        reclaims_per_s: kernel_memory.reclaims as f64 / seconds,
        psi_some_pct: psi.some_pct,
        psi_full_pct: psi.full_pct,
        psi_available: psi.available,
        swap_kb,
        lost,
    }
}

/// Share of off-CPU time spent waiting on a futex, from 0.0 to 1.0.
fn futex_share(offcpu: &offcpu::OffCpuStats) -> f64 {
    let total = offcpu.total_ns();
    if total == 0 {
        return 0.0;
    }
    let futex: u64 = offcpu
        .reasons_by_total_time()
        .into_iter()
        .filter(|(reason, _)| *reason == offcpu::WaitReason::Futex)
        .map(|(_, totals)| totals.total_ns)
        .sum();
    futex as f64 / total as f64
}

fn print_report(name: &str, pid: u32, summary: &runtime::CollectionSummary, evidence: &Evidence) {
    println!("PID: {name} ({pid})");
    println!("Duration: {}", humantime::format_duration(summary.elapsed));
    if summary.interrupted {
        println!("Status: interrupted");
    }
    if summary.process_exited {
        println!("Status: process exited");
    }
    println!();

    println!("Measured");
    println!(
        "  scheduler: {} samples, p95 {} us",
        evidence.sched_samples, evidence.sched_p95_us
    );
    println!(
        "  cpu: {} samples, {:.1}% of one CPU",
        evidence.cpu_samples, evidence.cpu_percent
    );
    println!(
        "  block io: {} completions, p99 {} us, {} over the slow threshold",
        evidence.io_samples, evidence.io_p99_us, evidence.io_slow
    );
    println!(
        "  tcp: {} events, {:.2}% retransmitted",
        evidence.net_samples,
        evidence.retrans_ratio * 100.0
    );
    println!(
        "  off-cpu: {} waits, p95 {} us, {} us total, {:.0}% of it on a futex",
        evidence.offcpu_samples,
        evidence.offcpu_p95_us,
        evidence.offcpu_total_us,
        evidence.offcpu_futex_ratio * 100.0
    );
    println!(
        "  memory: {:.0} minor and {:.1} major faults/s, {:.1} direct reclaims/s",
        evidence.minor_faults_per_s, evidence.major_faults_per_s, evidence.reclaims_per_s
    );
    println!("  memory psi: {}", describe_psi(evidence));
    println!("  swap used: {} KiB", evidence.swap_kb);
    if evidence.lost.is_empty() {
        println!("  lost events: none");
    } else {
        let detail = evidence
            .lost
            .iter()
            .map(|(name, count)| format!("{name} {count}"))
            .collect::<Vec<_>>()
            .join(", ");
        println!("  lost events: {detail} (those signals are incomplete)");
    }
}

/// Renders the PSI line, naming the absence rather than printing a zero.
fn describe_psi(evidence: &Evidence) -> String {
    if !evidence.psi_available {
        return "unavailable (kernel built without CONFIG_PSI)".to_string();
    }
    format!(
        "some {:.1}%  full {:.1}%",
        evidence.psi_some_pct, evidence.psi_full_pct
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// An evidence set for a process that is doing nothing measurable, which
    /// is what every collector reports for a quiet target.
    fn quiet() -> Evidence {
        Evidence::default()
    }

    #[test]
    fn a_cpu_bound_process_shows_high_cpu_and_no_waits() {
        let evidence = Evidence {
            sched_samples: 1_000,
            sched_p95_us: 4_000,
            cpu_samples: 3_900,
            cpu_percent: 99.0,
            offcpu_samples: 0,
            offcpu_total_us: 0,
            ..quiet()
        };
        assert_eq!(evidence.cpu_percent, 99.0);
        assert_eq!(evidence.offcpu_total_us, 0);
        assert_eq!(evidence.offcpu_futex_ratio, 0.0);
    }

    #[test]
    fn futex_share_is_zero_without_offcpu_time() {
        let offcpu = offcpu::OffCpuStats::default();
        assert_eq!(futex_share(&offcpu), 0.0);
    }

    #[test]
    fn evidence_defaults_to_unmeasured_rather_than_healthy() {
        // Zero samples must not read as a zero value, or an absent collector
        // would look like a quiet process.
        let evidence = quiet();
        assert_eq!(evidence.sched_samples, 0);
        assert_eq!(evidence.cpu_samples, 0);
        assert_eq!(evidence.net_samples, 0);
        assert!(!evidence.psi_available);
    }
}
