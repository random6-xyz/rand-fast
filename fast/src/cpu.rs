use std::{
    collections::{BTreeMap, BTreeSet},
    convert::TryInto,
    fs,
};

use anyhow::{Context, Result, anyhow, bail};
use aya::{
    Ebpf, include_bytes_aligned,
    programs::perf_event::{
        PerfEvent, PerfEventConfig, PerfEventScope, SamplePolicy, SoftwareEvent,
    },
    util::online_cpus,
};
use fast_common::{COLLECT_CPU_SAMPLE, CpuSampleEvent};

use crate::{
    cli::CpuArgs,
    json::{self, Envelope, Format},
    process, runtime,
    symbolize::{StackMaps, StackSymbolizer},
};

/// Samples arrive at the configured frequency per CPU (default 99 Hz), so the
/// default buffer is sufficient.
const PERF_PAGE_COUNT: usize = runtime::DEFAULT_PERF_PAGE_COUNT;

/// Upper bound on frames printed per hot stack.
const MAX_REPORT_FRAMES: usize = 24;

/// Highest hot-stack count shown in the report.
const HOT_STACKS_SHOWN: usize = 5;

/// How many hot stacks a JSON document carries. The document is meant to be read
/// by a program, so it stays smaller than the human table.
pub const HOT_STACKS_JSON: usize = 10;

/// A stack id pair recorded per sample: kernel and user stack entries in the
/// shared `STACK_TRACES` map (`-1` when that half was not captured).
type StackId = (i64, i64);

#[derive(Debug, Default, Clone, Copy)]
pub struct CpuUsage {
    utime: u64,
    stime: u64,
}

#[derive(Debug, Default)]
pub struct CpuStats {
    total: usize,
    stack_counts: BTreeMap<StackId, usize>,
    per_cpu: BTreeMap<u32, usize>,
    lost: u64,
    start_usage: Option<CpuUsage>,
    end_usage: Option<CpuUsage>,
    start_system: Option<u64>,
    end_system: Option<u64>,
}

impl CpuStats {
    fn record(&mut self, sample: CpuSampleEvent) {
        self.total += 1;
        *self.per_cpu.entry(sample.cpu).or_default() += 1;
        *self
            .stack_counts
            .entry((sample.kernel_stack_id, sample.user_stack_id))
            .or_default() += 1;
    }

    fn record_lost(&mut self, count: u64) {
        self.lost = self.lost.saturating_add(count);
    }

    pub fn hot_stacks(&self, n: usize) -> Vec<(StackId, usize)> {
        let mut v: Vec<_> = self.stack_counts.iter().map(|(k, c)| (*k, *c)).collect();
        // Deterministic order: count descending, then stack id ascending.
        v.sort_by_key(|(id, count)| (std::cmp::Reverse(*count), *id));
        v.truncate(n);
        v
    }

    pub fn cpu_percent(&self) -> Option<f64> {
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

    /// Reads the end-of-window CPU counters.
    ///
    /// The usage percentage is a difference between two readings, so a
    /// collector that is only primed at the start would report zero no matter
    /// how busy the process was. Every caller has to call this once the
    /// collection is over.
    pub fn finalize(&mut self, pid: u32) {
        self.end_usage = read_proc_cpu_usage(pid).ok();
        self.end_system = read_system_ticks().ok();
    }

    /// Number of on-CPU samples observed.
    pub fn sample_count(&self) -> usize {
        self.total
    }

    /// Records the kernel's dropped-event count.
    pub fn lost(&self) -> u64 {
        self.lost
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

/// CPU time a process has consumed, in clock ticks.
///
/// Read from `/proc/<pid>/stat`, which is the same place the usage percentage
/// comes from, so a caller that needs both gets two readings of one number
/// rather than two different definitions of it.
pub fn read_process_ticks(pid: u32) -> Result<u64> {
    let stat = fs::read_to_string(format!("/proc/{pid}/stat"))
        .with_context(|| format!("read /proc/{pid}/stat"))?;
    let end = stat
        .rfind(')')
        .with_context(|| format!("malformed /proc/{pid}/stat"))?;
    let fields: Vec<&str> = stat[end + 2..].split_whitespace().collect();
    let utime: u64 = fields
        .get(11)
        .and_then(|v| v.parse().ok())
        .context("missing utime in /proc/<pid>/stat")?;
    let stime: u64 = fields
        .get(12)
        .and_then(|v| v.parse().ok())
        .context("missing stime in /proc/<pid>/stat")?;
    Ok(utime + stime)
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

/// Detaches the on-CPU sampler.
///
/// Failures are best-effort: by the time this runs the report is already
/// complete, and a handle the kernel has dropped needs no detaching.
pub fn detach_sampler(bpf: &mut Ebpf, links: Vec<aya::programs::perf_event::PerfEventLinkId>) {
    if links.is_empty() {
        return;
    }
    let Some(program) = bpf.program_mut("cpu_sample") else {
        return;
    };
    let Ok(program) = program.try_into() else {
        return;
    };
    let program: &mut PerfEvent = program;
    for link_id in links {
        let _ = program.detach(link_id);
    }
}

/// Loads and attaches the on-CPU sampler, returning the link handles and a
/// primed collector.
///
/// The handles must be kept alive for the duration of the collection: dropping
/// them detaches the sampler, so a caller that discards them would stop
/// sampling immediately. The collector is primed with the process' current CPU
/// time and the system total, which is what makes the usage percentage a
/// measurement rather than a count of samples.
pub fn attach_cpu_sampler(
    bpf: &mut Ebpf,
    pid: u32,
    frequency: u64,
) -> Result<(Vec<aya::programs::perf_event::PerfEventLinkId>, CpuStats)> {
    let program = bpf
        .program_mut("cpu_sample")
        .context("eBPF program cpu_sample is missing")?;
    let program: &mut PerfEvent = program
        .try_into()
        .context("cpu_sample is not a perf event program")?;
    program
        .load()
        .context("failed to load eBPF program cpu_sample")?;

    // Attach a cpu-clock sampler to every online CPU. The BPF program filters
    // by TARGET_TIDS, so only the target's threads contribute samples, and the
    // sample count scales with frequency times the CPU time they burn.
    let config = PerfEventConfig::Software(SoftwareEvent::CpuClock);
    let mut links = Vec::new();
    for cpu in online_cpus()
        .map_err(|(path, error)| anyhow!("failed to read online CPU list from {path}: {error}"))?
    {
        links.push(
            program
                .attach(
                    config,
                    PerfEventScope::AllProcessesOneCpu { cpu },
                    SamplePolicy::Frequency(frequency),
                    false,
                )
                .with_context(|| format!("failed to attach cpu_sample to CPU {cpu}"))?,
        );
    }

    let stats = CpuStats {
        start_usage: read_proc_cpu_usage(pid).ok(),
        start_system: read_system_ticks().ok(),
        ..CpuStats::default()
    };
    Ok((links, stats))
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

    // Attaching the sampler and priming the usage counters is shared with
    // `fast diagnose`, which observes CPU in the same run as everything else.
    let (links, mut stats) = attach_cpu_sampler(&mut bpf, pid, args.frequency)?;

    let mut target_tids = runtime::take_target_map(&mut bpf)?;
    let mut no_pending = runtime::NoPendingCleanup;
    let mut known_tids = BTreeSet::new();
    let summary = runtime::run_collection(
        &mut bpf,
        &mut target_tids,
        &mut no_pending,
        &mut known_tids,
        &initial_tids,
        &mut stats,
        runtime::CollectionOptions {
            pid,
            duration: args.duration,
            events_map: "CPU_EVENTS",
            perf_page_count: PERF_PAGE_COUNT,
            mode: COLLECT_CPU_SAMPLE,
        },
    )?;

    // Stop the sampler before reading the stack maps and building the report:
    // the perf readers are gone at this point, so continued sampling would
    // only churn the stack maps and burn CPU while the report is built.
    detach_sampler(&mut bpf, links);

    stats.finalize(pid);

    let stack_maps = StackMaps::take(&mut bpf)?;

    if args.format.format == Format::Json {
        json::emit(
            args.format.format,
            &Envelope::new(
                "cpu",
                pid,
                Some(process_name),
                summary.elapsed,
                summary.interrupted,
                summary.process_exited,
                crate::json_payloads::cpu_json(&stats),
            ),
        );
    } else {
        print_cpu_report(
            pid,
            &process_name,
            summary.elapsed,
            &stats,
            summary.interrupted,
            summary.process_exited,
            &stack_maps,
        );
    }
    Ok(())
}

fn print_hot_stacks(pid: u32, stats: &CpuStats, stack_maps: &StackMaps) {
    let mut symbolizer = StackSymbolizer::new(pid);
    println!();
    println!("On-CPU samples (hot stacks)");
    let hot = stats.hot_stacks(HOT_STACKS_SHOWN);
    if hot.is_empty() {
        println!("No stack samples collected.");
        return;
    }
    for (stack_id, count) in hot {
        let percent = if stats.total > 0 {
            count as f64 / stats.total as f64 * 100.0
        } else {
            0.0
        };
        println!("stack {stack_id:?}  samples {count} ({percent:.1}%)");
        let (kernel_id, user_id) = stack_id;
        let mut frames = Vec::new();
        match stack_maps.read(kernel_id, false) {
            Ok(ips) => frames.extend(symbolizer.kernel_frames(&ips)),
            Err(error) => println!("  (kernel stack unavailable: {error})"),
        }
        match stack_maps.read(user_id, true) {
            Ok(ips) => frames.extend(symbolizer.user_frames(&ips)),
            Err(error) => println!("  (user stack unavailable: {error})"),
        }
        if frames.is_empty() {
            println!("  (no stack captured)");
        }
        for (depth, frame) in frames.iter().enumerate() {
            if depth == MAX_REPORT_FRAMES {
                println!("  … {} more frames", frames.len() - MAX_REPORT_FRAMES);
                break;
            }
            println!("  {depth:<2} {}", frame.render());
        }
    }
}

fn print_cpu_report(
    pid: u32,
    name: &str,
    duration: std::time::Duration,
    stats: &CpuStats,
    interrupted: bool,
    exited: bool,
    stack_maps: &StackMaps,
) {
    use humantime::format_duration;
    println!("PID: {name} ({pid})");
    println!("Duration: {}", format_duration(duration));
    if interrupted {
        println!("Status: interrupted");
    } else if exited {
        println!("Status: process exited");
    }
    println!("Samples: {}", stats.total);
    println!("Lost: {}", stats.lost);
    if let Some(p) = stats.cpu_percent() {
        println!(
            "CPU usage: {:.1}% (over {:.1}s wall, {} ticks total)",
            p,
            duration.as_secs_f64(),
            stats.end_system.unwrap_or(0) - stats.start_system.unwrap_or(0)
        );
    } else {
        println!("CPU usage: unavailable (could not read /proc)");
    }

    print_hot_stacks(pid, stats, stack_maps);

    println!();
    println!("Per-CPU samples");
    if stats.per_cpu.is_empty() {
        println!("No per-CPU samples.");
    } else {
        for (cpu, cnt) in &stats.per_cpu {
            println!("cpu {cpu:<4} samples {cnt}");
        }
    }
    println!();
    println!("Correlation");
    if let Some(p) = stats.cpu_percent() {
        if p > 80.0 && stats.total > 0 {
            println!(
                "CPU saturation likely contributes to scheduler latency (CPU {:.1}% with {} samples)",
                p, stats.total
            );
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

    fn sample(tid: u32, cpu: u32, kstack: i64, ustack: i64) -> CpuSampleEvent {
        CpuSampleEvent {
            tid,
            cpu,
            kernel_stack_id: kstack,
            user_stack_id: ustack,
            _pad: 0,
            _pad2: 0,
        }
    }

    #[test]
    fn tracks_hot_stacks() {
        let mut stats = CpuStats::default();
        stats.record(sample(1, 0, 10, -1));
        stats.record(sample(1, 0, 10, -1));
        stats.record(sample(1, 0, 11, 20));
        let hot = stats.hot_stacks(1);
        assert_eq!(hot[0], ((10, -1), 2));
        assert_eq!(stats.total, 3);
    }

    #[test]
    fn sorts_hot_stacks_deterministically() {
        let mut stats = CpuStats::default();
        stats.record(sample(1, 0, 5, -1));
        stats.record(sample(1, 0, 3, -1));
        stats.record(sample(1, 0, 5, -1));
        let hot = stats.hot_stacks(2);
        assert_eq!(hot[0], ((5, -1), 2));
        assert_eq!(hot[1], ((3, -1), 1));
    }

    #[test]
    fn cpu_percent_calc() {
        let stats = CpuStats {
            start_usage: Some(CpuUsage {
                utime: 100,
                stime: 0,
            }),
            end_usage: Some(CpuUsage {
                utime: 200,
                stime: 0,
            }),
            start_system: Some(1000),
            end_system: Some(2000),
            ..CpuStats::default()
        };
        let p = stats.cpu_percent().unwrap();
        assert!((p - 10.0).abs() < 0.1);
    }
}
