use std::{
    collections::{BTreeMap, BTreeSet},
    convert::TryInto,
    fs,
    path::Path,
};

use anyhow::{Context, Result, anyhow, bail};
use aya::{
    Ebpf, include_bytes_aligned,
    maps::{MapData, stack_trace::StackTraceMap},
    programs::perf_event::{
        PerfEvent, PerfEventConfig, PerfEventScope, SamplePolicy, SoftwareEvent,
    },
    util::online_cpus,
};
use blazesym::symbolize::{
    Input, Symbolizer,
    source::{self, Source},
};
use fast_common::{COLLECT_CPU_SAMPLE, CpuSampleEvent};

use crate::{cli::CpuArgs, process, runtime};

/// Samples arrive at the configured frequency per CPU (default 99 Hz), so the
/// default buffer is sufficient.
const PERF_PAGE_COUNT: usize = runtime::DEFAULT_PERF_PAGE_COUNT;

/// Upper bound on frames printed per hot stack.
const MAX_REPORT_FRAMES: usize = 24;

/// Highest hot-stack count shown in the report.
const HOT_STACKS_SHOWN: usize = 5;

/// A stack id pair recorded per sample: kernel and user stack entries in the
/// shared `STACK_TRACES` map (`-1` when that half was not captured).
type StackId = (i64, i64);

#[derive(Debug, Default, Clone, Copy)]
struct CpuUsage {
    utime: u64,
    stime: u64,
}

#[derive(Debug, Default)]
struct CpuStats {
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

    fn hot_stacks(&self, n: usize) -> Vec<(StackId, usize)> {
        let mut v: Vec<_> = self.stack_counts.iter().map(|(k, c)| (*k, *c)).collect();
        // Deterministic order: count descending, then stack id ascending.
        v.sort_by_key(|(id, count)| (std::cmp::Reverse(*count), *id));
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

/// One stack frame prepared for the report: symbolized when possible, raw
/// instruction pointer otherwise.
#[derive(Debug, PartialEq, Eq)]
struct Frame {
    /// `name+0xoff` when the frame resolved to a symbol.
    symbol: Option<String>,
    /// Module (executable or shared object) the symbol came from, if known.
    module: Option<String>,
    /// Raw instruction pointer, always available for display.
    ip: u64,
    /// True for kernel-space frames.
    kernel: bool,
}

impl Frame {
    fn render(&self) -> String {
        let prefix = if self.kernel { "[k] " } else { "" };
        let location = match (&self.symbol, &self.module) {
            (Some(symbol), Some(module)) => format!("{symbol} ({module})"),
            (Some(symbol), None) => symbol.clone(),
            (None, _) => format!("{:#x}", self.ip),
        };
        format!("{prefix}{location}")
    }
}

/// Renders a blazesym result into a [`Frame`], keeping the raw ip as fallback.
fn frame_from_sym(ip: u64, kernel: bool, sym: &blazesym::symbolize::Sym) -> Frame {
    let offset = sym.offset;
    let mut symbol = sym.name.to_string();
    if offset > 0 {
        symbol.push_str(&format!("+{offset:#x}"));
    }
    let module = sym
        .module
        .as_ref()
        .map(|module| {
            Path::new(module)
                .file_name()
                .map(|name| name.to_string_lossy().into_owned())
                .unwrap_or_else(|| module.to_string_lossy().into_owned())
        })
        .filter(|name| !name.is_empty());
    Frame {
        symbol: Some(symbol),
        module,
        ip,
        kernel,
    }
}

/// Best-effort stack symbolizer: kernel frames via the running kernel's
/// kallsyms (through blazesym's kernel source), user frames via the target
/// process' live `/proc/<pid>` state.
struct StackSymbolizer {
    symbolizer: Symbolizer,
    kernel: Source<'static>,
    user: Option<Source<'static>>,
}

impl StackSymbolizer {
    /// Builds the symbolizer for the observed process. `user` is `None` when
    /// the process has already exited; its user stacks then stay unresolved.
    fn new(pid: u32) -> Self {
        let kernel = Source::Kernel(source::Kernel::default());
        let user = if process::is_alive(pid).unwrap_or(false) {
            let mut process = source::Process::new(blazesym::Pid::from(pid));
            // Symbolic /proc/<pid>/maps paths instead of /proc/<pid>/map_files:
            // map_files requires SYS_ADMIN even when CAP_BPF/CAP_PERFMON are
            // held, and symbolic paths suffice for still-running binaries.
            process.map_files = false;
            Some(Source::Process(process))
        } else {
            None
        };
        Self {
            symbolizer: Symbolizer::new(),
            kernel,
            user,
        }
    }

    /// Symbolizes kernel-space instruction pointers, best effort.
    fn kernel_frames(&mut self, ips: &[u64]) -> Vec<Frame> {
        self.frames(ips, true)
    }

    /// Symbolizes user-space instruction pointers, best effort.
    fn user_frames(&mut self, ips: &[u64]) -> Vec<Frame> {
        self.frames(ips, false)
    }

    fn frames(&mut self, ips: &[u64], kernel: bool) -> Vec<Frame> {
        if ips.is_empty() {
            return Vec::new();
        }
        let source = if kernel {
            &self.kernel
        } else {
            self.user.as_ref().unwrap_or(&self.kernel)
        };
        let resolved = if !kernel && self.user.is_none() {
            Vec::new()
        } else {
            self.symbolizer
                .symbolize(source, Input::AbsAddr(ips))
                .ok()
                .unwrap_or_default()
        };
        ips.iter()
            .enumerate()
            .map(|(i, &ip)| match resolved.get(i).and_then(|s| s.as_sym()) {
                Some(sym) => frame_from_sym(ip, kernel, sym),
                None => Frame {
                    symbol: None,
                    module: None,
                    ip,
                    kernel,
                },
            })
            .collect()
    }
}

/// The kernel and user stack trace maps, taken out of the loaded eBPF object
/// after collection. Lookups take no flags: `BPF_F_USER_STACK` only affects
/// the capture side, and kernel/user stacks are separated by map.
struct StackMaps {
    kernel: StackTraceMap<MapData>,
    user: StackTraceMap<MapData>,
}

impl StackMaps {
    fn take(bpf: &mut Ebpf) -> Result<Self> {
        let kernel: StackTraceMap<MapData> = bpf
            .take_map("STACK_TRACES")
            .context("eBPF map STACK_TRACES is missing")?
            .try_into()
            .context("STACK_TRACES has an unexpected map type or layout")?;
        let user: StackTraceMap<MapData> = bpf
            .take_map("STACK_TRACES_USER")
            .context("eBPF map STACK_TRACES_USER is missing")?
            .try_into()
            .context("STACK_TRACES_USER has an unexpected map type or layout")?;
        Ok(Self { kernel, user })
    }

    /// Reads the raw instruction pointers stored under one stack id.
    fn read(&self, stack_id: i64, user: bool) -> Result<Vec<u64>> {
        if stack_id < 0 {
            return Ok(Vec::new());
        }
        let id = u32::try_from(stack_id).context("stack id overflows u32")?;
        let map = if user { &self.user } else { &self.kernel };
        let trace = map
            .get(&id, 0)
            .with_context(|| format!("failed to read stack {stack_id} from the stack trace map"))?;
        Ok(trace.frames().iter().map(|frame| frame.ip).collect())
    }
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
    // sample count scales with frequency times the CPU time they burn. The
    // link ids are kept so the sampler can be stopped the moment collection
    // ends.
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
                    SamplePolicy::Frequency(args.frequency),
                    false,
                )
                .with_context(|| format!("failed to attach cpu_sample to CPU {cpu}"))?,
        );
    }

    let mut target_tids = runtime::take_target_map(&mut bpf)?;
    let mut no_pending = runtime::NoPendingCleanup;
    let mut known_tids = BTreeSet::new();
    let mut stats = CpuStats {
        start_usage: read_proc_cpu_usage(pid).ok(),
        start_system: read_system_ticks().ok(),
        ..CpuStats::default()
    };
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
    // Detach failures are best-effort here; the report is already complete.
    let program: &mut PerfEvent = bpf
        .program_mut("cpu_sample")
        .context("eBPF program cpu_sample is missing")?
        .try_into()
        .context("cpu_sample is not a perf event program")?;
    for link_id in links {
        let _ = program.detach(link_id);
    }

    stats.end_usage = read_proc_cpu_usage(pid).ok();
    stats.end_system = read_system_ticks().ok();

    let stack_maps = StackMaps::take(&mut bpf)?;

    print_cpu_report(
        pid,
        &process_name,
        summary.elapsed,
        &stats,
        summary.interrupted,
        summary.process_exited,
        &stack_maps,
    );
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

    #[test]
    fn renders_symbolized_kernel_frame() {
        let frame = Frame {
            symbol: Some("do_futex+0x41".to_string()),
            module: None,
            ip: 0xffffffff81123456,
            kernel: true,
        };
        assert_eq!(frame.render(), "[k] do_futex+0x41");
    }

    #[test]
    fn renders_user_frame_with_module() {
        let frame = Frame {
            symbol: Some("pthread_cond_wait".to_string()),
            module: Some("libc.so.6".to_string()),
            ip: 0x7f8e2a1b3c4d,
            kernel: false,
        };
        assert_eq!(frame.render(), "pthread_cond_wait (libc.so.6)");
    }

    #[test]
    fn renders_raw_frame_when_unresolved() {
        let frame = Frame {
            symbol: None,
            module: None,
            ip: 0xffffffff81123456,
            kernel: true,
        };
        assert_eq!(frame.render(), "[k] 0xffffffff81123456");

        let user = Frame {
            symbol: None,
            module: None,
            ip: 0x1000,
            kernel: false,
        };
        assert_eq!(user.render(), "0x1000");
    }
}
