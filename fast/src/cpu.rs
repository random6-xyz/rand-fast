use std::{
    collections::{BTreeMap, BTreeSet},
    convert::TryInto,
    fs,
    io,
    mem::size_of,
    os::fd::AsRawFd,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
        mpsc::{self, Receiver, Sender},
    },
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};

use anyhow::{Context, Result, anyhow, bail};
use aya::{
    Ebpf, include_bytes_aligned,
    maps::{
        HashMap as AyaHashMap, MapData, PerfEventArray,
        perf::{PerfEvent, PerfEventArrayBuffer},
    },
    programs::TracePoint,
    util::online_cpus,
};
use fast_common::{CpuSampleEvent, MAX_TARGET_TIDS};

use crate::{cli::CpuArgs, process};

const POLL_INTERVAL_MS: i32 = 100;
const PERF_PAGE_COUNT: usize = 8;
const THREAD_REFRESH_INTERVAL: Duration = Duration::from_millis(100);

#[derive(Debug, Default, Clone)]
struct CpuUsage {
    utime: u64,
    stime: u64,
}

#[derive(Debug, Default)]
struct CpuStats {
    samples: Vec<CpuSampleEvent>,
    stack_counts: BTreeMap<i64, usize>,
    lost: u64,
    start_usage: Option<CpuUsage>,
    end_usage: Option<CpuUsage>,
    start_system: Option<u64>,
    end_system: Option<u64>,
}

impl CpuStats {
    fn record(&mut self, sample: CpuSampleEvent) {
        // Count hot stacks by kernel stack id
        if sample.kernel_stack_id >= 0 {
            *self.stack_counts.entry(sample.kernel_stack_id).or_default() += 1;
        }
        self.samples.push(sample);
    }

    fn record_lost(&mut self, count: u64) {
        self.lost = self.lost.saturating_add(count);
    }

    fn hot_stacks(&self, n: usize) -> Vec<(i64, usize)> {
        let mut v: Vec<_> = self.stack_counts.iter().map(|(k, c)| (*k, *c)).collect();
        v.sort_by(|a, b| b.1.cmp(&a.1));
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
    attach_tracepoint(&mut bpf, "sched_wakeup", "sched_wakeup")?;
    attach_tracepoint(&mut bpf, "sched_switch", "sched_switch")?;

    let target_map = bpf
        .take_map("TARGET_TIDS")
        .context("eBPF map TARGET_TIDS is missing")?;
    let mut target_tids: AyaHashMap<MapData, u32, u8> = target_map
        .try_into()
        .context("TARGET_TIDS has an unexpected map type or layout")?;

    // Keep PENDING_WAKEUPS for scheduler correlation, even if CPU mode doesn't strictly need it
    let pending_map = bpf.take_map("PENDING_WAKEUPS").context("PENDING_WAKEUPS missing")?;
    let mut pending_wakeups: AyaHashMap<MapData, u32, [u64; 2]> = pending_map
        .try_into()
        .context("PENDING_WAKEUPS layout")?;

    let mut known_tids = BTreeSet::new();
    sync_target_tids(&mut target_tids, &mut pending_wakeups, &mut known_tids, &initial_tids)?;

    let event_map = bpf.take_map("CPU_EVENTS").context("CPU_EVENTS missing")?;
    let mut events: PerfEventArray<MapData> = event_map.try_into().context("CPU_EVENTS layout")?;

    let cpus = online_cpus()
        .map_err(|(path, error)| anyhow!("failed to read online CPUs from {path}: {error}"))?;
    if cpus.is_empty() {
        bail!("no online CPUs were found");
    }
    let mut buffers = Vec::with_capacity(cpus.len());
    for cpu in cpus {
        let buffer = events
            .open(cpu, Some(PERF_PAGE_COUNT))
            .with_context(|| format!("failed to open perf buffer for CPU {cpu}"))?;
        buffers.push(buffer);
    }
    drop(events);

    let stop = Arc::new(AtomicBool::new(false));
    let interrupted = Arc::new(AtomicBool::new(false));
    install_signal_handler(&stop, &interrupted)?;

    let (sender, receiver) = mpsc::channel();
    let readers = buffers
        .into_iter()
        .map(|buffer| spawn_perf_reader(buffer, Arc::clone(&stop), sender.clone()))
        .collect::<Vec<_>>();
    drop(sender);

    let started = Instant::now();
    let mut next_refresh = started + THREAD_REFRESH_INTERVAL;
    let mut stats = CpuStats::default();
    stats.start_usage = read_proc_cpu_usage(pid).ok();
    stats.start_system = read_system_ticks().ok();

    let mut process_exited = false;
    let mut fatal_error: Option<anyhow::Error> = None;

    while started.elapsed() < args.duration {
        if stop.load(Ordering::Relaxed) {
            break;
        }
        let remaining = args.duration.saturating_sub(started.elapsed());
        let wait = remaining.min(Duration::from_millis(50));
        match receiver.recv_timeout(wait) {
            Ok(PerfMessage::Sample(s)) => stats.record(s),
            Ok(PerfMessage::Lost(c)) => stats.record_lost(c),
            Ok(PerfMessage::Error(e)) => {
                fatal_error = Some(anyhow!(e));
                stop.store(true, Ordering::Relaxed);
                break;
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {}
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                if !stop.load(Ordering::Relaxed) {
                    fatal_error = Some(anyhow!("all perf readers stopped unexpectedly"));
                    stop.store(true, Ordering::Relaxed);
                }
                break;
            }
        }
        if Instant::now() >= next_refresh {
            match refresh_process(pid, &mut target_tids, &mut pending_wakeups, &mut known_tids) {
                Ok(RefreshResult::Alive) => {}
                Ok(RefreshResult::Exited) => {
                    process_exited = true;
                    stop.store(true, Ordering::Relaxed);
                    break;
                }
                Err(error) => {
                    fatal_error = Some(error);
                    stop.store(true, Ordering::Relaxed);
                    break;
                }
            }
            next_refresh = Instant::now() + THREAD_REFRESH_INTERVAL;
        }
    }

    stats.end_usage = read_proc_cpu_usage(pid).ok();
    stats.end_system = read_system_ticks().ok();

    stop.store(true, Ordering::Relaxed);
    let mut panicked = false;
    for r in readers {
        if r.join().is_err() {
            panicked = true;
        }
    }
    if panicked && fatal_error.is_none() {
        fatal_error = Some(anyhow!("a perf reader panicked"));
    }
    drain_messages(&receiver, &mut stats);
    if let Some(e) = fatal_error {
        return Err(e);
    }

    print_cpu_report(pid, &process_name, started.elapsed(), &stats, interrupted.load(Ordering::Relaxed), process_exited);
    Ok(())
}

fn attach_tracepoint(bpf: &mut Ebpf, program_name: &str, event_name: &str) -> Result<()> {
    let program = bpf
        .program_mut(program_name)
        .with_context(|| format!("eBPF program {program_name} is missing"))?;
    let program: &mut TracePoint = program
        .try_into()
        .with_context(|| format!("eBPF program {program_name} is not a tracepoint"))?;
    program
        .load()
        .with_context(|| format!("failed to load eBPF program {program_name}"))?;
    program
        .attach("sched", event_name)
        .with_context(|| format!("failed to attach to sched/{event_name}"))?;
    Ok(())
}

fn install_signal_handler(stop: &Arc<AtomicBool>, interrupted: &Arc<AtomicBool>) -> Result<()> {
    let stop = Arc::clone(stop);
    let interrupted = Arc::clone(interrupted);
    ctrlc::set_handler(move || {
        interrupted.store(true, Ordering::Relaxed);
        stop.store(true, Ordering::Relaxed);
    })
    .context("failed to install Ctrl-C handler")
}

fn sync_target_tids(
    target_tids: &mut AyaHashMap<MapData, u32, u8>,
    pending_wakeups: &mut AyaHashMap<MapData, u32, [u64; 2]>,
    known_tids: &mut BTreeSet<u32>,
    current_tids: &BTreeSet<u32>,
) -> Result<()> {
    use aya::maps::MapError;
    if current_tids.len() > MAX_TARGET_TIDS as usize {
        bail!(
            "process has {} threads, but the target map supports at most {}",
            current_tids.len(),
            MAX_TARGET_TIDS
        );
    }
    let removed = known_tids.difference(current_tids).copied().collect::<Vec<_>>();
    for tid in removed {
        target_tids
            .remove(&tid)
            .with_context(|| format!("failed to remove thread {tid}"))?;
        match pending_wakeups.remove(&tid) {
            Ok(()) | Err(MapError::KeyNotFound) => {}
            Err(e) => return Err(e).with_context(|| format!("failed to clear pending for {tid}")),
        }
    }
    let added = current_tids.difference(known_tids).copied().collect::<Vec<_>>();
    for tid in added {
        target_tids
            .insert(tid, 1, 0)
            .with_context(|| format!("failed to add thread {tid}"))?;
    }
    *known_tids = current_tids.clone();
    Ok(())
}

enum RefreshResult { Alive, Exited }

fn refresh_process(
    pid: u32,
    target_tids: &mut AyaHashMap<MapData, u32, u8>,
    pending_wakeups: &mut AyaHashMap<MapData, u32, [u64; 2]>,
    known_tids: &mut BTreeSet<u32>,
) -> Result<RefreshResult> {
    if !process::is_alive(pid).with_context(|| format!("failed to inspect process {pid}"))? {
        return Ok(RefreshResult::Exited);
    }
    match process::thread_ids(pid) {
        Ok(current) => {
            sync_target_tids(target_tids, pending_wakeups, known_tids, &current)?;
            Ok(RefreshResult::Alive)
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(RefreshResult::Exited),
        Err(e) => Err(e).with_context(|| format!("failed to refresh threads for {pid}")),
    }
}

enum PerfMessage {
    Sample(CpuSampleEvent),
    Lost(u64),
    Error(String),
}

fn spawn_perf_reader(
    mut buffer: PerfEventArrayBuffer<MapData>,
    stop: Arc<AtomicBool>,
    sender: Sender<PerfMessage>,
) -> JoinHandle<()> {
    thread::spawn(move || {
        let mut poll_fd = libc::pollfd {
            fd: buffer.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        while !stop.load(Ordering::Relaxed) {
            poll_fd.revents = 0;
            let result = unsafe { libc::poll(&mut poll_fd, 1, POLL_INTERVAL_MS) };
            if result < 0 {
                let error = io::Error::last_os_error();
                if error.kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                let _ = sender.send(PerfMessage::Error(format!("poll failed: {error}")));
                break;
            }
            if result == 0 {
                continue;
            }
            if poll_fd.revents & (libc::POLLIN | libc::POLLERR | libc::POLLHUP | libc::POLLNVAL) == 0 {
                continue;
            }
            let mut failed = false;
            buffer.for_each(|event| match event {
                PerfEvent::Sample { head, tail } => match decode_cpu(head, tail) {
                    Some(s) => {
                        if sender.send(PerfMessage::Sample(s)).is_err() {
                            failed = true;
                        }
                    }
                    None => {
                        let _ = sender.send(PerfMessage::Error(format!(
                            "invalid CPU event payload: expected {} bytes",
                            size_of::<CpuSampleEvent>()
                        )));
                        failed = true;
                    }
                },
                PerfEvent::Lost { count } => {
                    if sender.send(PerfMessage::Lost(count)).is_err() {
                        failed = true;
                    }
                }
            });
            if failed {
                break;
            }
        }
    })
}

fn decode_cpu(head: &[u8], tail: &[u8]) -> Option<CpuSampleEvent> {
    let sz = size_of::<CpuSampleEvent>();
    if head.len().saturating_add(tail.len()) < sz {
        return None;
    }
    let mut bytes = [0u8; size_of::<CpuSampleEvent>()];
    let hl = head.len().min(sz);
    bytes[..hl].copy_from_slice(&head[..hl]);
    if hl < sz {
        bytes[hl..].copy_from_slice(&tail[..sz - hl]);
    }
    Some(bytemuck::pod_read_unaligned(&bytes))
}

fn drain_messages(receiver: &Receiver<PerfMessage>, stats: &mut CpuStats) {
    for msg in receiver.try_iter() {
        match msg {
            PerfMessage::Sample(s) => stats.record(s),
            PerfMessage::Lost(c) => stats.record_lost(c),
            PerfMessage::Error(_) => {}
        }
    }
}

fn print_cpu_report(pid: u32, name: &str, duration: Duration, stats: &CpuStats, interrupted: bool, exited: bool) {
    use humantime::format_duration;
    println!("PID: {name} ({pid})");
    println!("Duration: {}", format_duration(duration));
    if interrupted {
        println!("Status: interrupted");
    } else if exited {
        println!("Status: process exited");
    }
    println!("Samples: {}", stats.samples.len());
    println!("Lost: {}", stats.lost);
    if let Some(p) = stats.cpu_percent() {
        println!("CPU usage: {:.1}% (over {:.1}s wall, {} ticks total)", p, duration.as_secs_f64(), stats.end_system.unwrap_or(0) - stats.start_system.unwrap_or(0));
    } else {
        println!("CPU usage: unavailable (could not read /proc)");
    }
    println!();
    println!("On-CPU samples (hot stacks)");
    let hot = stats.hot_stacks(5);
    if hot.is_empty() {
        println!("No stack samples collected.");
    } else {
        for (id, cnt) in hot {
            println!("stack {id:<6} samples {cnt}");
        }
    }
    println!();
    println!("Per-CPU samples");
    let mut per_cpu: BTreeMap<u32, usize> = BTreeMap::new();
    for s in &stats.samples {
        *per_cpu.entry(s.cpu).or_default() += 1;
    }
    if per_cpu.is_empty() {
        println!("No per-CPU samples.");
    } else {
        for (cpu, cnt) in per_cpu {
            println!("cpu {cpu:<4} samples {cnt}");
        }
    }
    println!();
    println!("Correlation");
    if let Some(p) = stats.cpu_percent() {
        if p > 80.0 && !stats.samples.is_empty() {
            println!("CPU saturation likely contributes to scheduler latency (CPU {:.1}% with {} samples)", p, stats.samples.len());
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

    fn sample(tid: u32, cpu: u32, kstack: i64) -> CpuSampleEvent {
        CpuSampleEvent { tid, cpu, kernel_stack_id: kstack, user_stack_id: -1, _pad: 0, _pad2: 0 }
    }

    #[test]
    fn decodes_cpu_event() {
        let s = sample(42, 2, 5);
        let bytes = bytemuck::bytes_of(&s);
        assert_eq!(decode_cpu(bytes, &[]).unwrap().tid, 42);
    }

    #[test]
    fn tracks_hot_stacks() {
        let mut stats = CpuStats::default();
        stats.record(sample(1, 0, 10));
        stats.record(sample(1, 0, 10));
        stats.record(sample(1, 0, 11));
        let hot = stats.hot_stacks(1);
        assert_eq!(hot[0], (10, 2));
    }

    #[test]
    fn cpu_percent_calc() {
        let mut stats = CpuStats::default();
        stats.start_usage = Some(CpuUsage { utime: 100, stime: 0 });
        stats.end_usage = Some(CpuUsage { utime: 200, stime: 0 });
        stats.start_system = Some(1000);
        stats.end_system = Some(2000);
        let p = stats.cpu_percent().unwrap();
        assert!((p - 10.0).abs() < 0.1);
    }
}
