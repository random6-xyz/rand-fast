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
use fast_common::{IoEvent, MAX_TARGET_TIDS};

use crate::{cli::IoArgs, process};

const POLL_INTERVAL_MS: i32 = 100;
const PERF_PAGE_COUNT: usize = 8;

#[derive(Debug, Default)]
struct IoStats {
    latencies: Vec<u64>,
    by_device: BTreeMap<u32, Vec<u64>>,
    slow: u64,
    lost: u64,
}

impl IoStats {
    fn record(&mut self, event: IoEvent, threshold_ns: u64) {
        self.latencies.push(event.latency_ns);
        self.by_device.entry(event.dev).or_default().push(event.latency_ns);
        if event.latency_ns > threshold_ns {
            self.slow += 1;
        }
    }
    fn record_lost(&mut self, count: u64) {
        self.lost = self.lost.saturating_add(count);
    }
    fn summary(&self) -> Option<Summary> {
        summary(&self.latencies)
    }
    fn device_summaries(&self) -> Vec<(u32, Summary)> {
        let mut out = Vec::new();
        for (dev, vals) in &self.by_device {
            if let Some(s) = summary(vals) {
                out.push((*dev, s));
            }
        }
        out.sort_by_key(|(d, _)| *d);
        out
    }
}

#[derive(Debug, Clone, Copy)]
struct Summary {
    count: usize,
    p50_ns: u64,
    p95_ns: u64,
    p99_ns: u64,
    max_ns: u64,
}

fn summary(values: &[u64]) -> Option<Summary> {
    if values.is_empty() {
        return None;
    }
    let mut sorted = values.to_vec();
    sorted.sort_unstable();
    let percentile = |p: f64| {
        let idx = ((p / 100.0) * sorted.len() as f64).ceil() as usize;
        let idx = idx.clamp(1, sorted.len()) - 1;
        sorted[idx]
    };
    Some(Summary {
        count: sorted.len(),
        p50_ns: percentile(50.0),
        p95_ns: percentile(95.0),
        p99_ns: percentile(99.0),
        max_ns: *sorted.last().unwrap(),
    })
}

fn format_ns(ns: u64) -> String {
    if ns < 1_000 {
        return format!("{ns} ns");
    }
    let us = ns.saturating_add(500) / 1_000;
    if us < 1_000 {
        return format!("{us} µs");
    }
    if ns < 1_000_000_000 {
        return format!("{:.1} ms", ns as f64 / 1_000_000.0);
    }
    format!("{:.2} s", ns as f64 / 1_000_000_000.0)
}

fn read_proc_io(pid: u32) -> Result<(u64, u64)> {
    let content = fs::read_to_string(format!("/proc/{pid}/io"))
        .with_context(|| format!("failed to read /proc/{pid}/io"))?;
    let mut rchar = 0u64;
    let mut wchar = 0u64;
    for line in content.lines() {
        if let Some(v) = line.strip_prefix("rchar:") {
            rchar = v.trim().parse().unwrap_or(0);
        } else if let Some(v) = line.strip_prefix("wchar:") {
            wchar = v.trim().parse().unwrap_or(0);
        }
    }
    Ok((rchar, wchar))
}

pub fn run(args: IoArgs) -> Result<()> {
    let pid = args.pid;
    let threshold = args.threshold;
    let process_name = process::read_name(pid)
        .with_context(|| format!("cannot read process {pid}"))?;
    let initial_tids = process::thread_ids(pid)
        .with_context(|| format!("cannot enumerate threads for {pid}"))?;
    let initial_set: BTreeSet<u32> = initial_tids.iter().copied().collect();

    let mut bpf = Ebpf::load(include_bytes_aligned!(concat!(env!("OUT_DIR"), "/fast-ebpf")))
        .context("failed to load eBPF object; run as root or grant CAP_BPF and CAP_PERFMON")?;
    let _ = attach_tracepoint(&mut bpf, "block_rq_issue", "block_rq_issue");
    let _ = attach_tracepoint(&mut bpf, "block_rq_complete", "block_rq_complete");

    let target_map = bpf.take_map("TARGET_TIDS").context("TARGET_TIDS missing")?;
    let mut target_tids: AyaHashMap<MapData, u32, u8> = target_map.try_into().context("TARGET_TIDS type")?;
    let pending_map = bpf.take_map("PENDING_IO").context("PENDING_IO missing")?;
    let mut pending_io: AyaHashMap<MapData, u32, u64> = pending_map.try_into().context("PENDING_IO type")?;

    let mut known_tids = BTreeSet::new();
    sync_target_tids(&mut target_tids, &mut pending_io, &mut known_tids, &initial_set)?;

    let event_map = bpf.take_map("IO_EVENTS").context("IO_EVENTS missing")?;
    let mut events: PerfEventArray<MapData> = event_map.try_into().context("IO_EVENTS type")?;
    let cpus = online_cpus().map_err(|(p, e)| anyhow!("failed to read {p}: {e}"))?;
    let mut buffers = Vec::with_capacity(cpus.len());
    for cpu in cpus {
        let buf = events.open(cpu, Some(PERF_PAGE_COUNT)).with_context(|| format!("perf buffer cpu {cpu}"))?;
        buffers.push(buf);
    }
    drop(events);

    let stop = Arc::new(AtomicBool::new(false));
    let interrupted = Arc::new(AtomicBool::new(false));
    install_signal_handler(&stop, &interrupted)?;

    let (sender, receiver) = mpsc::channel();
    let readers = buffers.into_iter().map(|b| spawn_perf_reader(b, Arc::clone(&stop), sender.clone())).collect::<Vec<_>>();
    drop(sender);

    let started = Instant::now();
    let mut next_refresh = started + Duration::from_millis(100);
    let mut stats = IoStats::default();
    let (rchar_start, wchar_start) = read_proc_io(pid).unwrap_or((0, 0));

    while started.elapsed() < args.duration {
        if stop.load(Ordering::Relaxed) {
            break;
        }
        if Instant::now() >= next_refresh {
            match refresh_process(pid, &mut target_tids, &mut pending_io, &mut known_tids) {
                Ok(RefreshResult::Alive) => {}
                Ok(RefreshResult::Exited) => {
                    stop.store(true, Ordering::Relaxed);
                    break;
                }
                Err(e) => {
                    stop.store(true, Ordering::Relaxed);
                    bail!("{e:#}");
                }
            }
            next_refresh = Instant::now() + Duration::from_millis(100);
        }
        let remaining = args.duration.saturating_sub(started.elapsed());
        let wait = remaining.min(Duration::from_millis(50));
        match receiver.recv_timeout(wait) {
            Ok(PerfMessage::Sample(ev)) => stats.record(ev, threshold.as_nanos() as u64),
            Ok(PerfMessage::Lost(c)) => stats.record_lost(c),
            Ok(PerfMessage::Error(e)) => {
                stop.store(true, Ordering::Relaxed);
                bail!("{e}");
            }
            Err(mpsc::RecvTimeoutError::Timeout) => continue,
            Err(mpsc::RecvTimeoutError::Disconnected) => break,
        }
    }
    stop.store(true, Ordering::Relaxed);
    for h in readers {
        let _ = h.join();
    }
    drain_messages(&receiver, &mut stats);

    let elapsed = started.elapsed().min(args.duration);
    let (rchar_end, wchar_end) = read_proc_io(pid).unwrap_or((rchar_start, wchar_start));
    let rchar_delta = rchar_end.saturating_sub(rchar_start);
    let wchar_delta = wchar_end.saturating_sub(wchar_start);

    println!("PID: {process_name} ({pid})");
    println!("Duration: {}", humantime::format_duration(elapsed));
    if interrupted.load(Ordering::Relaxed) {
        println!("Status: interrupted");
    }
    println!("Samples: {}", stats.latencies.len());
    println!("Lost events: {}", stats.lost);
    println!("Slow > {}: {}", humantime::format_duration(threshold), stats.slow);
    println!("rchar: {rchar_delta} bytes, wchar: {wchar_delta} bytes");
    println!();
    println!("I/O latency");
    match stats.summary() {
        Some(s) => {
            println!("{:<8}{:>10}", "p50", format_ns(s.p50_ns));
            println!("{:<8}{:>10}", "p95", format_ns(s.p95_ns));
            println!("{:<8}{:>10}", "p99", format_ns(s.p99_ns));
            println!("{:<8}{:>10}", "max", format_ns(s.max_ns));
        }
        None => println!("No I/O samples were collected."),
    }
    println!();
    println!("Per-device latency");
    let dev_summaries = stats.device_summaries();
    if dev_summaries.is_empty() {
        println!("No per-device samples were collected.");
    } else {
        for (dev, s) in dev_summaries {
            let major = dev >> 20;
            let minor = dev & 0xFFFFF;
            println!("dev {major}:{minor} samples {:<4} p50 {:>10} p95 {:>10} p99 {:>10} max {:>10}", s.count, format_ns(s.p50_ns), format_ns(s.p95_ns), format_ns(s.p99_ns), format_ns(s.max_ns));
        }
    }
    println!();
    println!("Slow-device threshold: {} (configurable via --threshold)", humantime::format_duration(threshold));
    Ok(())
}

fn attach_tracepoint(bpf: &mut Ebpf, program_name: &str, event_name: &str) -> Result<()> {
    let program = bpf.program_mut(program_name).with_context(|| format!("eBPF program {program_name} is missing"))?;
    let program: &mut TracePoint = program.try_into().with_context(|| format!("{program_name} is not a tracepoint"))?;
    let _ = program.load();
    let _ = program.attach("block", event_name);
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
    pending_io: &mut AyaHashMap<MapData, u32, u64>,
    known_tids: &mut BTreeSet<u32>,
    current_tids: &BTreeSet<u32>,
) -> Result<()> {
    use aya::maps::MapError;
    if current_tids.len() > MAX_TARGET_TIDS as usize {
        bail!("process has {} threads, but the target map supports at most {}", current_tids.len(), MAX_TARGET_TIDS);
    }
    let removed = known_tids.difference(current_tids).copied().collect::<Vec<_>>();
    for tid in removed {
        target_tids.remove(&tid).with_context(|| format!("failed to remove thread {tid}"))?;
        match pending_io.remove(&tid) {
            Ok(()) | Err(MapError::KeyNotFound) => {}
            Err(e) => return Err(e).with_context(|| format!("failed to clear pending for {tid}")),
        }
    }
    let added = current_tids.difference(known_tids).copied().collect::<Vec<_>>();
    for tid in added {
        target_tids.insert(tid, 1, 0).with_context(|| format!("failed to add thread {tid}"))?;
    }
    *known_tids = current_tids.clone();
    Ok(())
}

enum RefreshResult { Alive, Exited }

fn refresh_process(
    pid: u32,
    target_tids: &mut AyaHashMap<MapData, u32, u8>,
    pending_io: &mut AyaHashMap<MapData, u32, u64>,
    known_tids: &mut BTreeSet<u32>,
) -> Result<RefreshResult> {
    if !process::is_alive(pid).with_context(|| format!("failed to inspect process {pid}"))? {
        return Ok(RefreshResult::Exited);
    }
    match process::thread_ids(pid) {
        Ok(current) => {
            let set: BTreeSet<u32> = current.iter().copied().collect();
            sync_target_tids(target_tids, pending_io, known_tids, &set)?;
            Ok(RefreshResult::Alive)
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(RefreshResult::Exited),
        Err(e) => Err(e).with_context(|| format!("failed to refresh threads for {pid}")),
    }
}

#[derive(Debug)]
enum PerfMessage {
    Sample(IoEvent),
    Lost(u64),
    Error(String),
}

fn spawn_perf_reader(
    mut buffer: PerfEventArrayBuffer<MapData>,
    stop: Arc<AtomicBool>,
    sender: Sender<PerfMessage>,
) -> JoinHandle<()> {
    thread::spawn(move || {
        let mut poll_fd = libc::pollfd { fd: buffer.as_raw_fd(), events: libc::POLLIN, revents: 0 };
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
                PerfEvent::Sample { head, tail } => match decode_io(head, tail) {
                    Some(s) => {
                        if sender.send(PerfMessage::Sample(s)).is_err() {
                            failed = true;
                        }
                    }
                    None => {
                        let _ = sender.send(PerfMessage::Error(format!("invalid I/O event payload: expected {} bytes", size_of::<IoEvent>())));
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

fn decode_io(head: &[u8], tail: &[u8]) -> Option<IoEvent> {
    let sz = size_of::<IoEvent>();
    if head.len().saturating_add(tail.len()) < sz {
        return None;
    }
    let mut bytes = [0u8; size_of::<IoEvent>()];
    let hl = head.len().min(sz);
    bytes[..hl].copy_from_slice(&head[..hl]);
    if hl < sz {
        bytes[hl..].copy_from_slice(&tail[..sz - hl]);
    }
    Some(bytemuck::pod_read_unaligned(&bytes))
}

fn drain_messages(receiver: &Receiver<PerfMessage>, stats: &mut IoStats) {
    for msg in receiver.try_iter() {
        match msg {
            PerfMessage::Sample(s) => stats.record(s, 10_000_000),
            PerfMessage::Lost(c) => stats.record_lost(c),
            PerfMessage::Error(_) => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn counts_slow_and_device() {
        let mut s = IoStats::default();
        s.record(IoEvent { latency_ns: 5_000_000, tid: 1, dev: 0x0801, sectors: 8, op: 0 }, 1_000_000);
        s.record(IoEvent { latency_ns: 5_000_000, tid: 1, dev: 0x0801, sectors: 8, op: 0 }, 10_000_000);
        assert_eq!(s.slow, 1);
        assert_eq!(s.by_device.len(), 1);
        assert_eq!(s.latencies.len(), 2);
    }
    #[test]
    fn summary_computed() {
        let mut s = IoStats::default();
        for i in 1..=10 {
            s.record(IoEvent { latency_ns: i * 1_000_000, tid: 1, dev: 0, sectors: 1, op: 0 }, 100_000_000);
        }
        let sum = s.summary().unwrap();
        assert!(sum.p50_ns > 0);
        assert!(sum.max_ns == 10_000_000);
    }
}
