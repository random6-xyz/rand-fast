use std::{
    collections::{BTreeMap, BTreeSet},
    convert::TryInto,
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
use fast_common::{OffCpuEvent, MAX_TARGET_TIDS};

use crate::{cli::OffCpuArgs, process};

const POLL_INTERVAL_MS: i32 = 100;
const PERF_PAGE_COUNT: usize = 8;

#[derive(Debug, Default)]
struct OffCpuStats {
    waits: Vec<u64>,
    by_stack: BTreeMap<i64, Vec<u64>>,
    lost: u64,
}

impl OffCpuStats {
    fn record(&mut self, ev: OffCpuEvent) {
        self.waits.push(ev.wait_ns);
        self.by_stack.entry(ev.stack_id).or_default().push(ev.wait_ns);
    }
    fn record_lost(&mut self, c: u64) {
        self.lost = self.lost.saturating_add(c);
    }
    fn summary(&self) -> Option<Summary> {
        summary(&self.waits)
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
    if values.is_empty() { return None; }
    let mut s = values.to_vec();
    s.sort_unstable();
    let pct = |p: f64| {
        let idx = ((p/100.0)*s.len() as f64).ceil() as usize;
        let idx = idx.clamp(1, s.len())-1;
        s[idx]
    };
    Some(Summary { count: s.len(), p50_ns: pct(50.0), p95_ns: pct(95.0), p99_ns: pct(99.0), max_ns: *s.last().unwrap() })
}
fn format_ns(ns: u64) -> String {
    if ns < 1_000 { return format!("{ns} ns"); }
    let us = ns.saturating_add(500)/1_000;
    if us < 1_000 { return format!("{us} µs"); }
    if ns < 1_000_000_000 { return format!("{:.1} ms", ns as f64/1_000_000.0); }
    format!("{:.2} s", ns as f64/1_000_000_000.0)
}

pub fn run(args: OffCpuArgs) -> Result<()> {
    let pid = args.pid;
    let process_name = process::read_name(pid).with_context(|| format!("cannot read {pid}"))?;
    let initial_tids = process::thread_ids(pid).with_context(|| format!("enumerate {pid}"))?;
    let initial_set: BTreeSet<u32> = initial_tids.iter().copied().collect();

    let mut bpf = Ebpf::load(include_bytes_aligned!(concat!(env!("OUT_DIR"), "/fast-ebpf")))
        .context("failed to load eBPF object")?;
    let _ = attach_tracepoint(&mut bpf, "sched_stat_sleep", "sched_stat_sleep");
    let _ = attach_tracepoint(&mut bpf, "sched_wakeup", "sched_wakeup");

    let target_map = bpf.take_map("TARGET_TIDS").context("TARGET_TIDS missing")?;
    let mut target_tids: AyaHashMap<MapData, u32, u8> = target_map.try_into().context("TARGET_TIDS type")?;
    let pending_map = bpf.take_map("OFFCPU_START").context("OFFCPU_START missing")?;
    let mut pending: AyaHashMap<MapData, u32, u64> = pending_map.try_into().context("OFFCPU_START type")?;
    let mut known = BTreeSet::new();
    sync_target_tids(&mut target_tids, &mut pending, &mut known, &initial_set)?;

    let event_map = bpf.take_map("OFFCPU_EVENTS").context("OFFCPU_EVENTS missing")?;
    let mut events: PerfEventArray<MapData> = event_map.try_into().context("OFFCPU_EVENTS type")?;
    let cpus = online_cpus().map_err(|(p,e)| anyhow!("{p}: {e}"))?;
    let mut buffers = Vec::with_capacity(cpus.len());
    for cpu in cpus { buffers.push(events.open(cpu, Some(PERF_PAGE_COUNT)).with_context(|| format!("cpu {cpu}"))?); }
    drop(events);

    let stop = Arc::new(AtomicBool::new(false));
    let interrupted = Arc::new(AtomicBool::new(false));
    install_signal_handler(&stop, &interrupted)?;
    let (sender, receiver) = mpsc::channel();
    let readers = buffers.into_iter().map(|b| spawn_reader(b, Arc::clone(&stop), sender.clone())).collect::<Vec<_>>();
    drop(sender);

    let started = Instant::now();
    let mut next_refresh = started + Duration::from_millis(100);
    let mut stats = OffCpuStats::default();

    while started.elapsed() < args.duration {
        if stop.load(Ordering::Relaxed) { break; }
        if Instant::now() >= next_refresh {
            match refresh_process(pid, &mut target_tids, &mut pending, &mut known) {
                Ok(RefreshResult::Alive) => {},
                Ok(RefreshResult::Exited) => { stop.store(true, Ordering::Relaxed); break; },
                Err(e) => { stop.store(true, Ordering::Relaxed); bail!("{e:#}"); },
            }
            next_refresh = Instant::now() + Duration::from_millis(100);
        }
        let remaining = args.duration.saturating_sub(started.elapsed());
        let wait = remaining.min(Duration::from_millis(50));
        match receiver.recv_timeout(wait) {
            Ok(PerfMessage::Sample(ev)) => stats.record(ev),
            Ok(PerfMessage::Lost(c)) => stats.record_lost(c),
            Ok(PerfMessage::Error(e)) => { stop.store(true, Ordering::Relaxed); bail!("{e}"); },
            Err(mpsc::RecvTimeoutError::Timeout) => continue,
            Err(mpsc::RecvTimeoutError::Disconnected) => break,
        }
    }
    stop.store(true, Ordering::Relaxed);
    for h in readers { let _ = h.join(); }
    drain_messages(&receiver, &mut stats);

    let elapsed = started.elapsed().min(args.duration);
    println!("PID: {process_name} ({pid})");
    println!("Duration: {}", humantime::format_duration(elapsed));
    if interrupted.load(Ordering::Relaxed) { println!("Status: interrupted"); }
    println!("Samples: {}", stats.waits.len());
    println!("Lost: {}", stats.lost);
    println!();
    println!("Off-CPU wait");
    match stats.summary() {
        Some(s) => {
            println!("{:<8}{:>10}", "p50", format_ns(s.p50_ns));
            println!("{:<8}{:>10}", "p95", format_ns(s.p95_ns));
            println!("{:<8}{:>10}", "p99", format_ns(s.p99_ns));
            println!("{:<8}{:>10}", "max", format_ns(s.max_ns));
        }
        None => println!("No off-CPU samples collected. Test with futex contention: two threads contending on a mutex."),
    }
    println!();
    println!("Hot wait stacks");
    let mut hot: Vec<(i64, usize)> = stats.by_stack.iter().map(|(k,v)| (*k, v.len())).collect();
    hot.sort_by(|a,b| b.1.cmp(&a.1));
    hot.truncate(5);
    if hot.is_empty() { println!("No stacks."); } else { for (id, cnt) in hot { println!("stack {id:<6} samples {cnt}"); } }
    Ok(())
}

fn attach_tracepoint(bpf: &mut Ebpf, prog: &str, event: &str) -> Result<()> {
    let p = bpf.program_mut(prog).with_context(|| format!("{prog} missing"))?;
    let p: &mut TracePoint = p.try_into().with_context(|| format!("{prog} not tracepoint"))?;
    let _ = p.load();
    let _ = p.attach("sched", event);
    Ok(())
}
fn install_signal_handler(stop: &Arc<AtomicBool>, interrupted: &Arc<AtomicBool>) -> Result<()> {
    let s = Arc::clone(stop); let i = Arc::clone(interrupted);
    ctrlc::set_handler(move || { i.store(true, Ordering::Relaxed); s.store(true, Ordering::Relaxed); }).context("Ctrl-C handler")
}
fn sync_target_tids(target_tids: &mut AyaHashMap<MapData, u32, u8>, pending: &mut AyaHashMap<MapData, u32, u64>, known: &mut BTreeSet<u32>, current: &BTreeSet<u32>) -> Result<()> {
    use aya::maps::MapError;
    if current.len() > MAX_TARGET_TIDS as usize { bail!("too many threads"); }
    for tid in known.difference(current).copied().collect::<Vec<_>>() {
        target_tids.remove(&tid).with_context(|| format!("remove {tid}"))?;
        match pending.remove(&tid) { Ok(()) | Err(MapError::KeyNotFound) => {}, Err(e) => return Err(e).with_context(|| format!("clear {tid}")) }
    }
    for tid in current.difference(known).copied().collect::<Vec<_>>() { target_tids.insert(tid, 1, 0).with_context(|| format!("add {tid}"))?; }
    *known = current.clone(); Ok(())
}
enum RefreshResult { Alive, Exited }
fn refresh_process(pid: u32, target_tids: &mut AyaHashMap<MapData, u32, u8>, pending: &mut AyaHashMap<MapData, u32, u64>, known: &mut BTreeSet<u32>) -> Result<RefreshResult> {
    if !process::is_alive(pid).with_context(|| format!("inspect {pid}"))? { return Ok(RefreshResult::Exited); }
    match process::thread_ids(pid) {
        Ok(current) => { let set: BTreeSet<u32> = current.iter().copied().collect(); sync_target_tids(target_tids, pending, known, &set)?; Ok(RefreshResult::Alive) }
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(RefreshResult::Exited),
        Err(e) => Err(e).with_context(|| format!("refresh {pid}")),
    }
}
#[derive(Debug)]
enum PerfMessage { Sample(OffCpuEvent), Lost(u64), Error(String) }
fn spawn_reader(mut buffer: PerfEventArrayBuffer<MapData>, stop: Arc<AtomicBool>, sender: Sender<PerfMessage>) -> JoinHandle<()> {
    thread::spawn(move || {
        let mut poll_fd = libc::pollfd { fd: buffer.as_raw_fd(), events: libc::POLLIN, revents: 0 };
        while !stop.load(Ordering::Relaxed) {
            poll_fd.revents = 0;
            let r = unsafe { libc::poll(&mut poll_fd, 1, POLL_INTERVAL_MS) };
            if r < 0 { let e = io::Error::last_os_error(); if e.kind()==io::ErrorKind::Interrupted { continue; } let _=sender.send(PerfMessage::Error(format!("poll {e}"))); break; }
            if r==0 { continue; }
            if poll_fd.revents & (libc::POLLIN|libc::POLLERR|libc::POLLHUP|libc::POLLNVAL)==0 { continue; }
            let mut failed=false;
            buffer.for_each(|ev| match ev {
                PerfEvent::Sample{head,tail} => match decode(head,tail) { Some(s)=>{ if sender.send(PerfMessage::Sample(s)).is_err(){ failed=true; } }, None=>{ let _=sender.send(PerfMessage::Error(format!("invalid {}", size_of::<OffCpuEvent>()))); failed=true; } },
                PerfEvent::Lost{count} => { if sender.send(PerfMessage::Lost(count)).is_err(){ failed=true; } },
            });
            if failed { break; }
        }
    })
}
fn decode(head: &[u8], tail: &[u8]) -> Option<OffCpuEvent> {
    let sz = size_of::<OffCpuEvent>();
    if head.len().saturating_add(tail.len()) < sz { return None; }
    let mut b = [0u8; size_of::<OffCpuEvent>()];
    let hl = head.len().min(sz);
    b[..hl].copy_from_slice(&head[..hl]);
    if hl<sz { b[hl..].copy_from_slice(&tail[..sz-hl]); }
    Some(bytemuck::pod_read_unaligned(&b))
}
fn drain_messages(receiver: &Receiver<PerfMessage>, stats: &mut OffCpuStats) {
    for msg in receiver.try_iter() {
        match msg { PerfMessage::Sample(s)=> stats.record(s), PerfMessage::Lost(c)=> stats.record_lost(c), PerfMessage::Error(_)=>{} }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn wait_stack() {
        let mut s = OffCpuStats::default();
        s.record(OffCpuEvent { wait_ns: 10_000, stack_id: 5, tid: 1, reason: 0, _pad: 0, _pad2: 0 });
        s.record(OffCpuEvent { wait_ns: 20_000, stack_id: 5, tid: 1, reason: 0, _pad: 0, _pad2: 0 });
        assert_eq!(s.waits.len(), 2);
        assert_eq!(s.by_stack.len(), 1);
    }
}
