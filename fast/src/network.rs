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
use fast_common::{TcpEvent, MAX_TARGET_TIDS};

use crate::{cli::NetArgs, process};

const POLL_INTERVAL_MS: i32 = 100;
const PERF_PAGE_COUNT: usize = 8;

#[derive(Debug, Default)]
struct NetStats {
    by_endpoint: BTreeMap<(u32, u32, u16, u16), Vec<u32>>,
    retrans: u64,
    lost: u64,
}

impl NetStats {
    fn record(&mut self, ev: TcpEvent) {
        let key = (ev.saddr, ev.daddr, ev.sport, ev.dport);
        self.by_endpoint.entry(key).or_default().push(ev.rtt_us);
        if ev.retrans != 0 {
            self.retrans += 1;
        }
    }
    fn record_lost(&mut self, c: u64) {
        self.lost = self.lost.saturating_add(c);
    }
}

pub fn run(args: NetArgs) -> Result<()> {
    let pid = args.pid;
    let process_name = process::read_name(pid).with_context(|| format!("cannot read process {pid}"))?;
    let initial_tids = process::thread_ids(pid).with_context(|| format!("cannot enumerate threads for {pid}"))?;
    let initial_set: BTreeSet<u32> = initial_tids.iter().copied().collect();

    let mut bpf = Ebpf::load(include_bytes_aligned!(concat!(env!("OUT_DIR"), "/fast-ebpf")))
        .context("failed to load eBPF object; run as root or grant CAP_BPF and CAP_PERFMON")?;
    let _ = attach_tracepoint(&mut bpf, "tcp_retransmit_skb", "tcp_retransmit_skb");

    let target_map = bpf.take_map("TARGET_TIDS").context("TARGET_TIDS missing")?;
    let mut target_tids: AyaHashMap<MapData, u32, u8> = target_map.try_into().context("TARGET_TIDS type")?;
    let pending_map = bpf.take_map("PENDING_IO").context("PENDING_IO missing")?;
    let mut pending_dummy: AyaHashMap<MapData, u32, u64> = pending_map.try_into().context("PENDING_IO type")?;
    let mut known_tids = BTreeSet::new();
    sync_target_tids(&mut target_tids, &mut pending_dummy, &mut known_tids, &initial_set)?;

    let event_map = bpf.take_map("NET_EVENTS").context("NET_EVENTS missing")?;
    let mut events: PerfEventArray<MapData> = event_map.try_into().context("NET_EVENTS type")?;
    let cpus = online_cpus().map_err(|(p, e)| anyhow!("failed to read {p}: {e}"))?;
    let mut buffers = Vec::with_capacity(cpus.len());
    for cpu in cpus {
        buffers.push(events.open(cpu, Some(PERF_PAGE_COUNT)).with_context(|| format!("perf buffer cpu {cpu}"))?);
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
    let mut stats = NetStats::default();

    while started.elapsed() < args.duration {
        if stop.load(Ordering::Relaxed) {
            break;
        }
        if Instant::now() >= next_refresh {
            match refresh_process(pid, &mut target_tids, &mut pending_dummy, &mut known_tids) {
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
            Ok(PerfMessage::Sample(ev)) => stats.record(ev),
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
    println!("PID: {process_name} ({pid})");
    println!("Duration: {}", humantime::format_duration(elapsed));
    if interrupted.load(Ordering::Relaxed) {
        println!("Status: interrupted");
    }
    println!("Retransmissions: {}", stats.retrans);
    println!("Lost events: {}", stats.lost);
    println!();
    println!("Endpoints");
    if stats.by_endpoint.is_empty() {
        println!("No TCP samples collected (no retransmissions or RTT >0). Test with: python3 -m http.server 8000 & curl http://127.0.0.1:8000/");
        println!("Local fixture: start a local server and generate traffic from the target process.");
    } else {
        for ((saddr, daddr, sport, dport), rtts) in &stats.by_endpoint {
            let avg = rtts.iter().map(|v| *v as u64).sum::<u64>() / rtts.len() as u64;
            println!("{}:{} -> {}:{}  samples {} avg RTT {}µs", ip_to_str(*saddr), sport, ip_to_str(*daddr), dport, rtts.len(), avg);
        }
    }
    println!();
    println!("Note: connection vs transfer vs retransmission delays are distinguished by RTT (transfer) and retrans flag.");
    Ok(())
}

fn ip_to_str(ip: u32) -> String {
    format!("{}.{}.{}.{}", ip & 0xFF, (ip >> 8) & 0xFF, (ip >> 16) & 0xFF, (ip >> 24) & 0xFF)
}

fn attach_tracepoint(bpf: &mut Ebpf, program_name: &str, event_name: &str) -> Result<()> {
    let program = bpf.program_mut(program_name).with_context(|| format!("eBPF program {program_name} is missing"))?;
    let program: &mut TracePoint = program.try_into().with_context(|| format!("{program_name} is not a tracepoint"))?;
    let _ = program.load();
    let _ = program.attach("tcp", event_name);
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
    pending: &mut AyaHashMap<MapData, u32, u64>,
    known_tids: &mut BTreeSet<u32>,
    current_tids: &BTreeSet<u32>,
) -> Result<()> {
    use aya::maps::MapError;
    if current_tids.len() > MAX_TARGET_TIDS as usize {
        bail!("too many threads {}", current_tids.len());
    }
    for tid in known_tids.difference(current_tids).copied().collect::<Vec<_>>() {
        target_tids.remove(&tid).with_context(|| format!("remove {tid}"))?;
        match pending.remove(&tid) {
            Ok(()) | Err(MapError::KeyNotFound) => {}
            Err(e) => return Err(e).with_context(|| format!("clear pending {tid}")),
        }
    }
    for tid in current_tids.difference(known_tids).copied().collect::<Vec<_>>() {
        target_tids.insert(tid, 1, 0).with_context(|| format!("add {tid}"))?;
    }
    *known_tids = current_tids.clone();
    Ok(())
}

enum RefreshResult { Alive, Exited }
fn refresh_process(pid: u32, target_tids: &mut AyaHashMap<MapData, u32, u8>, pending: &mut AyaHashMap<MapData, u32, u64>, known_tids: &mut BTreeSet<u32>) -> Result<RefreshResult> {
    if !process::is_alive(pid).with_context(|| format!("inspect {pid}"))? {
        return Ok(RefreshResult::Exited);
    }
    match process::thread_ids(pid) {
        Ok(current) => {
            let set: BTreeSet<u32> = current.iter().copied().collect();
            sync_target_tids(target_tids, pending, known_tids, &set)?;
            Ok(RefreshResult::Alive)
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(RefreshResult::Exited),
        Err(e) => Err(e).with_context(|| format!("refresh {pid}")),
    }
}

#[derive(Debug)]
enum PerfMessage { Sample(TcpEvent), Lost(u64), Error(String) }

fn spawn_perf_reader(mut buffer: PerfEventArrayBuffer<MapData>, stop: Arc<AtomicBool>, sender: Sender<PerfMessage>) -> JoinHandle<()> {
    thread::spawn(move || {
        let mut poll_fd = libc::pollfd { fd: buffer.as_raw_fd(), events: libc::POLLIN, revents: 0 };
        while !stop.load(Ordering::Relaxed) {
            poll_fd.revents = 0;
            let result = unsafe { libc::poll(&mut poll_fd, 1, POLL_INTERVAL_MS) };
            if result < 0 {
                let error = io::Error::last_os_error();
                if error.kind() == io::ErrorKind::Interrupted { continue; }
                let _ = sender.send(PerfMessage::Error(format!("poll failed: {error}")));
                break;
            }
            if result == 0 { continue; }
            if poll_fd.revents & (libc::POLLIN | libc::POLLERR | libc::POLLHUP | libc::POLLNVAL) == 0 { continue; }
            let mut failed = false;
            buffer.for_each(|event| match event {
                PerfEvent::Sample { head, tail } => match decode(head, tail) {
                    Some(s) => { if sender.send(PerfMessage::Sample(s)).is_err() { failed = true; } },
                    None => { let _ = sender.send(PerfMessage::Error(format!("invalid TcpEvent {}", size_of::<TcpEvent>()))); failed = true; },
                },
                PerfEvent::Lost { count } => { if sender.send(PerfMessage::Lost(count)).is_err() { failed = true; } },
            });
            if failed { break; }
        }
    })
}

fn decode(head: &[u8], tail: &[u8]) -> Option<TcpEvent> {
    let sz = size_of::<TcpEvent>();
    if head.len().saturating_add(tail.len()) < sz { return None; }
    let mut bytes = [0u8; size_of::<TcpEvent>()];
    let hl = head.len().min(sz);
    bytes[..hl].copy_from_slice(&head[..hl]);
    if hl < sz { bytes[hl..].copy_from_slice(&tail[..sz - hl]); }
    Some(bytemuck::pod_read_unaligned(&bytes))
}

fn drain_messages(receiver: &Receiver<PerfMessage>, stats: &mut NetStats) {
    for msg in receiver.try_iter() {
        match msg {
            PerfMessage::Sample(s) => stats.record(s),
            PerfMessage::Lost(c) => stats.record_lost(c),
            PerfMessage::Error(_) => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn endpoint_aggregation() {
        let mut s = NetStats::default();
        s.record(TcpEvent { tid: 1, saddr: 0x0100007F, daddr: 0x0100007F, sport: 1234, dport: 80, rtt_us: 100, retrans: 0, _pad: [0;3] });
        s.record(TcpEvent { tid: 1, saddr: 0x0100007F, daddr: 0x0100007F, sport: 1234, dport: 80, rtt_us: 200, retrans: 1, _pad: [0;3] });
        assert_eq!(s.retrans, 1);
        assert_eq!(s.by_endpoint.len(), 1);
    }
}
