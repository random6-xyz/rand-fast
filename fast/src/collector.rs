use std::{
    collections::BTreeSet,
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
        HashMap as AyaHashMap, MapData, MapError, PerfEventArray,
        perf::{PerfEvent, PerfEventArrayBuffer},
    },
    programs::TracePoint,
    util::online_cpus,
};
use fast_common::{MAX_TARGET_TIDS, SchedulerLatencyEvent};

use crate::{cli::SchedArgs, output, process, stats::Statistics};

const THREAD_REFRESH_INTERVAL: Duration = Duration::from_millis(100);
const POLL_INTERVAL_MS: i32 = 100;
const PERF_PAGE_COUNT: usize = 8;

pub fn run(args: SchedArgs) -> Result<()> {
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
    let pending_map = bpf
        .take_map("PENDING_WAKEUPS")
        .context("eBPF map PENDING_WAKEUPS is missing")?;
    let mut pending_wakeups: AyaHashMap<MapData, u32, [u64; 2]> = pending_map
        .try_into()
        .context("PENDING_WAKEUPS has an unexpected map type or layout")?;

    let mut known_tids = BTreeSet::new();
    sync_target_tids(
        &mut target_tids,
        &mut pending_wakeups,
        &mut known_tids,
        &initial_tids,
    )?;

    let event_map = bpf
        .take_map("EVENTS")
        .context("eBPF map EVENTS is missing")?;
    let mut events: PerfEventArray<MapData> = event_map
        .try_into()
        .context("EVENTS has an unexpected map type or layout")?;
    let cpus = online_cpus()
        .map_err(|(path, error)| anyhow!("failed to read online CPU list from {path}: {error}"))?;
    if cpus.is_empty() {
        bail!("no online CPUs were found");
    }

    let mut buffers = Vec::with_capacity(cpus.len());
    for cpu in cpus {
        let buffer = events
            .open(cpu, Some(PERF_PAGE_COUNT))
            .with_context(|| format!("failed to open the perf buffer for CPU {cpu}"))?;
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
    let mut stats = Statistics::default();
    let mut process_exited = false;
    let mut fatal_error = None;

    while started.elapsed() < args.duration {
        if stop.load(Ordering::Relaxed) {
            break;
        }

        let remaining = args.duration.saturating_sub(started.elapsed());
        let wait = remaining.min(Duration::from_millis(50));
        match receiver.recv_timeout(wait) {
            Ok(PerfMessage::Sample(event)) => stats.record(event),
            Ok(PerfMessage::Lost(count)) => stats.record_lost(count),
            Ok(PerfMessage::Error(error)) => {
                fatal_error = Some(anyhow!(error));
                stop.store(true, Ordering::Relaxed);
                break;
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {}
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                if !stop.load(Ordering::Relaxed) {
                    fatal_error = Some(anyhow!("all perf event readers stopped unexpectedly"));
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

    stop.store(true, Ordering::Relaxed);
    let mut reader_panicked = false;
    for reader in readers {
        if reader.join().is_err() {
            reader_panicked = true;
        }
    }
    if reader_panicked && fatal_error.is_none() {
        fatal_error = Some(anyhow!("a perf event reader thread panicked"));
    }

    drain_messages(&receiver, &mut stats);

    if let Some(error) = fatal_error {
        return Err(error);
    }

    output::print_report(
        pid,
        &process_name,
        started.elapsed(),
        &stats,
        interrupted.load(Ordering::Relaxed),
        process_exited,
    );
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
    .context("failed to install the Ctrl-C handler")
}

fn sync_target_tids(
    target_tids: &mut AyaHashMap<MapData, u32, u8>,
    pending_wakeups: &mut AyaHashMap<MapData, u32, [u64; 2]>,
    known_tids: &mut BTreeSet<u32>,
    current_tids: &BTreeSet<u32>,
) -> Result<()> {
    if current_tids.len() > MAX_TARGET_TIDS as usize {
        bail!(
            "process has {} threads, but the target map supports at most {}",
            current_tids.len(),
            MAX_TARGET_TIDS
        );
    }

    let removed = known_tids
        .difference(current_tids)
        .copied()
        .collect::<Vec<_>>();
    for tid in removed {
        target_tids
            .remove(&tid)
            .with_context(|| format!("failed to remove thread {tid} from the target map"))?;
        match pending_wakeups.remove(&tid) {
            Ok(()) | Err(MapError::KeyNotFound) => {}
            Err(error) => {
                return Err(error)
                    .with_context(|| format!("failed to clear pending wakeup for thread {tid}"));
            }
        }
    }

    let added = current_tids
        .difference(known_tids)
        .copied()
        .collect::<Vec<_>>();
    for tid in added {
        target_tids
            .insert(tid, 1, 0)
            .with_context(|| format!("failed to add thread {tid} to the target map"))?;
    }

    *known_tids = current_tids.clone();
    Ok(())
}

enum RefreshResult {
    Alive,
    Exited,
}

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
        Ok(current_tids) => {
            sync_target_tids(target_tids, pending_wakeups, known_tids, &current_tids)?;
            Ok(RefreshResult::Alive)
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(RefreshResult::Exited),
        Err(error) => {
            Err(error).with_context(|| format!("failed to refresh threads for process {pid}"))
        }
    }
}

enum PerfMessage {
    Sample(SchedulerLatencyEvent),
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
                let _ = sender.send(PerfMessage::Error(format!(
                    "perf buffer poll failed: {error}"
                )));
                break;
            }
            if result == 0 {
                continue;
            }
            if poll_fd.revents & (libc::POLLIN | libc::POLLERR | libc::POLLHUP | libc::POLLNVAL)
                == 0
            {
                continue;
            }

            let mut send_failed = false;
            buffer.for_each(|event| match event {
                PerfEvent::Sample { head, tail } => match decode_event(head, tail) {
                    Some(event) => {
                        if sender.send(PerfMessage::Sample(event)).is_err() {
                            send_failed = true;
                        }
                    }
                    None => {
                        let _ = sender.send(PerfMessage::Error(format!(
                            "invalid scheduler event payload: expected at least {} bytes",
                            size_of::<SchedulerLatencyEvent>()
                        )));
                        send_failed = true;
                    }
                },
                PerfEvent::Lost { count } => {
                    if sender.send(PerfMessage::Lost(count)).is_err() {
                        send_failed = true;
                    }
                }
            });

            if send_failed {
                break;
            }
        }
    })
}

fn decode_event(head: &[u8], tail: &[u8]) -> Option<SchedulerLatencyEvent> {
    let event_size = size_of::<SchedulerLatencyEvent>();
    if head.len().saturating_add(tail.len()) < event_size {
        return None;
    }

    let mut bytes = [0u8; size_of::<SchedulerLatencyEvent>()];
    let head_len = head.len().min(event_size);
    bytes[..head_len].copy_from_slice(&head[..head_len]);
    if head_len < event_size {
        bytes[head_len..].copy_from_slice(&tail[..event_size - head_len]);
    }
    Some(bytemuck::pod_read_unaligned(&bytes))
}

fn drain_messages(receiver: &Receiver<PerfMessage>, stats: &mut Statistics) {
    for message in receiver.try_iter() {
        match message {
            PerfMessage::Sample(event) => stats.record(event),
            PerfMessage::Lost(count) => stats.record_lost(count),
            PerfMessage::Error(_) => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_contiguous_event_payload() {
        let event = SchedulerLatencyEvent {
            latency_ns: 7,
            wake_ns: 10,
            run_ns: 17,
            tid: 42,
            wake_cpu: 1,
            run_cpu: 2,
            reserved: 0,
        };
        let bytes = bytemuck::bytes_of(&event);
        assert_eq!(decode_event(bytes, &[]).unwrap().tid, 42);
        assert_eq!(decode_event(bytes, &[]).unwrap().latency_ns, 7);
    }

    #[test]
    fn decodes_wrapped_event_payload() {
        let event = SchedulerLatencyEvent {
            latency_ns: 7,
            wake_ns: 10,
            run_ns: 17,
            tid: 42,
            wake_cpu: 1,
            run_cpu: 2,
            reserved: 0,
        };
        let bytes = bytemuck::bytes_of(&event);
        let split = 13;
        assert_eq!(
            decode_event(&bytes[..split], &bytes[split..])
                .unwrap()
                .run_cpu,
            2
        );
    }

    #[test]
    fn rejects_short_event_payload() {
        assert!(decode_event(&[0; 4], &[]).is_none());
    }
}
