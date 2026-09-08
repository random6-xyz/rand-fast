//! Shared eBPF collector runtime.
//!
//! Every collector command shares the same plumbing: install the target TIDs
//! into `TARGET_TIDS`, poll a perf event array, decode fixed-size events,
//! watch for Ctrl-C and process exit, and stop after a bounded duration. This
//! module provides that harness so each command only implements its own
//! statistics and report.

use std::{
    collections::BTreeSet,
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
    Ebpf, Pod as AyaPod,
    maps::{
        HashMap as AyaHashMap, MapData, MapError, PerfEventArray,
        perf::{PerfEvent, PerfEventArrayBuffer},
    },
    programs::TracePoint,
    util::online_cpus,
};
use bytemuck::Pod;
use fast_common::MAX_TARGET_TIDS;

use crate::process;

/// How often the target thread set is re-synced with `/proc/<pid>/task`.
pub const THREAD_REFRESH_INTERVAL: Duration = Duration::from_millis(100);

/// How long each perf reader waits inside `poll(2)` before re-checking the
/// stop flag.
const POLL_INTERVAL_MS: i32 = 100;

/// How long the collector main loop waits for the next perf message before
/// re-checking the stop flag and the thread refresh deadline.
const RECV_WAIT: Duration = Duration::from_millis(50);

/// Default perf buffer page count per CPU buffer.
///
/// One page is 4 KiB. The scheduler emits at most one event per wakeup of the
/// target threads, so the default is enough there. Commands that subscribe to
/// chatty tracepoints pass a larger count to avoid silent event loss.
pub const DEFAULT_PERF_PAGE_COUNT: usize = 8;

/// Upper bound for a single decodable event. All `fast-common` events are at
/// most 40 bytes; this leaves headroom without unbounded stack use.
const MAX_EVENT_SIZE: usize = 64;

/// Options for [`run_collection`].
#[derive(Debug, Clone)]
pub struct CollectionOptions {
    /// Process (TGID) whose threads are observed.
    pub pid: u32,
    /// Bounded collection duration.
    pub duration: Duration,
    /// Name of the `PerfEventArray` map to consume.
    pub events_map: &'static str,
    /// Perf buffer page count per CPU. Use a larger value than
    /// [`DEFAULT_PERF_PAGE_COUNT`] for chatty tracepoints.
    pub perf_page_count: usize,
}

/// How a collection ended.
#[derive(Debug, Clone, Copy)]
pub struct CollectionSummary {
    /// Wall time actually spent collecting. Shorter than the requested
    /// duration when Ctrl-C arrived or the process exited early.
    pub elapsed: Duration,
    /// The user pressed Ctrl-C.
    pub interrupted: bool,
    /// The observed process exited before the duration elapsed.
    pub process_exited: bool,
}

/// Receives decoded events from the perf buffers.
pub trait EventHandler<E> {
    /// Called for every decoded event.
    fn on_event(&mut self, event: E);

    /// Called when the kernel reports dropped records.
    fn on_lost(&mut self, count: u64);
}

/// Takes the shared `TARGET_TIDS` map out of the loaded eBPF object.
pub fn take_target_map(bpf: &mut Ebpf) -> Result<AyaHashMap<MapData, u32, u8>> {
    let map = bpf
        .take_map("TARGET_TIDS")
        .context("eBPF map TARGET_TIDS is missing")?;
    map.try_into()
        .context("TARGET_TIDS has an unexpected map type or layout")
}

/// Loads and attaches a tracepoint program. The program name must match the
/// tracepoint event name, as it does throughout this crate.
pub fn attach_tracepoint(bpf: &mut Ebpf, category: &str, name: &str) -> Result<()> {
    let program = bpf
        .program_mut(name)
        .with_context(|| format!("eBPF program {name} is missing"))?;
    let program: &mut TracePoint = program
        .try_into()
        .with_context(|| format!("eBPF program {name} is not a tracepoint"))?;
    program
        .load()
        .with_context(|| format!("failed to load eBPF program {name}"))?;
    program
        .attach(category, name)
        .with_context(|| format!("failed to attach to {category}/{name}"))?;
    Ok(())
}

/// Installs `current_tids` into the target map, removing stale entries and
/// their pending state.
pub fn sync_target_tids<V: AyaPod>(
    target_tids: &mut AyaHashMap<MapData, u32, u8>,
    pending: &mut AyaHashMap<MapData, u32, V>,
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
        match pending.remove(&tid) {
            Ok(()) | Err(MapError::KeyNotFound) => {}
            Err(error) => {
                return Err(error)
                    .with_context(|| format!("failed to clear pending state for thread {tid}"));
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

/// Re-syncs the target thread set with `/proc`.
///
/// Returns `Ok(true)` while the process is alive and `Ok(false)` once it has
/// exited.
pub fn refresh_target_threads<V: AyaPod>(
    pid: u32,
    target_tids: &mut AyaHashMap<MapData, u32, u8>,
    pending: &mut AyaHashMap<MapData, u32, V>,
    known_tids: &mut BTreeSet<u32>,
) -> Result<bool> {
    if !process::is_alive(pid).with_context(|| format!("failed to inspect process {pid}"))? {
        return Ok(false);
    }

    match process::thread_ids(pid) {
        Ok(current_tids) => {
            sync_target_tids(target_tids, pending, known_tids, &current_tids)?;
            Ok(true)
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(error) => {
            Err(error).with_context(|| format!("failed to refresh threads for process {pid}"))
        }
    }
}

/// Runs one bounded eBPF collection.
///
/// Installs `initial_tids` into the target map, opens a perf buffer per CPU
/// on the map named `options.events_map`, spawns one reader thread per buffer,
/// and feeds decoded events of type `E` to `handler` until the duration
/// elapses, Ctrl-C arrives, the process exits, or a fatal error occurs.
pub fn run_collection<E, V, H>(
    bpf: &mut Ebpf,
    target_tids: &mut AyaHashMap<MapData, u32, u8>,
    pending: &mut AyaHashMap<MapData, u32, V>,
    known_tids: &mut BTreeSet<u32>,
    initial_tids: &BTreeSet<u32>,
    handler: &mut H,
    options: CollectionOptions,
) -> Result<CollectionSummary>
where
    E: Pod + Send,
    V: AyaPod,
    H: EventHandler<E>,
{
    if options.perf_page_count == 0 {
        bail!("perf page count must be greater than zero");
    }

    sync_target_tids(target_tids, pending, known_tids, initial_tids)?;

    let event_map = bpf
        .take_map(options.events_map)
        .with_context(|| format!("eBPF map {} is missing", options.events_map))?;
    let mut events: PerfEventArray<MapData> = event_map.try_into().with_context(|| {
        format!(
            "{} has an unexpected map type or layout",
            options.events_map
        )
    })?;

    let cpus = online_cpus()
        .map_err(|(path, error)| anyhow!("failed to read online CPU list from {path}: {error}"))?;
    if cpus.is_empty() {
        bail!("no online CPUs were found");
    }

    let mut buffers = Vec::with_capacity(cpus.len());
    for cpu in cpus {
        let buffer = events
            .open(cpu, Some(options.perf_page_count))
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
    let mut process_exited = false;
    let mut fatal_error = None;

    while started.elapsed() < options.duration {
        if stop.load(Ordering::Relaxed) {
            break;
        }

        let remaining = options.duration.saturating_sub(started.elapsed());
        let wait = remaining.min(RECV_WAIT);
        match receiver.recv_timeout(wait) {
            Ok(PerfMessage::Sample(event)) => handler.on_event(event),
            Ok(PerfMessage::Lost(count)) => handler.on_lost(count),
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
            match refresh_target_threads(options.pid, target_tids, pending, known_tids) {
                Ok(true) => {}
                Ok(false) => {
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

    drain_messages(&receiver, handler);

    let summary = CollectionSummary {
        elapsed: started.elapsed(),
        interrupted: interrupted.load(Ordering::Relaxed),
        process_exited,
    };

    match fatal_error {
        Some(error) => Err(error),
        None => Ok(summary),
    }
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

enum PerfMessage<E> {
    Sample(E),
    Lost(u64),
    Error(String),
}

fn spawn_perf_reader<E: Pod + Send>(
    mut buffer: PerfEventArrayBuffer<MapData>,
    stop: Arc<AtomicBool>,
    sender: Sender<PerfMessage<E>>,
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
                            "invalid event payload: expected at least {} bytes",
                            size_of::<E>()
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

/// Decodes a fixed-size event that may be split across the perf buffer wrap
/// point.
fn decode_event<E: Pod>(head: &[u8], tail: &[u8]) -> Option<E> {
    let event_size = size_of::<E>();
    if event_size > MAX_EVENT_SIZE {
        return None;
    }
    if head.len().saturating_add(tail.len()) < event_size {
        return None;
    }

    let mut bytes = [0u8; MAX_EVENT_SIZE];
    let head_len = head.len().min(event_size);
    bytes[..head_len].copy_from_slice(&head[..head_len]);
    if head_len < event_size {
        bytes[head_len..event_size].copy_from_slice(&tail[..event_size - head_len]);
    }
    Some(bytemuck::pod_read_unaligned(&bytes[..event_size]))
}

fn drain_messages<E, H: EventHandler<E>>(receiver: &Receiver<PerfMessage<E>>, handler: &mut H) {
    for message in receiver.try_iter() {
        match message {
            PerfMessage::Sample(event) => handler.on_event(event),
            PerfMessage::Lost(count) => handler.on_lost(count),
            PerfMessage::Error(_) => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fast_common::{CpuSampleEvent, IoEvent, OffCpuEvent, SchedulerLatencyEvent, TcpEvent};

    #[test]
    fn known_events_fit_the_decode_buffer() {
        assert!(size_of::<SchedulerLatencyEvent>() <= MAX_EVENT_SIZE);
        assert!(size_of::<CpuSampleEvent>() <= MAX_EVENT_SIZE);
        assert!(size_of::<IoEvent>() <= MAX_EVENT_SIZE);
        assert!(size_of::<TcpEvent>() <= MAX_EVENT_SIZE);
        assert!(size_of::<OffCpuEvent>() <= MAX_EVENT_SIZE);
    }

    fn sample_event() -> SchedulerLatencyEvent {
        SchedulerLatencyEvent {
            latency_ns: 7,
            wake_ns: 10,
            run_ns: 17,
            tid: 42,
            wake_cpu: 1,
            run_cpu: 2,
            reserved: 0,
        }
    }

    #[test]
    fn decodes_contiguous_event_payload() {
        let event_data = sample_event();
        let bytes = bytemuck::bytes_of(&event_data);
        let event = decode_event::<SchedulerLatencyEvent>(bytes, &[]).unwrap();
        assert_eq!(event.tid, 42);
        assert_eq!(event.latency_ns, 7);
    }

    #[test]
    fn decodes_wrapped_event_payload() {
        let event_data = sample_event();
        let bytes = bytemuck::bytes_of(&event_data);
        let split = 13;
        let event = decode_event::<SchedulerLatencyEvent>(&bytes[..split], &bytes[split..]).unwrap();
        assert_eq!(event.run_cpu, 2);
        assert_eq!(event.latency_ns, 7);
    }

    #[test]
    fn rejects_short_event_payload() {
        assert!(decode_event::<SchedulerLatencyEvent>(&[0; 4], &[]).is_none());
    }
}
