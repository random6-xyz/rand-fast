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
    marker::PhantomData,
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

/// The default `poll(2)` interval for a collection that reports at the end.
///
/// Long enough that reader threads are not the dominant cost, short enough
/// that a Ctrl-C is acted on promptly.
pub const DEFAULT_POLL_INTERVAL: Duration = Duration::from_millis(POLL_INTERVAL_MS as u64);

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
/// most 56 bytes; this leaves headroom without unbounded stack use.
pub const MAX_EVENT_SIZE: usize = 64;

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
    /// Collector mode bits (`fast_common::COLLECT_*`) written into the eBPF
    /// `MODE` map so tracepoint programs only run the paths this command
    /// consumes.
    pub mode: u32,
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

/// Lets a borrowed collector be handed to a stream.
///
/// A multi-stream run keeps its collectors in one scope and hands each one out
/// by mutable reference, which is what keeps the caller's statistics readable
/// after the run.
impl<E, H: EventHandler<E> + ?Sized> EventHandler<E> for &mut H {
    fn on_event(&mut self, event: E) {
        (**self).on_event(event);
    }

    fn on_lost(&mut self, count: u64) {
        (**self).on_lost(count);
    }
}

/// Per-thread pending state that must be cleared when a target thread exits.
pub trait PendingCleanup {
    /// Removes any pending state tracked for `tid`.
    fn clear(&mut self, tid: u32) -> Result<(), MapError>;
}

impl<V: AyaPod> PendingCleanup for AyaHashMap<MapData, u32, V> {
    fn clear(&mut self, tid: u32) -> Result<(), MapError> {
        match self.remove(&tid) {
            Ok(()) | Err(MapError::KeyNotFound) => Ok(()),
            Err(error) => Err(error),
        }
    }
}

/// Pending-state no-op for collectors whose pending maps are not keyed by
/// TID, so thread-exit cleanup has nothing to remove: on-CPU sampling keeps
/// no pending state, and per-request I/O entries die through the map's LRU
/// eviction instead.
pub struct NoPendingCleanup;

impl PendingCleanup for NoPendingCleanup {
    fn clear(&mut self, _tid: u32) -> Result<(), MapError> {
        Ok(())
    }
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
pub fn sync_target_tids(
    target_tids: &mut AyaHashMap<MapData, u32, u8>,
    pending: &mut dyn PendingCleanup,
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
        pending
            .clear(tid)
            .with_context(|| format!("failed to clear pending state for thread {tid}"))?;
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
pub fn refresh_target_threads(
    pid: u32,
    target_tids: &mut AyaHashMap<MapData, u32, u8>,
    pending: &mut dyn PendingCleanup,
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
pub fn run_collection<E, H>(
    bpf: &mut Ebpf,
    target_tids: &mut AyaHashMap<MapData, u32, u8>,
    pending: &mut dyn PendingCleanup,
    known_tids: &mut BTreeSet<u32>,
    initial_tids: &BTreeSet<u32>,
    handler: &mut H,
    options: CollectionOptions,
) -> Result<CollectionSummary>
where
    E: Pod + Send,
    H: EventHandler<E>,
{
    if options.perf_page_count == 0 {
        bail!("perf page count must be greater than zero");
    }

    // Select the collector paths the tracepoint programs execute before any
    // event can flow.
    let mode_map = bpf.take_map("MODE").context("eBPF map MODE is missing")?;
    let mut mode_map: AyaHashMap<MapData, u32, u32> = mode_map
        .try_into()
        .context("MODE has an unexpected map type or layout")?;
    mode_map
        .insert(0, options.mode, 0)
        .context("failed to write the collector mode")?;

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
        .map(|buffer| spawn_typed_perf_reader(buffer, Arc::clone(&stop), sender.clone()))
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
        // Cap at the requested duration: joining the readers and draining the
        // channel must not inflate the reported measurement window.
        elapsed: started.elapsed().min(options.duration),
        interrupted: interrupted.load(Ordering::Relaxed),
        process_exited,
    };

    match fatal_error {
        Some(error) => Err(error),
        None => Ok(summary),
    }
}

/// A consumer of one event stream, with the event type erased.
///
/// Multi-stream collection has to hold several different event types behind
/// one loop and one channel, so a stream receives raw payloads and decodes
/// them with its own type.
///
/// The sink is touched only by the collection loop, never by the reader
/// threads, which forward untyped bytes. That is why it carries no `Send`
/// bound: a collector can therefore be a borrow of the caller's own variable,
/// so the numbers stay readable after the run instead of having to be handed
/// back out of a box.
pub trait EventSink {
    /// Called with one raw event payload, sized for this stream's event type.
    fn on_event(&mut self, bytes: &[u8]) -> Result<()>;

    /// Called when the kernel reports records dropped on this stream.
    fn on_lost(&mut self, count: u64);

    /// Reports everything accumulated so far, as a document.
    ///
    /// A collector that only reports at the end of a collection does not need
    /// this. A long-running one does: it has to summarise the last interval
    /// while the collection stays open, and the only way to reach the
    /// accumulators from outside is through the stream that owns them.
    ///
    /// The values are cumulative, not per-interval. The caller differences
    /// consecutive snapshots, which is what makes the interval length cancel
    /// out.
    fn snapshot(&mut self) -> Option<serde_json::Value> {
        None
    }
}

/// A function that renders a collector's accumulated state as a document.
pub type SnapshotFn<H> = fn(&H) -> serde_json::Value;

/// Adapts a typed [`EventHandler`] to the type-erased [`EventSink`].
///
/// Decoding happens here rather than in the reader thread so one channel
/// carries every stream: the reader hands over a fixed-size byte buffer and
/// the sink, which knows its event type, interprets it.
pub struct TypedSink<E, H> {
    handler: H,
    event_size: usize,
    snapshot: Option<SnapshotFn<H>>,
    marker: PhantomData<E>,
}

impl<E, H> TypedSink<E, H>
where
    E: Pod,
    H: EventHandler<E>,
{
    /// Wraps a typed handler that reports only at the end of a collection.
    pub fn new(handler: H) -> Self {
        Self {
            handler,
            event_size: size_of::<E>(),
            snapshot: None,
            marker: PhantomData,
        }
    }

    /// Wraps a typed handler that can also report what it has accumulated.
    pub fn with_snapshot(handler: H, snapshot: SnapshotFn<H>) -> Self {
        Self {
            handler,
            event_size: size_of::<E>(),
            snapshot: Some(snapshot),
            marker: PhantomData,
        }
    }
}

impl<E, H> EventSink for TypedSink<E, H>
where
    E: Pod,
    H: EventHandler<E>,
{
    fn on_event(&mut self, bytes: &[u8]) -> Result<()> {
        if bytes.len() < self.event_size {
            bail!(
                "event payload of {} bytes is shorter than the {}-byte event type",
                bytes.len(),
                self.event_size
            );
        }
        // Copy first: the payload is a packed perf record, so it is not
        // guaranteed to satisfy the event type's own alignment.
        let mut aligned = [0u8; MAX_EVENT_SIZE];
        aligned[..self.event_size].copy_from_slice(&bytes[..self.event_size]);
        let event: E = bytemuck::pod_read_unaligned(&aligned[..self.event_size]);
        self.handler.on_event(event);
        Ok(())
    }

    fn on_lost(&mut self, count: u64) {
        self.handler.on_lost(count);
    }

    fn snapshot(&mut self) -> Option<serde_json::Value> {
        let snapshot = self.snapshot?;
        Some(snapshot(&self.handler))
    }
}

/// One perf event array to consume during a multi-stream collection.
pub struct EventStream<'a> {
    /// Name of the `PerfEventArray` map.
    pub map_name: &'static str,
    /// Name a periodic summary reports this stream under, which is the command
    /// it belongs to rather than the map that carries it.
    pub name: &'static str,
    /// Perf buffer page count per CPU for this stream.
    pub perf_page_count: usize,
    /// Byte size of this stream's event type.
    pub event_size: usize,
    /// Where decoded events go.
    pub sink: Box<dyn EventSink + 'a>,
}

impl<'a> EventStream<'a> {
    /// Builds a stream for an event type `E`, feeding a typed handler.
    pub fn of<E, H>(map_name: &'static str, perf_page_count: usize, handler: H) -> Self
    where
        E: Pod + 'a,
        H: EventHandler<E> + 'a,
    {
        Self {
            map_name,
            name: map_name,
            perf_page_count,
            event_size: size_of::<E>(),
            sink: Box::new(TypedSink::<E, H>::new(handler)),
        }
    }

    /// Builds a named stream whose collector can also report what it has
    /// accumulated, for a caller that samples while the collection stays open.
    pub fn sampled<E, H>(
        name: &'static str,
        map_name: &'static str,
        perf_page_count: usize,
        handler: H,
        snapshot: SnapshotFn<H>,
    ) -> Self
    where
        E: Pod + 'a,
        H: EventHandler<E> + 'a,
    {
        Self {
            map_name,
            name,
            perf_page_count,
            event_size: size_of::<E>(),
            sink: Box::new(TypedSink::<E, H>::with_snapshot(handler, snapshot)),
        }
    }
}

/// Options for [`run_multi_collection`].
#[derive(Debug, Clone, Copy)]
pub struct MultiCollectionOptions {
    /// Process (TGID) whose threads are observed.
    pub pid: u32,
    /// Bounded collection duration.
    pub duration: Duration,
    /// Collector mode bits written into the eBPF `MODE` map.
    pub mode: u32,
    /// How often the tick callback runs, when one is given. Ignored without a
    /// callback.
    pub tick_interval: Duration,
    /// How long each perf reader waits inside `poll(2)` before checking the
    /// stop flag.
    ///
    /// A short interval makes events reach the collector sooner. A long one
    /// makes each reader thread wake less often, which is the dominant cost of
    /// a long-running collection: a background recorder has nothing to gain
    /// from dispatching events faster than it summarises them.
    pub poll_interval: Duration,
}

/// A periodic summary of every stream, taken while the collection stays open.
///
/// The values are cumulative. A caller that wants the numbers for one interval
/// differences two consecutive summaries, which is also what makes the summary
/// independent of when the collection happened to start.
pub type TickSummary<'a> = Vec<(&'static str, serde_json::Value)>;

/// The callback a long-running collection uses to summarise each interval.
///
/// Named because the type is long enough to be worth not writing twice.
pub type TickCallback<'a> = Box<dyn FnMut(Duration, TickSummary<'_>) + 'a>;

/// What a multi-stream collection consumes: the streams, and optionally a
/// callback that summarises them while the collection runs.
pub struct MultiStreams<'a> {
    /// One entry per `PerfEventArray` to consume.
    pub streams: Vec<EventStream<'a>>,
    /// Called every [`MultiCollectionOptions::tick_interval`] with cumulative
    /// totals. `None` for a collection that only reports at the end.
    pub on_tick: Option<TickCallback<'a>>,
}

/// Runs several perf event streams from one eBPF object over one channel.
///
/// This is what lets a command observe scheduler latency, CPU sampling, block
/// I/O and TCP at the same time: the object is loaded once, one reader thread
/// runs per stream per CPU, and a single loop dispatches each record to the
/// stream that produced it. Target exit and Ctrl-C are handled once for all of
/// them rather than per collector.
pub fn run_multi_collection<'a>(
    bpf: &mut Ebpf,
    target_tids: &mut AyaHashMap<MapData, u32, u8>,
    pending: &mut dyn PendingCleanup,
    known_tids: &mut BTreeSet<u32>,
    initial_tids: &BTreeSet<u32>,
    options: MultiCollectionOptions,
    consumers: MultiStreams<'a>,
) -> Result<CollectionSummary> {
    let MultiStreams {
        mut streams,
        mut on_tick,
    } = consumers;
    if streams.is_empty() {
        bail!("at least one event stream is required");
    }
    if options.tick_interval.is_zero() && on_tick.is_some() {
        bail!("a tick interval of zero would never produce a summary");
    }

    let mode_map = bpf.take_map("MODE").context("eBPF map MODE is missing")?;
    let mut mode_map: AyaHashMap<MapData, u32, u32> = mode_map
        .try_into()
        .context("MODE has an unexpected map type or layout")?;
    mode_map
        .insert(0, options.mode, 0)
        .context("failed to write the collector mode")?;

    sync_target_tids(target_tids, pending, known_tids, initial_tids)?;

    let cpus = online_cpus()
        .map_err(|(path, error)| anyhow!("failed to read online CPU list from {path}: {error}"))?;
    if cpus.is_empty() {
        bail!("no online CPUs were found");
    }

    let stop = Arc::new(AtomicBool::new(false));
    let interrupted = Arc::new(AtomicBool::new(false));
    install_signal_handler(&stop, &interrupted)?;

    let (sender, receiver) = mpsc::channel::<MultiMessage>();
    let mut readers = Vec::new();
    // poll(2) takes milliseconds, and a zero interval would spin, so the
    // option is clamped to at least the default.
    let poll_ms = options
        .poll_interval
        .as_millis()
        .clamp(POLL_INTERVAL_MS as u128, i32::MAX as u128) as i32;

    for (index, stream) in streams.iter().enumerate() {
        if stream.perf_page_count == 0 {
            bail!("perf page count must be greater than zero");
        }
        if stream.event_size > MAX_EVENT_SIZE {
            bail!(
                "{} events are {} bytes, which exceeds the {MAX_EVENT_SIZE}-byte buffer",
                stream.map_name,
                stream.event_size
            );
        }
        let event_map = bpf
            .take_map(stream.map_name)
            .with_context(|| format!("eBPF map {} is missing", stream.map_name))?;
        let mut events: PerfEventArray<MapData> = event_map
            .try_into()
            .with_context(|| format!("{} has an unexpected map type or layout", stream.map_name))?;
        for cpu in &cpus {
            let buffer = events
                .open(*cpu, Some(stream.perf_page_count))
                .with_context(|| {
                    format!(
                        "failed to open the {} perf buffer for CPU {cpu}",
                        stream.map_name
                    )
                })?;
            readers.push(spawn_stream_reader(
                buffer,
                stream.event_size,
                index,
                Arc::clone(&stop),
                sender.clone(),
                poll_ms,
            ));
        }
        // The map is dropped per stream, so two streams must not name the same
        // one: the second take would fail with a confusing type error.
        drop(events);
    }
    drop(sender);

    let started = Instant::now();
    let mut next_refresh = started + THREAD_REFRESH_INTERVAL;
    let mut next_tick = started + options.tick_interval;
    let mut process_exited = false;
    let mut fatal_error = None;

    while started.elapsed() < options.duration {
        if stop.load(Ordering::Relaxed) {
            break;
        }
        let remaining = options.duration.saturating_sub(started.elapsed());
        let wait = remaining.min(RECV_WAIT);
        match receiver.recv_timeout(wait) {
            Ok(MultiMessage::Sample(index, bytes)) => {
                if let Some(Err(error)) = streams.get_mut(index).map(|s| s.sink.on_event(&bytes)) {
                    // A malformed payload is a bug in the event layout, not a
                    // transient condition, so it ends the run rather than
                    // silently dropping records.
                    fatal_error = Some(error);
                    stop.store(true, Ordering::Relaxed);
                    break;
                }
            }
            Ok(MultiMessage::Lost(index, count)) => {
                if let Some(stream) = streams.get_mut(index) {
                    stream.sink.on_lost(count);
                }
            }
            Ok(MultiMessage::Error(error)) => {
                fatal_error = Some(anyhow!(error));
                stop.store(true, Ordering::Relaxed);
                break;
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {}
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                if !stop.load(Ordering::Relaxed) {
                    fatal_error = Some(anyhow!("all perf event readers stopped unexpectedly"));
                }
                break;
            }
        }

        if let Some(tick) = on_tick.as_mut()
            && Instant::now() >= next_tick
        {
            // The snapshots are read here rather than inside the readers, so
            // the summary is consistent with the events already dispatched.
            let summary: TickSummary<'_> = streams
                .iter_mut()
                .filter_map(|stream| stream.sink.snapshot().map(|value| (stream.name, value)))
                .collect();
            tick(started.elapsed(), summary);
            // Drifted forward from now rather than from the last tick, so a slow
            // callback does not make the interval shorter every time and end
            // up firing back to back.
            next_tick = Instant::now() + options.tick_interval;
        }

        if let Some(tick) = on_tick.as_mut()
            && Instant::now() >= next_tick
        {
            // The snapshots are read here rather than inside the readers, so
            // the summary is consistent with the events already dispatched.
            let summary: TickSummary<'_> = streams
                .iter_mut()
                .filter_map(|stream| stream.sink.snapshot().map(|value| (stream.name, value)))
                .collect();
            tick(started.elapsed(), summary);
            // Drifted forward from now rather than from the last tick, so a slow
            // callback does not make the interval shorter every time and end
            // up firing back to back.
            next_tick = Instant::now() + options.tick_interval;
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

    // Drain what the readers produced while they were shutting down, so the
    // last moments of a collection are not thrown away.
    for message in receiver.try_iter() {
        match message {
            MultiMessage::Sample(index, bytes) => {
                if let Some(stream) = streams.get_mut(index) {
                    let _ = stream.sink.on_event(&bytes);
                }
            }
            MultiMessage::Lost(index, count) => {
                if let Some(stream) = streams.get_mut(index) {
                    stream.sink.on_lost(count);
                }
            }
            MultiMessage::Error(_) => {}
        }
    }

    let summary = CollectionSummary {
        elapsed: started.elapsed().min(options.duration),
        interrupted: interrupted.load(Ordering::Relaxed),
        process_exited,
    };

    match fatal_error {
        Some(error) => Err(error),
        None => Ok(summary),
    }
}

enum MultiMessage {
    /// Which stream produced the record, and its raw payload.
    Sample(usize, [u8; MAX_EVENT_SIZE]),
    Lost(usize, u64),
    Error(String),
}

/// Copies one event payload out of a perf record, which may be split across
/// the buffer wrap point.
///
/// Unlike [`decode_event`] this does not decode into a typed event: a
/// multi-stream reader does not know the type, so it copies `event_size` bytes
/// into a fixed buffer for the sink to interpret.
fn decode_payload(head: &[u8], tail: &[u8], event_size: usize) -> Option<[u8; MAX_EVENT_SIZE]> {
    if event_size == 0 || event_size > MAX_EVENT_SIZE {
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
    Some(bytes)
}

/// Reader for one stream of a multi-stream collection.
///
/// The payload is forwarded as raw bytes tagged with the stream index, so one
/// channel can carry every stream and the sink decodes with its own type.
fn spawn_stream_reader(
    mut buffer: PerfEventArrayBuffer<MapData>,
    event_size: usize,
    index: usize,
    stop: Arc<AtomicBool>,
    sender: Sender<MultiMessage>,
    poll_ms: i32,
) -> JoinHandle<()> {
    thread::spawn(move || {
        let mut poll_fd = libc::pollfd {
            fd: buffer.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };

        while !stop.load(Ordering::Relaxed) {
            poll_fd.revents = 0;
            let result = unsafe { libc::poll(&mut poll_fd, 1, poll_ms) };
            if result < 0 {
                let error = io::Error::last_os_error();
                if error.kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                let _ = sender.send(MultiMessage::Error(format!(
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
                PerfEvent::Sample { head, tail } => match decode_payload(head, tail, event_size) {
                    Some(payload) => {
                        if sender.send(MultiMessage::Sample(index, payload)).is_err() {
                            send_failed = true;
                        }
                    }
                    None => {
                        let _ = sender.send(MultiMessage::Error(format!(
                            "invalid event payload: expected at least {event_size} bytes"
                        )));
                        send_failed = true;
                    }
                },
                PerfEvent::Lost { count } => {
                    if sender.send(MultiMessage::Lost(index, count)).is_err() {
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

/// Options for [`run_map_collection`].
#[derive(Debug, Clone, Copy)]
pub struct MapCollectionOptions {
    /// Process (TGID) whose threads are observed.
    pub pid: u32,
    /// Bounded collection duration.
    pub duration: Duration,
    /// How often the collector callback is invoked.
    pub interval: Duration,
    /// Collector mode bits (`fast_common::COLLECT_*`) written into the eBPF
    /// `MODE` map.
    pub mode: u32,
}

/// Runs a collection that polls eBPF maps instead of consuming perf events.
///
/// Used by collectors whose kernel side is too hot to stream as events, such
/// as the page fault counter. The callback is invoked once per `interval`,
/// with the wall time since collection started, and the loop ends when the
/// duration elapses, Ctrl-C arrives, or the process exits.
///
/// The final call happens after the loop regardless, so a duration shorter
/// than one interval still produces one sample.
pub fn run_map_collection<F>(
    bpf: &mut Ebpf,
    target_tids: &mut AyaHashMap<MapData, u32, u8>,
    pending: &mut dyn PendingCleanup,
    known_tids: &mut BTreeSet<u32>,
    initial_tids: &BTreeSet<u32>,
    options: MapCollectionOptions,
    mut sample: F,
) -> Result<CollectionSummary>
where
    F: FnMut(Duration),
{
    let mode_map = bpf.take_map("MODE").context("eBPF map MODE is missing")?;
    let mut mode_map: AyaHashMap<MapData, u32, u32> = mode_map
        .try_into()
        .context("MODE has an unexpected map type or layout")?;
    mode_map
        .insert(0, options.mode, 0)
        .context("failed to write the collector mode")?;

    sync_target_tids(target_tids, pending, known_tids, initial_tids)?;

    let stop = Arc::new(AtomicBool::new(false));
    let interrupted = Arc::new(AtomicBool::new(false));
    install_signal_handler(&stop, &interrupted)?;

    let started = Instant::now();
    let mut next_sample = started;
    let mut next_refresh = started + THREAD_REFRESH_INTERVAL;
    let mut process_exited = false;

    while started.elapsed() < options.duration {
        if stop.load(Ordering::Relaxed) {
            break;
        }
        if Instant::now() >= next_sample {
            sample(started.elapsed());
            next_sample = Instant::now() + options.interval;
        }
        if Instant::now() >= next_refresh {
            match refresh_target_threads(options.pid, target_tids, pending, known_tids) {
                Ok(true) => {}
                Ok(false) => {
                    process_exited = true;
                    stop.store(true, Ordering::Relaxed);
                    break;
                }
                Err(error) => return Err(error),
            }
            next_refresh = Instant::now() + THREAD_REFRESH_INTERVAL;
        }
        thread::sleep(RECV_WAIT.min(options.interval));
    }

    // One last sample, so a run shorter than the interval is not empty.
    sample(started.elapsed());

    Ok(CollectionSummary {
        elapsed: started.elapsed().min(options.duration),
        interrupted: interrupted.load(Ordering::Relaxed),
        process_exited,
    })
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

/// Reader for a single-typed collection, decoding in the reader thread.
fn spawn_typed_perf_reader<E: Pod + Send>(
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
        let event =
            decode_event::<SchedulerLatencyEvent>(&bytes[..split], &bytes[split..]).unwrap();
        assert_eq!(event.run_cpu, 2);
        assert_eq!(event.latency_ns, 7);
    }

    #[test]
    fn rejects_short_event_payload() {
        assert!(decode_event::<SchedulerLatencyEvent>(&[0; 4], &[]).is_none());
    }
}
