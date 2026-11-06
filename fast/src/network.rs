//! TCP measurement and endpoint reporting.
//!
//! A measurement is only published when the connection's owner is proven:
//! either the kernel saw the target create the socket, or the target's own
//! descriptor table shows it holds the socket. The ownership record carries
//! that proof, and every event is joined against it by connection 5-tuple.
//! There is no fallback to "the current task looked busy", because a
//! plausible-looking wrong attribution is worse than an unavailable one.

use std::{
    cell::RefCell,
    cmp::Reverse,
    collections::BTreeMap,
    rc::Rc,
    time::{Duration, Instant},
};

use anyhow::{Context, Result};
use aya::{Ebpf, include_bytes_aligned};
use fast_common::{COLLECT_NET, ConnEvent, TCP_CONNECT_ESTABLISHED, TcpEvent, TcpKey};

use crate::{
    cli::NetArgs,
    json::{self, Envelope, Format},
    process, runtime,
    tcp::TcpCollector,
};

pub use crate::tcp_ownership::format_address;

/// The two TCP event streams feed one aggregator.
///
/// The collection loop dispatches every stream on one thread, so a shared
/// cell is enough to let the RTT and handshake streams write to the same
/// accumulator without cloning it.
pub struct SharedStats(Rc<RefCell<NetStats>>);

impl SharedStats {
    /// Wraps a shared accumulator for a collection stream.
    pub fn new(stats: Rc<RefCell<NetStats>>) -> Self {
        Self(stats)
    }
}

impl runtime::EventHandler<TcpEvent> for SharedStats {
    fn on_event(&mut self, event: TcpEvent) {
        self.0.borrow_mut().record(event);
    }

    fn on_lost(&mut self, count: u64) {
        self.0.borrow_mut().record_lost(count);
    }
}

impl runtime::EventHandler<ConnEvent> for SharedStats {
    fn on_event(&mut self, event: ConnEvent) {
        self.0.borrow_mut().record_conn(event);
    }

    fn on_lost(&mut self, count: u64) {
        self.0.borrow_mut().record_lost(count);
    }
}

/// RTT samples arrive at most once per connection per sampling interval, and
/// 64 pages (256 KiB) per CPU keeps event loss low for a process with many
/// connections.
const PERF_PAGE_COUNT: usize = 64;

/// How often the ownership records are reconciled with procfs. A descriptor
/// handed away or closed is attributed for at most this long after it happens.
const RECONCILE_INTERVAL: Duration = Duration::from_secs(1);

/// How many rows the endpoint table prints before truncating. A busy process
/// can hold hundreds of connections, and a table nobody scrolls is better
/// than one that buries its first line.
const MAX_REPORTED_ENDPOINTS: usize = 10;

/// One remote endpoint observed during a run.
#[derive(Debug, Default, Clone)]
pub struct Endpoint {
    /// Connection identity, also the aggregation key.
    pub key: TcpKey,
    /// Smoothed RTT samples in microseconds, one per attributed event.
    pub rtts: Vec<u32>,
    /// Number of retransmissions attributed to this connection.
    pub retrans: u64,
    /// Highest congestion window in segments seen on this connection.
    pub max_cwnd: u32,
    /// Highest receive window in bytes seen on this connection.
    pub max_rcv_wnd: u32,
    /// Client handshakes that completed for this connection.
    pub connects: u64,
    /// Client handshakes that closed before establishing.
    pub connect_failures: u64,
    /// Handshake durations in microseconds.
    pub connect_us: Vec<u32>,
}

impl Endpoint {
    fn new(key: TcpKey, event: &TcpEvent) -> Self {
        Self {
            key,
            rtts: Vec::new(),
            retrans: 0,
            max_cwnd: event.snd_cwnd,
            max_rcv_wnd: event.rcv_wnd,
            connects: 0,
            connect_failures: 0,
            connect_us: Vec::new(),
        }
    }

    /// p50, p95 and p99 of this endpoint's RTT samples, in microseconds.
    pub fn rtt_percentiles(&self) -> (u32, u32, u32) {
        crate::stats::percentiles_us(&self.rtts)
    }

    /// p50, p95 and p99 of this endpoint's handshake durations, in
    /// microseconds. All zero when no handshake was measured.
    pub fn connect_percentiles(&self) -> (u32, u32, u32) {
        if self.connect_us.is_empty() {
            return (0, 0, 0);
        }
        crate::stats::percentiles_us(&self.connect_us)
    }

    /// Key used to rank endpoints by how slow they are.
    ///
    /// p95 is the ranking signal because a single slow tail is what makes a
    /// connection the reason a request felt slow, and p95 is far steadier
    /// than a maximum over a short run. The connection key breaks ties so the
    /// ordering is deterministic between runs.
    fn slowness(&self) -> (u32, TcpKey) {
        let (_, p95, _) = self.rtt_percentiles();
        (p95, self.key)
    }

    /// Key used to rank slow connection setup, in microseconds.
    fn connect_slowness(&self) -> (u32, TcpKey) {
        let (_, p95, _) = self.connect_percentiles();
        (p95, self.key)
    }

    /// Retransmissions per second of collection time.
    pub fn retrans_per_second(&self, elapsed: Duration) -> f64 {
        if elapsed.is_zero() {
            return 0.0;
        }
        self.retrans as f64 / elapsed.as_secs_f64()
    }
}

/// Aggregates attributed TCP events per connection.
#[derive(Debug, Default)]
pub struct NetStats {
    endpoints: BTreeMap<TcpKey, Endpoint>,
    retrans: u64,
    samples: u64,
    lost: u64,
    connects: u64,
    connect_failures: u64,
    connect_us: Vec<u32>,
    /// Connections that produced a creation event, which corroborates
    /// ownership independently of procfs.
    created: std::collections::BTreeSet<TcpKey>,
}

impl NetStats {
    fn record(&mut self, event: TcpEvent) {
        let key = TcpKey::new(
            event.family,
            event.saddr,
            event.sport,
            event.daddr,
            event.dport,
        );
        let is_retrans = event.retrans != 0;
        if is_retrans {
            self.retrans += 1;
        } else {
            self.samples += 1;
        }

        let entry = self
            .endpoints
            .entry(key)
            .or_insert_with(|| Endpoint::new(key, &event));
        if is_retrans {
            entry.retrans += 1;
        } else {
            if event.rtt_us != 0 {
                // A connection that has not completed a round trip yet
                // reports a smoothed RTT of zero, which carries no
                // percentile information.
                entry.rtts.push(event.rtt_us);
            }
            entry.max_cwnd = entry.max_cwnd.max(event.snd_cwnd);
            entry.max_rcv_wnd = entry.max_rcv_wnd.max(event.rcv_wnd);
        }
    }

    fn record_conn(&mut self, event: ConnEvent) {
        let key = event.key();
        self.created.insert(key);
        let entry = self.endpoints.entry(key).or_insert_with(|| Endpoint {
            key,
            ..Endpoint::default()
        });
        if event.result == TCP_CONNECT_ESTABLISHED {
            self.connects += 1;
            entry.connects += 1;
            if event.latency_us != 0 {
                self.connect_us.push(event.latency_us);
                entry.connect_us.push(event.latency_us);
            }
        } else {
            self.connect_failures += 1;
            entry.connect_failures += 1;
        }
    }

    fn record_lost(&mut self, count: u64) {
        self.lost = self.lost.saturating_add(count);
    }

    /// Endpoints ordered from slowest to fastest by RTT p95.
    pub fn slowest_endpoints(&self) -> Vec<&Endpoint> {
        let mut ordered: Vec<&Endpoint> = self.endpoints.values().collect();
        ordered.sort_by_key(|endpoint| Reverse(endpoint.slowness()));
        ordered
    }

    /// Endpoints ordered from slowest to fastest handshake by p95.
    ///
    /// Only connections with a measured handshake appear: an accepted socket
    /// has no observable start, and a connection that existed before
    /// collection has no creation event, so neither can be ranked here.
    pub fn slowest_connects(&self) -> Vec<&Endpoint> {
        let mut ordered: Vec<&Endpoint> = self
            .endpoints
            .values()
            .filter(|endpoint| !endpoint.connect_us.is_empty())
            .collect();
        ordered.sort_by_key(|endpoint| Reverse(endpoint.connect_slowness()));
        ordered
    }

    /// Total retransmissions across all endpoints.
    pub fn retrans(&self) -> u64 {
        self.retrans
    }

    /// Number of ordinary RTT samples across all endpoints.
    pub fn samples(&self) -> u64 {
        self.samples
    }

    /// Number of records the kernel dropped.
    pub fn lost(&self) -> u64 {
        self.lost
    }

    /// Completed client handshakes.
    pub fn connects(&self) -> u64 {
        self.connects
    }

    /// Client handshakes that closed before establishing.
    pub fn connect_failures(&self) -> u64 {
        self.connect_failures
    }

    /// Handshake percentiles across every measured connection.
    pub fn connect_percentiles(&self) -> (u32, u32, u32) {
        if self.connect_us.is_empty() {
            return (0, 0, 0);
        }
        crate::stats::percentiles_us(&self.connect_us)
    }

    /// Whether a connection produced its own creation event.
    pub fn was_created(&self, key: &TcpKey) -> bool {
        self.created.contains(key)
    }

    /// Drops endpoints the target's socket table never corroborated, and
    /// returns how many were dropped.
    ///
    /// The kernel keys ownership by tuple, which is not scoped to a network
    /// namespace. A socket in another namespace with the same 5-tuple could
    /// therefore add samples to one of these rows; a row is only published
    /// when the target itself either created the connection or holds its
    /// descriptor.
    pub fn retain_verified(&mut self, collector: &TcpCollector) -> u64 {
        let unverified: Vec<TcpKey> = self
            .endpoints
            .keys()
            .copied()
            .filter(|key| !collector.is_verified(key) && !self.created.contains(key))
            .collect();
        for key in &unverified {
            self.endpoints.remove(key);
        }
        unverified.len() as u64
    }

    /// Whether any endpoint remains after verification.
    pub fn endpoints_len(&self) -> usize {
        self.endpoints.len()
    }
}

impl runtime::EventHandler<TcpEvent> for NetStats {
    fn on_event(&mut self, event: TcpEvent) {
        self.record(event);
    }

    fn on_lost(&mut self, count: u64) {
        self.record_lost(count);
    }
}

impl runtime::EventHandler<ConnEvent> for NetStats {
    fn on_event(&mut self, event: ConnEvent) {
        self.record_conn(event);
    }

    fn on_lost(&mut self, count: u64) {
        self.record_lost(count);
    }
}

/// Renders an endpoint as `address:port -> address:port`.
pub fn format_endpoint(endpoint: &Endpoint) -> String {
    format!(
        "{}:{} -> {}:{}",
        format_address(endpoint.key.family, endpoint.key.saddr),
        endpoint.key.sport,
        format_address(endpoint.key.family, endpoint.key.daddr),
        endpoint.key.dport
    )
}

/// Attaches the TCP ownership and measurement programs.
pub fn attach(bpf: &mut Ebpf) -> Result<()> {
    runtime::attach_tracepoint(bpf, "sock", "inet_sock_set_state")?;
    runtime::attach_tracepoint(bpf, "tcp", "tcp_probe")?;
    runtime::attach_tracepoint(bpf, "tcp", "tcp_retransmit_skb")?;
    Ok(())
}

pub fn run(args: NetArgs) -> Result<()> {
    let pid = args.pid;
    let process_name =
        process::read_name(pid).with_context(|| format!("cannot read process {pid}"))?;
    let initial_tids =
        process::thread_ids(pid).with_context(|| format!("cannot enumerate threads for {pid}"))?;

    let mut bpf = Ebpf::load(include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/fast-ebpf"
    )))
    .context("failed to load eBPF object; run as root or grant CAP_BPF and CAP_PERFMON")?;
    attach(&mut bpf)?;
    let mut target_tids = runtime::take_target_map(&mut bpf)?;
    let collector = Rc::new(RefCell::new(TcpCollector::new(&mut bpf, pid)?));
    // Seed the sockets that already exist, so a process that is already
    // serving or connected is measurable without waiting for a restart.
    collector.borrow_mut().reconcile();

    let mut known_tids = std::collections::BTreeSet::new();
    let stats = Rc::new(RefCell::new(NetStats::default()));
    let reconcile = Rc::clone(&collector);
    // The tick callback reports the collection's elapsed time, so the window
    // the report prints is the one the measurements covered.
    let tick_started = Instant::now();
    let summary = runtime::run_multi_collection(
        &mut bpf,
        &mut target_tids,
        &mut runtime::NoPendingCleanup,
        &mut known_tids,
        &initial_tids,
        runtime::MultiCollectionOptions {
            pid,
            duration: args.duration,
            mode: COLLECT_NET,
            tick_interval: RECONCILE_INTERVAL,
            poll_interval: runtime::DEFAULT_POLL_INTERVAL,
        },
        runtime::MultiStreams {
            streams: vec![
                runtime::EventStream::of::<TcpEvent, _>(
                    "NET_EVENTS",
                    PERF_PAGE_COUNT,
                    SharedStats(Rc::clone(&stats)),
                ),
                runtime::EventStream::of::<ConnEvent, _>(
                    "CONN_EVENTS",
                    runtime::DEFAULT_PERF_PAGE_COUNT,
                    SharedStats(Rc::clone(&stats)),
                ),
            ],
            on_tick: Some(Box::new(move |_at, _summary| {
                reconcile.borrow_mut().reconcile();
                tick_started.elapsed()
            })),
            on_progress: None,
        },
    )?;
    // The tick callback reconciled during the final drain; reading once more
    // makes the verification use the newest descriptor table.
    collector.borrow_mut().reconcile();
    let mut stats = std::mem::take(&mut *stats.borrow_mut());
    // The tick callback is dropped when the collection returns, so this is
    // the only remaining reference.
    let collector = match Rc::try_unwrap(collector) {
        Ok(cell) => cell.into_inner(),
        Err(_) => anyhow::bail!("TCP ownership is still borrowed after collection"),
    };
    let mut collector = collector;
    let counters = collector.counters();
    let unverified = stats.retain_verified(&collector);
    let report = NetReport::new(&stats, &collector, &counters, unverified, &summary);

    if args.format.format == Format::Text {
        print_text(pid, &process_name, summary.elapsed, &report);
    } else {
        json::emit(
            args.format.format,
            &Envelope::new(
                "net",
                pid,
                Some(process_name),
                summary.elapsed,
                summary.interrupted,
                summary.process_exited,
                crate::json_payloads::network_json(&report),
            )
            .with_v2(),
        );
    }
    Ok(())
}

/// Everything the report needs, gathered so the text and JSON renderers read
/// the same numbers.
pub struct NetReport<'a> {
    /// Per-connection aggregation.
    pub stats: &'a NetStats,
    /// Ownership state and evidence counts, absent for a report built
    /// without a collector (unit tests of the document shape).
    collector: Option<&'a TcpCollector>,
    /// Kernel-side attribution counters.
    pub counters: &'a crate::tcp::TcpCounters,
    /// Endpoints dropped because no evidence corroborated them.
    pub unverified: u64,
    /// Whether attribution is possible at all.
    pub available: bool,
    /// Why it is not, when it is not.
    pub reason: Option<String>,
    /// Wall time the measurements were collected over.
    pub elapsed: Duration,
    /// Whether a client handshake was measured.
    pub connect_available: bool,
    /// Why not, when not.
    pub connect_reason: Option<String>,
}

impl<'a> NetReport<'a> {
    /// Gathers the numbers both renderers read.
    pub fn new(
        stats: &'a NetStats,
        collector: &'a TcpCollector,
        counters: &'a crate::tcp::TcpCounters,
        unverified: u64,
        summary: &runtime::CollectionSummary,
    ) -> NetReport<'a> {
        let reason = collector.unavailable_reason().map(str::to_owned);
        // Availability is about evidence, not traffic: a target that holds no TCP
        // socket is measured, with a sample count of zero.
        let available = reason.is_none();
        let connect_available = stats.connects() > 0;
        let connect_reason = if connect_available {
            None
        } else if stats.connect_failures() > 0 {
            Some("no handshake completed: every connect failed".to_string())
        } else if reason.is_some() {
            reason.clone()
        } else if stats.endpoints_len() == 0 {
            Some("no owned TCP connection was observed".to_string())
        } else {
            Some("no client handshake was observed; accepted sockets and pre-existing connections have no measurable start".to_string())
        };
        NetReport {
            stats,
            collector: Some(collector),
            counters,
            unverified,
            elapsed: summary.elapsed,
            available,
            reason,
            connect_available,
            connect_reason,
        }
    }
}

/// Whether the report can publish RTT and retransmission measurements.
impl<'a> NetReport<'a> {
    /// Builds a report with no ownership evidence, for document tests.
    #[cfg(test)]
    pub fn for_test(
        stats: &'a NetStats,
        counters: &'a crate::tcp::TcpCounters,
        elapsed: Duration,
    ) -> NetReport<'a> {
        Self {
            stats,
            collector: None,
            counters,
            unverified: 0,
            elapsed,
            available: false,
            reason: Some("no ownership evidence".to_string()),
            connect_available: false,
            connect_reason: Some("no handshake measured".to_string()),
        }
    }

    /// Connections removed because the target stopped holding the socket.
    pub fn excluded(&self) -> u64 {
        self.collector.map_or(0, TcpCollector::excluded)
    }

    /// Listener addresses that could not be attributed.
    pub fn ambiguous_listeners(&self) -> usize {
        self.collector.map_or(0, TcpCollector::ambiguous_listeners)
    }

    /// Whether the target's socket table corroborated this connection.
    pub fn is_verified(&self, key: &TcpKey) -> bool {
        self.collector
            .is_some_and(|collector| collector.is_verified(key))
    }

    /// Human-readable attribution summary line.
    pub fn attribution_line(&self) -> String {
        if let Some(reason) = &self.reason {
            return format!("TCP attribution: unavailable ({reason})");
        }
        format!(
            "TCP attribution: verified ({} endpoint(s), {} excluded, {} ambiguous listener(s), {} event(s) from connections this run could not attribute)",
            self.stats.endpoints_len(),
            self.excluded() + self.unverified,
            self.ambiguous_listeners(),
            self.counters.unmatched_rtt + self.counters.unmatched_retrans
        )
    }

    /// Whether the target listens on `port`.
    pub fn is_listener_port(&self, port: u16) -> bool {
        self.collector
            .is_some_and(|collector| collector.is_listener_port(port))
    }
}

fn print_text(pid: u32, process_name: &str, elapsed: Duration, report: &NetReport<'_>) {
    println!("PID: {process_name} ({pid})");
    println!("Duration: {}", humantime::format_duration(elapsed));
    println!("{}", report.attribution_line());
    if report.available {
        println!("Samples: {}", report.stats.samples());
        println!("Retransmissions: {}", report.stats.retrans());
    } else {
        println!("Samples: unavailable");
        println!("Retransmissions: unavailable");
    }
    println!("Lost events: {}", report.stats.lost());
    println!(
        "Attribution counters: {} owner record(s), {} dropped, {} closed; RTT {} matched, {} rate-limited, {} unattributed; retransmissions {} matched, {} unattributed; handshakes {} tracked, {} established, {} failed",
        report.counters.inserted,
        report.counters.drops,
        report.counters.removed,
        report.counters.matched_rtt,
        report.counters.rate_limited,
        report.counters.unmatched_rtt,
        report.counters.matched_retrans,
        report.counters.unmatched_retrans,
        report.counters.pending_inserted,
        report.counters.pending_established,
        report.counters.pending_failed,
    );
    println!();

    let ranked = report.stats.slowest_endpoints();
    if ranked.is_empty() {
        println!("Endpoints");
        println!("No attributed TCP connections.");
        return;
    }

    println!(
        "Slowest connections by RTT p95 ({} of {} shown)",
        ranked.len().min(MAX_REPORTED_ENDPOINTS),
        ranked.len()
    );
    println!(
        "  {:>8} {:>8} {:>8} {:>8} {:>8}  endpoint",
        "p95", "p50", "p99", "samples", "retrans"
    );
    for endpoint in ranked.iter().take(MAX_REPORTED_ENDPOINTS) {
        let (p50, p95, p99) = endpoint.rtt_percentiles();
        println!(
            "  {p95:>8} {p50:>8} {p99:>8} {:>8} {:>8}  {}",
            endpoint.rtts.len(),
            endpoint.retrans,
            format_endpoint(endpoint),
        );
    }
    if ranked.len() > MAX_REPORTED_ENDPOINTS {
        println!(
            "  ... {} more connection(s) not shown",
            ranked.len() - MAX_REPORTED_ENDPOINTS
        );
    }

    let worst = ranked[0];
    let (_, worst_p95, _) = worst.rtt_percentiles();
    println!();
    println!("Slowest connection");
    println!("  {} us p95 RTT", worst_p95);
    println!("  {}", format_endpoint(worst));
    println!("  {} retransmissions", worst.retrans);
    println!(
        "  congestion window {} segments, receive window {} bytes",
        worst.max_cwnd, worst.max_rcv_wnd
    );

    println!();
    match report.connect_available {
        true => {
            let (p50, p95, p99) = report.stats.connect_percentiles();
            println!(
                "Connection setup: {} attempt(s), {} failed",
                report.stats.connects() + report.stats.connect_failures(),
                report.stats.connect_failures()
            );
            println!("  p95 {p95} us, p50 {p50} us, p99 {p99} us (connect to established)");
            for endpoint in report
                .stats
                .slowest_connects()
                .iter()
                .take(MAX_REPORTED_ENDPOINTS)
            {
                let (_, endpoint_p95, _) = endpoint.connect_percentiles();
                println!(
                    "  {endpoint_p95:>8} us p95  {}  ({} connect(s))",
                    format_endpoint(endpoint),
                    endpoint.connects
                );
            }
        }
        false => println!(
            "Connection setup: unavailable ({})",
            report.connect_reason.as_deref().unwrap_or("no measurement")
        ),
    }
    println!();
    println!("Retransmission ratio: unavailable (no transmitted-segment denominator)");
}

#[cfg(test)]
mod tests {
    use super::*;
    use fast_common::AF_INET;

    fn v4(last: u8) -> [u8; 16] {
        let mut address = [0u8; 16];
        address[..4].copy_from_slice(&[10, 0, 0, last]);
        address
    }

    fn probe(daddr: u8, rtt_us: u32) -> TcpEvent {
        TcpEvent {
            tid: 0,
            family: AF_INET,
            retrans: 0,
            _pad: 0,
            sport: 1234,
            dport: 80,
            rtt_us,
            snd_cwnd: 10,
            rcv_wnd: 4096,
            saddr: v4(1),
            daddr: v4(daddr),
        }
    }

    fn retrans(daddr: u8) -> TcpEvent {
        TcpEvent {
            retrans: 1,
            ..probe(daddr, 0)
        }
    }

    #[test]
    fn groups_samples_per_connection() {
        let mut stats = NetStats::default();
        stats.record(probe(2, 100));
        stats.record(probe(2, 300));
        stats.record(probe(3, 200));
        let ranked = stats.slowest_endpoints();
        assert_eq!(ranked.len(), 2);
        assert_eq!(format_endpoint(ranked[0]), "10.0.0.1:1234 -> 10.0.0.2:80");
        assert_eq!(format_endpoint(ranked[1]), "10.0.0.1:1234 -> 10.0.0.3:80");
        assert_eq!(ranked[0].rtts.len(), 2);
    }

    #[test]
    fn a_five_tuple_is_the_connection_identity() {
        // Two connections to the same remote are two rows, because the local
        // port differs; one connection keeps its samples together.
        let mut stats = NetStats::default();
        stats.record(probe(2, 100));
        stats.record(TcpEvent {
            sport: 4321,
            ..probe(2, 100)
        });
        stats.record(TcpEvent {
            sport: 4321,
            ..probe(2, 200)
        });
        let ranked = stats.slowest_endpoints();
        assert_eq!(ranked.len(), 2);
        assert_eq!(ranked[0].rtts.len(), 2);
        assert_eq!(ranked[1].rtts.len(), 1);
    }

    #[test]
    fn ranking_is_stable_for_equal_latency() {
        let mut stats = NetStats::default();
        for daddr in [10, 9, 8] {
            stats.record(probe(daddr, 100));
        }
        let first = format_endpoint(stats.slowest_endpoints()[0]);
        assert_eq!(first, "10.0.0.1:1234 -> 10.0.0.10:80");
        assert_eq!(first, format_endpoint(stats.slowest_endpoints()[0]));
    }

    #[test]
    fn counts_retransmissions_per_connection() {
        let mut stats = NetStats::default();
        stats.record(probe(1, 100));
        stats.record(retrans(1));
        assert_eq!(stats.retrans(), 1);
        let endpoint = &stats.slowest_endpoints()[0];
        assert_eq!(endpoint.retrans, 1);
        assert_eq!(endpoint.rtts.len(), 1);
    }

    #[test]
    fn separates_ipv4_from_ipv6_endpoints() {
        let mut stats = NetStats::default();
        stats.record(probe(1, 100));
        let mut v6 = [0u8; 16];
        v6[0] = 0x20;
        v6[1] = 0x01;
        stats.record(TcpEvent {
            family: fast_common::AF_INET6,
            saddr: v6,
            daddr: v6,
            ..probe(1, 100)
        });
        assert_eq!(stats.slowest_endpoints().len(), 2);
    }

    #[test]
    fn tracks_highest_windows_seen() {
        let mut stats = NetStats::default();
        stats.record(probe(1, 100));
        stats.record(TcpEvent {
            snd_cwnd: 24,
            rcv_wnd: 65535,
            ..probe(1, 120)
        });
        let endpoint = &stats.slowest_endpoints()[0];
        assert_eq!(endpoint.max_cwnd, 24);
        assert_eq!(endpoint.max_rcv_wnd, 65535);
    }

    #[test]
    fn formats_ipv6_endpoint() {
        let mut v6 = [0u8; 16];
        v6[0] = 0x20;
        v6[1] = 0x01;
        v6[2] = 0x0d;
        v6[3] = 0xb8;
        v6[15] = 0x01;
        let endpoint = Endpoint {
            key: TcpKey::new(fast_common::AF_INET6, v6, 443, v6, 51000),
            ..Endpoint::default()
        };
        assert_eq!(
            format_endpoint(&endpoint),
            "2001:db8::1:443 -> 2001:db8::1:51000"
        );
    }

    #[test]
    fn handshakes_rank_separately_from_rtt() {
        let mut stats = NetStats::default();
        stats.record(probe(1, 50));
        stats.record(probe(2, 900));
        stats.record_conn(ConnEvent {
            family: AF_INET,
            sport: 1234,
            dport: 80,
            result: TCP_CONNECT_ESTABLISHED,
            _pad: 0,
            latency_us: 1_500,
            saddr: v4(1),
            daddr: v4(1),
        });
        let by_rtt = stats.slowest_endpoints();
        assert_eq!(format_endpoint(by_rtt[0]), "10.0.0.1:1234 -> 10.0.0.2:80");
        let by_connect = stats.slowest_connects();
        assert_eq!(by_connect.len(), 1);
        assert_eq!(by_connect[0].connect_us, vec![1_500]);
        assert_eq!(stats.connects(), 1);
    }

    #[test]
    fn failed_handshakes_are_counted_and_never_ranked() {
        let mut stats = NetStats::default();
        stats.record_conn(ConnEvent {
            family: AF_INET,
            sport: 1234,
            dport: 9,
            result: fast_common::TCP_CONNECT_FAILED,
            _pad: 0,
            latency_us: 12,
            saddr: v4(1),
            daddr: v4(3),
        });
        assert_eq!(stats.connect_failures(), 1);
        assert_eq!(stats.connects(), 0);
        assert!(stats.slowest_connects().is_empty());
        assert_eq!(stats.endpoints_len(), 1);
    }

    #[test]
    fn retransmissions_per_second_uses_the_collection_window() {
        let mut stats = NetStats::default();
        stats.record(retrans(2));
        stats.record(retrans(2));
        let endpoint = &stats.slowest_endpoints()[0];
        assert_eq!(endpoint.retrans_per_second(Duration::from_secs(2)), 1.0);
        assert_eq!(endpoint.retrans_per_second(Duration::ZERO), 0.0);
    }
}
