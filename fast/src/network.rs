use std::collections::{BTreeMap, BTreeSet};

use anyhow::{Context, Result};
use aya::{Ebpf, include_bytes_aligned};
use fast_common::{AF_INET, COLLECT_NET, TcpEvent};

use crate::{cli::NetArgs, process, runtime};

/// RTT samples arrive at roughly the rate the socket sends and receives data.
/// 64 pages (256 KiB) per CPU keeps event loss low.
const PERF_PAGE_COUNT: usize = 64;

/// How many rows the endpoint table prints before truncating. A busy process
/// can hold hundreds of connections, and a table nobody scrolls is better
/// than one that buries its first line.
const MAX_REPORTED_ENDPOINTS: usize = 10;

/// Identity of a connection: address family, both addresses, both ports.
///
/// Kept as a plain tuple so `BTreeMap` can order endpoints, which gives the
/// report a deterministic order across runs.
type EndpointKey = (u16, [u8; 16], [u8; 16], u16, u16);

/// One remote endpoint observed during a run.
#[derive(Debug, Default, Clone)]
pub struct Endpoint {
    /// Address family, [`fast_common::AF_INET`] or [`fast_common::AF_INET6`].
    pub family: u16,
    /// Source address in network byte order.
    pub saddr: [u8; 16],
    /// Destination address in network byte order.
    pub daddr: [u8; 16],
    /// Source port, host byte order.
    pub sport: u16,
    /// Destination port, host byte order.
    pub dport: u16,
    /// Smoothed RTT samples in microseconds, one per `tcp_probe` event.
    pub rtts: Vec<u32>,
    /// Number of retransmissions attributed to this endpoint.
    pub retrans: u64,
    /// Highest congestion window in segments seen on this endpoint.
    pub max_cwnd: u32,
    /// Highest receive window in bytes seen on this endpoint.
    pub max_rcv_wnd: u32,
}

impl Endpoint {
    fn key(event: &TcpEvent) -> EndpointKey {
        (
            event.family,
            event.saddr,
            event.daddr,
            event.sport,
            event.dport,
        )
    }

    fn new(event: &TcpEvent) -> Self {
        Self {
            family: event.family,
            saddr: event.saddr,
            daddr: event.daddr,
            sport: event.sport,
            dport: event.dport,
            rtts: Vec::new(),
            retrans: 0,
            max_cwnd: event.snd_cwnd,
            max_rcv_wnd: event.rcv_wnd,
        }
    }

    /// Total number of observed segments: RTT samples plus retransmissions.
    pub fn segments(&self) -> u64 {
        self.rtts.len() as u64 + self.retrans
    }

    /// Retransmissions as a fraction of observed segments, from 0.0 to 1.0.
    pub fn retrans_ratio(&self) -> f64 {
        let total = self.segments();
        if total == 0 {
            return 0.0;
        }
        self.retrans as f64 / total as f64
    }

    /// p50, p95 and p99 of this endpoint's RTT samples, in microseconds.
    pub fn rtt_percentiles(&self) -> (u32, u32, u32) {
        crate::stats::percentiles_us(&self.rtts)
    }

    /// Key used to rank endpoints by how slow they are.
    ///
    /// p95 is the ranking signal because a single slow tail is what makes a
    /// connection the reason a request felt slow, and p95 is far steadier
    /// than a maximum over a short run. The endpoint label breaks ties so
    /// the ordering is deterministic between runs.
    fn slowness(&self) -> (u32, EndpointKey) {
        let (_, p95, _) = self.rtt_percentiles();
        (
            p95,
            (self.family, self.saddr, self.daddr, self.sport, self.dport),
        )
    }
}

/// Aggregates TCP events per endpoint.
#[derive(Debug, Default)]
pub struct NetStats {
    endpoints: BTreeMap<EndpointKey, Endpoint>,
    retrans: u64,
    samples: u64,
    lost: u64,
}

impl NetStats {
    fn record(&mut self, event: TcpEvent) {
        let is_retrans = event.retrans != 0;
        if is_retrans {
            self.retrans += 1;
        } else {
            self.samples += 1;
        }

        let entry = self
            .endpoints
            .entry(Endpoint::key(&event))
            .or_insert_with(|| Endpoint::new(&event));
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

    fn record_lost(&mut self, count: u64) {
        self.lost = self.lost.saturating_add(count);
    }

    /// Endpoints ordered from slowest to fastest by RTT p95.
    ///
    /// This is the ranking the report leads with, so that the endpoint most
    /// worth looking at comes first rather than whichever one the map
    /// happened to yield.
    pub fn slowest_endpoints(&self) -> Vec<&Endpoint> {
        let mut ordered: Vec<&Endpoint> = self.endpoints.values().collect();
        ordered.sort_by_key(|endpoint| std::cmp::Reverse(endpoint.slowness()));
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
}

impl runtime::EventHandler<TcpEvent> for NetStats {
    fn on_event(&mut self, event: TcpEvent) {
        self.record(event);
    }

    fn on_lost(&mut self, count: u64) {
        self.record_lost(count);
    }
}

/// Formats an address from an event as a printable string.
///
/// IPv4 renders in dotted-quad form. IPv6 renders as eight groups without
/// zero compression, which keeps the output stable and easy to compare
/// between runs.
pub fn format_address(family: u16, address: [u8; 16]) -> String {
    if family == AF_INET {
        return format!(
            "{}.{}.{}.{}",
            address[0], address[1], address[2], address[3]
        );
    }
    let mut out = String::with_capacity(39);
    for group in 0..8 {
        if group != 0 {
            out.push(':');
        }
        let high = u16::from_be_bytes([address[group * 2], address[group * 2 + 1]]);
        out.push_str(&format!("{high:x}"));
    }
    out
}

/// Renders an endpoint as `address:port -> address:port`.
pub fn format_endpoint(endpoint: &Endpoint) -> String {
    format!(
        "{}:{} -> {}:{}",
        format_address(endpoint.family, endpoint.saddr),
        endpoint.sport,
        format_address(endpoint.family, endpoint.daddr),
        endpoint.dport
    )
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
    // Both programs share the NET_EVENTS map and the TCP_SOCKETS map, so the
    // retransmission program can attribute an event to a socket the RTT
    // program first saw. tcp_probe must be attached as well: it is what
    // populates TCP_SOCKETS.
    runtime::attach_tracepoint(&mut bpf, "tcp", "tcp_probe")?;
    runtime::attach_tracepoint(&mut bpf, "tcp", "tcp_retransmit_skb")?;

    let mut target_tids = runtime::take_target_map(&mut bpf)?;

    let mut known_tids = BTreeSet::new();
    let mut stats = NetStats::default();
    let summary = runtime::run_collection(
        &mut bpf,
        &mut target_tids,
        &mut runtime::NoPendingCleanup,
        &mut known_tids,
        &initial_tids,
        &mut stats,
        runtime::CollectionOptions {
            pid,
            duration: args.duration,
            events_map: "NET_EVENTS",
            perf_page_count: PERF_PAGE_COUNT,
            mode: COLLECT_NET,
        },
    )?;

    println!("PID: {process_name} ({pid})");
    println!("Duration: {}", humantime::format_duration(summary.elapsed));
    if summary.interrupted {
        println!("Status: interrupted");
    }
    println!("Samples: {}", stats.samples());
    println!("Retransmissions: {}", stats.retrans());
    println!("Lost events: {}", stats.lost());
    println!();

    let ranked = stats.slowest_endpoints();
    if ranked.is_empty() {
        println!("Endpoints");
        println!("No TCP samples collected.");
        println!("Test with: fast-workload net-hog --duration 30s   (then observe its PID)");
        return Ok(());
    }

    // The table leads with the slowest endpoint so the connection worth
    // looking at is the first thing on screen. All latencies are in
    // microseconds, and the ratio is retransmissions over observed segments.
    println!(
        "Slow endpoints by RTT p95 ({} of {} shown)",
        ranked.len().min(MAX_REPORTED_ENDPOINTS),
        ranked.len()
    );
    println!(
        "  {:>8} {:>8} {:>8} {:>8} {:>8} {:>7}  endpoint",
        "p95", "p50", "p99", "samples", "retrans", "ratio"
    );
    for endpoint in ranked.iter().take(MAX_REPORTED_ENDPOINTS) {
        let (p50, p95, p99) = endpoint.rtt_percentiles();
        println!(
            "  {p95:>8} {p50:>8} {p99:>8} {:>8} {:>8} {:>6.1}%  {}",
            endpoint.rtts.len(),
            endpoint.retrans,
            endpoint.retrans_ratio() * 100.0,
            format_endpoint(endpoint),
        );
    }
    if ranked.len() > MAX_REPORTED_ENDPOINTS {
        println!(
            "  ... {} more endpoint(s) not shown",
            ranked.len() - MAX_REPORTED_ENDPOINTS
        );
    }

    // The worst offender is called out on its own, because a table row is
    // easy to skim past and this is the answer to "which remote is slow".
    let worst = ranked[0];
    let (_, worst_p95, _) = worst.rtt_percentiles();
    println!();
    println!("Slowest endpoint");
    println!("  {} us p95", worst_p95);
    println!("  {}", format_endpoint(worst));
    if worst.retrans > 0 {
        println!(
            "  {} retransmissions, {:.1}% of {} observed segments",
            worst.retrans,
            worst.retrans_ratio() * 100.0,
            worst.segments()
        );
    }
    // A closed congestion window with retransmissions on top is what a
    // struggling path looks like, so both are always named here.
    println!(
        "  congestion window {} segments, receive window {} bytes",
        worst.max_cwnd, worst.max_rcv_wnd
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn probe(family: u16, saddr: [u8; 16], daddr: [u8; 16], rtt: u32) -> TcpEvent {
        TcpEvent {
            tid: 1,
            family,
            retrans: 0,
            _pad: 0,
            sport: 1234,
            dport: 80,
            rtt_us: rtt,
            snd_cwnd: 10,
            rcv_wnd: 0,
            saddr,
            daddr,
        }
    }

    fn retrans(family: u16, saddr: [u8; 16], daddr: [u8; 16]) -> TcpEvent {
        TcpEvent {
            retrans: 1,
            ..probe(family, saddr, daddr, 0)
        }
    }

    fn v4(a: u8, b: u8, c: u8, d: u8) -> [u8; 16] {
        let mut out = [0u8; 16];
        out[..4].copy_from_slice(&[a, b, c, d]);
        out
    }

    #[test]
    fn groups_samples_per_endpoint() {
        let mut s = NetStats::default();
        s.record(probe(AF_INET, v4(127, 0, 0, 1), v4(10, 0, 0, 1), 100));
        s.record(probe(AF_INET, v4(127, 0, 0, 1), v4(10, 0, 0, 1), 300));
        s.record(probe(AF_INET, v4(127, 0, 0, 1), v4(10, 0, 0, 2), 200));

        assert_eq!(s.samples(), 3);
        assert_eq!(s.slowest_endpoints().len(), 2);
        // Endpoints are ordered by their key, so the 10.0.0.1 connection
        // comes first and holds both of its samples.
        let first = &s.slowest_endpoints()[0];
        assert_eq!(first.rtts.len(), 2);
        assert_eq!(format_endpoint(first), "127.0.0.1:1234 -> 10.0.0.1:80");
        assert_eq!(s.slowest_endpoints()[1].rtts.len(), 1);
    }

    #[test]
    fn ignores_zero_rtt_samples_but_keeps_the_endpoint() {
        let mut s = NetStats::default();
        // A fresh connection has no smoothed RTT yet.
        s.record(probe(AF_INET, v4(127, 0, 0, 1), v4(10, 0, 0, 1), 0));
        assert_eq!(s.samples(), 1);
        assert_eq!(s.slowest_endpoints().len(), 1);
        assert!(s.slowest_endpoints()[0].rtts.is_empty());
    }

    #[test]
    fn ranks_endpoints_slowest_first() {
        let mut s = NetStats::default();
        // A fast endpoint and a slow one, each with a steady distribution.
        for rtt in [40, 40, 40] {
            s.record(probe(AF_INET, v4(127, 0, 0, 1), v4(10, 0, 0, 1), rtt));
        }
        for rtt in [900, 900, 900] {
            s.record(probe(AF_INET, v4(127, 0, 0, 1), v4(10, 0, 0, 2), rtt));
        }
        // A middle endpoint, added last, to prove the order is by latency
        // and not by insertion or by address.
        for rtt in [200, 200, 200] {
            s.record(probe(AF_INET, v4(127, 0, 0, 1), v4(10, 0, 0, 3), rtt));
        }

        let ranked = s.slowest_endpoints();
        assert_eq!(ranked.len(), 3);
        assert_eq!(format_endpoint(ranked[0]), "127.0.0.1:1234 -> 10.0.0.2:80");
        assert_eq!(format_endpoint(ranked[1]), "127.0.0.1:1234 -> 10.0.0.3:80");
        assert_eq!(format_endpoint(ranked[2]), "127.0.0.1:1234 -> 10.0.0.1:80");
    }

    #[test]
    fn computes_retrans_ratio() {
        let mut s = NetStats::default();
        for _ in 0..3 {
            s.record(probe(AF_INET, v4(127, 0, 0, 1), v4(10, 0, 0, 1), 100));
        }
        s.record(retrans(AF_INET, v4(127, 0, 0, 1), v4(10, 0, 0, 1)));

        let endpoint = &s.slowest_endpoints()[0];
        assert_eq!(endpoint.segments(), 4);
        assert!((endpoint.retrans_ratio() - 0.25).abs() < 1e-9);
    }

    #[test]
    fn retrans_ratio_is_zero_without_segments() {
        let endpoint = Endpoint {
            family: AF_INET,
            saddr: v4(127, 0, 0, 1),
            daddr: v4(10, 0, 0, 1),
            sport: 1,
            dport: 2,
            rtts: Vec::new(),
            retrans: 0,
            max_cwnd: 0,
            max_rcv_wnd: 0,
        };
        assert_eq!(endpoint.segments(), 0);
        assert_eq!(endpoint.retrans_ratio(), 0.0);
    }

    #[test]
    fn ranking_is_stable_for_equal_latency() {
        let mut s = NetStats::default();
        for daddr in [10, 9, 8] {
            s.record(probe(AF_INET, v4(127, 0, 0, 1), v4(10, 0, 0, daddr), 100));
        }
        // Equal latency falls back to the endpoint key, in descending order,
        // so two reports generated from the same events read identically.
        let first = format_endpoint(s.slowest_endpoints()[0]);
        assert_eq!(first, "127.0.0.1:1234 -> 10.0.0.10:80");
        assert_eq!(first, format_endpoint(s.slowest_endpoints()[0]));
    }

    #[test]
    fn counts_retransmissions_per_endpoint() {
        let mut s = NetStats::default();
        s.record(probe(AF_INET, v4(127, 0, 0, 1), v4(10, 0, 0, 1), 100));
        s.record(retrans(AF_INET, v4(127, 0, 0, 1), v4(10, 0, 0, 1)));

        assert_eq!(s.retrans(), 1);
        let endpoint = &s.slowest_endpoints()[0];
        assert_eq!(endpoint.retrans, 1);
        // The sample and the retransmission belong to the same connection.
        assert_eq!(endpoint.rtts.len(), 1);
    }

    #[test]
    fn separates_ipv4_from_ipv6_endpoints() {
        let mut s = NetStats::default();
        let mut v6 = [0u8; 16];
        v6[0] = 0x20;
        v6[1] = 0x01;
        s.record(probe(AF_INET, v4(127, 0, 0, 1), v4(10, 0, 0, 1), 100));
        s.record(probe(fast_common::AF_INET6, v6, v6, 100));
        assert_eq!(s.slowest_endpoints().len(), 2);
    }

    #[test]
    fn tracks_highest_windows_seen() {
        let mut s = NetStats::default();
        s.record(probe(AF_INET, v4(127, 0, 0, 1), v4(10, 0, 0, 1), 100));
        s.record(TcpEvent {
            snd_cwnd: 24,
            rcv_wnd: 65535,
            ..probe(AF_INET, v4(127, 0, 0, 1), v4(10, 0, 0, 1), 120)
        });
        let endpoint = &s.slowest_endpoints()[0];
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
            family: fast_common::AF_INET6,
            saddr: v6,
            daddr: v6,
            sport: 443,
            dport: 51000,
            rtts: Vec::new(),
            retrans: 0,
            max_cwnd: 0,
            max_rcv_wnd: 0,
        };
        assert_eq!(
            format_endpoint(&endpoint),
            "2001:db8:0:0:0:0:0:1:443 -> 2001:db8:0:0:0:0:0:1:51000"
        );
    }
}
