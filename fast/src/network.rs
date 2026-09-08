use std::{collections::BTreeMap, collections::BTreeSet, convert::TryInto};

use anyhow::{Context, Result};
use aya::{Ebpf, include_bytes_aligned, maps::HashMap as AyaHashMap, maps::MapData};
use fast_common::TcpEvent;

use crate::{cli::NetArgs, process, runtime};

/// Retransmission bursts can be chatty; 64 pages (256 KiB) per CPU keeps
/// event loss low.
const PERF_PAGE_COUNT: usize = 64;

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

impl runtime::EventHandler<TcpEvent> for NetStats {
    fn on_event(&mut self, event: TcpEvent) {
        self.record(event);
    }

    fn on_lost(&mut self, count: u64) {
        self.record_lost(count);
    }
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
    runtime::attach_tracepoint(&mut bpf, "tcp", "tcp_retransmit_skb")?;

    let mut target_tids = runtime::take_target_map(&mut bpf)?;
    let pending_map = bpf
        .take_map("PENDING_IO")
        .context("eBPF map PENDING_IO is missing")?;
    let mut pending_dummy: AyaHashMap<MapData, u32, u64> = pending_map
        .try_into()
        .context("PENDING_IO has an unexpected map type or layout")?;

    let mut known_tids = BTreeSet::new();
    let mut stats = NetStats::default();
    let summary = runtime::run_collection(
        &mut bpf,
        &mut target_tids,
        &mut pending_dummy,
        &mut known_tids,
        &initial_tids,
        &mut stats,
        runtime::CollectionOptions {
            pid,
            duration: args.duration,
            events_map: "NET_EVENTS",
            perf_page_count: PERF_PAGE_COUNT,
            mode: 0,
        },
    )?;

    println!("PID: {process_name} ({pid})");
    println!("Duration: {}", humantime::format_duration(summary.elapsed));
    if summary.interrupted {
        println!("Status: interrupted");
    }
    println!("Retransmissions: {}", stats.retrans);
    println!("Lost events: {}", stats.lost);
    println!();
    println!("Endpoints");
    if stats.by_endpoint.is_empty() {
        println!(
            "No TCP samples collected (no retransmissions or RTT >0). Test with: python3 -m http.server 8000 & curl http://127.0.0.1:8000/"
        );
        println!(
            "Local fixture: start a local server and generate traffic from the target process."
        );
    } else {
        for ((saddr, daddr, sport, dport), rtts) in &stats.by_endpoint {
            let avg = rtts.iter().map(|v| *v as u64).sum::<u64>() / rtts.len() as u64;
            println!(
                "{}:{} -> {}:{}  samples {} avg RTT {}µs",
                ip_to_str(*saddr),
                sport,
                ip_to_str(*daddr),
                dport,
                rtts.len(),
                avg
            );
        }
    }
    println!();
    println!(
        "Note: connection vs transfer vs retransmission delays are distinguished by RTT (transfer) and retrans flag."
    );
    Ok(())
}

fn ip_to_str(ip: u32) -> String {
    format!(
        "{}.{}.{}.{}",
        ip & 0xFF,
        (ip >> 8) & 0xFF,
        (ip >> 16) & 0xFF,
        (ip >> 24) & 0xFF
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn endpoint_aggregation() {
        let mut s = NetStats::default();
        s.record(TcpEvent {
            tid: 1,
            saddr: 0x0100007F,
            daddr: 0x0100007F,
            sport: 1234,
            dport: 80,
            rtt_us: 100,
            retrans: 0,
            _pad: [0; 3],
        });
        s.record(TcpEvent {
            tid: 1,
            saddr: 0x0100007F,
            daddr: 0x0100007F,
            sport: 1234,
            dport: 80,
            rtt_us: 200,
            retrans: 1,
            _pad: [0; 3],
        });
        assert_eq!(s.retrans, 1);
        assert_eq!(s.by_endpoint.len(), 1);
    }
}
