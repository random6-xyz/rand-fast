//! The userspace half of TCP ownership.
//!
//! The eBPF programs record owners for connections created in the target's own
//! context. Sockets that already existed when collection started have no such
//! event, so this module seeds their records from procfs and reconciles them
//! while collection runs:
//!
//! - a connection whose descriptor is still held is (re)seeded, which covers
//!   listeners inherited across `exec` and connections opened before attach;
//! - a descriptor the target no longer holds is removed, so a socket passed to
//!   another process stops being attributed instead of keeping a stale owner;
//! - a listener address bound twice is poisoned, because an accepted
//!   connection on it belongs to neither process provably.
//!
//! Removing a record resets measurement for that connection: the kernel stops
//! emitting its events, and the report shows what was measured while the
//! target held it.

use std::collections::{BTreeMap, BTreeSet};

use anyhow::Context;
use aya::{
    Ebpf,
    maps::{Array as AyaArray, HashMap as AyaHashMap, MapData, PerCpuArray},
};
use fast_common::{
    ListenKey, ListenOwner, TCP_LISTENER_AMBIGUOUS, TCP_ORIGIN_SEEDED, TCP_ROLE_CLIENT,
    TCP_ROLE_SERVER, TCP_STAT_COUNT, TcpKey, TcpOwner,
};

use crate::tcp_ownership::{Inventory, read_inventory};

/// Ownership counters, summed over per-CPU slots.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct TcpCounters {
    /// Owner records written by the kernel.
    pub inserted: u64,
    /// Owner records the kernel could not write because the map was full.
    pub drops: u64,
    /// Owner records removed when a socket closed.
    pub removed: u64,
    /// RTT samples attributed to a verified owner.
    pub matched_rtt: u64,
    /// RTT samples dropped because no owner was known.
    pub unmatched_rtt: u64,
    /// Retransmissions attributed to a verified owner.
    pub matched_retrans: u64,
    /// Retransmissions dropped because no owner was known.
    pub unmatched_retrans: u64,
    /// RTT samples suppressed by the per-connection sampling interval.
    pub rate_limited: u64,
    /// Listener addresses seen with more than one owner.
    pub ambiguous_listeners: u64,
    /// Client handshakes the kernel started tracking.
    pub pending_inserted: u64,
    /// Handshakes that reached `TCP_ESTABLISHED`.
    pub pending_established: u64,
    /// Handshakes that closed before establishing.
    pub pending_failed: u64,
}

/// Owns the eBPF maps that describe socket ownership.
pub struct TcpCollector {
    tgid: u32,
    owners: AyaHashMap<MapData, TcpKey, TcpOwner>,
    listeners: AyaHashMap<MapData, ListenKey, ListenOwner>,
    stats: PerCpuArray<MapData, u64>,
    /// Records this module seeded, so they can be removed again. Records the
    /// kernel created are removed by the kernel on `TCP_CLOSE`.
    seeded: BTreeMap<TcpKey, u64>,
    seeded_listeners: BTreeSet<ListenKey>,
    ambiguous_listeners: BTreeSet<ListenKey>,
    /// Connection keys confirmed by a procfs read during this run, kept for
    /// the report even after the connection closes.
    verified: BTreeSet<TcpKey>,
    /// Connections the target held at the previous reconcile.
    previously_held: BTreeSet<TcpKey>,
    /// Listener ports the target owns, used to label a connection's role.
    listener_ports: BTreeSet<u16>,
    /// Connections removed because the target stopped holding them.
    excluded: u64,
    /// Why ownership cannot be established, when procfs cannot be read.
    unavailable: Option<String>,
    /// Reads that failed after the first successful one. A transient failure
    /// does not switch attribution off; the last inventory stays in force.
    pub reconcile_failures: u64,
    inventory: Inventory,
}

impl TcpCollector {
    /// Takes the ownership maps out of a loaded eBPF object and points the
    /// kernel at `pid` as the owning thread group.
    pub fn new(bpf: &mut Ebpf, pid: u32) -> anyhow::Result<Self> {
        let owners = bpf
            .take_map("TCP_OWNERS")
            .context("eBPF map TCP_OWNERS is missing")?;
        let owners: AyaHashMap<MapData, TcpKey, TcpOwner> = owners
            .try_into()
            .context("TCP_OWNERS has an unexpected map type or layout")?;
        let listeners = bpf
            .take_map("TCP_LISTENERS")
            .context("eBPF map TCP_LISTENERS is missing")?;
        let listeners: AyaHashMap<MapData, ListenKey, ListenOwner> = listeners
            .try_into()
            .context("TCP_LISTENERS has an unexpected map type or layout")?;
        let stats = bpf
            .take_map("TCP_OWNER_STATS")
            .context("eBPF map TCP_OWNER_STATS is missing")?;
        let stats: PerCpuArray<MapData, u64> = stats
            .try_into()
            .context("TCP_OWNER_STATS has an unexpected map type or layout")?;
        let target = bpf
            .take_map("TARGET_TGID")
            .context("eBPF map TARGET_TGID is missing")?;
        let mut target: AyaArray<MapData, u32> = target
            .try_into()
            .context("TARGET_TGID has an unexpected map type or layout")?;
        target
            .set(0, pid, 0)
            .context("failed to record the target thread group")?;
        Ok(Self {
            tgid: pid,
            owners,
            listeners,
            stats,
            seeded: BTreeMap::new(),
            seeded_listeners: BTreeSet::new(),
            ambiguous_listeners: BTreeSet::new(),
            verified: BTreeSet::new(),
            previously_held: BTreeSet::new(),
            listener_ports: BTreeSet::new(),
            excluded: 0,
            unavailable: None,
            reconcile_failures: 0,
            inventory: Inventory::default(),
        })
    }

    /// Re-reads the target's sockets and brings the kernel records in line.
    pub fn reconcile(&mut self) {
        let inventory = read_inventory(self.tgid);
        if let Some(reason) = inventory.unavailable.clone() {
            if self.unavailable.is_none() {
                self.unavailable = Some(reason);
            } else {
                self.reconcile_failures = self.reconcile_failures.saturating_add(1);
            }
            return;
        }
        self.unavailable = None;
        self.seed(&inventory);
        self.retire_missing(&inventory);
        self.inventory = inventory;
    }

    fn seed(&mut self, inventory: &Inventory) {
        for listener in &inventory.listeners {
            self.listener_ports.insert(listener.port);
        }
        for listener in &inventory.conflicting_listeners {
            self.listener_ports.insert(listener.port);
            if self.ambiguous_listeners.insert(*listener) {
                let owner = ListenOwner {
                    tgid: 0,
                    ambiguous: TCP_LISTENER_AMBIGUOUS,
                    _pad: [0; 3],
                };
                let _ = self.listeners.insert(*listener, owner, 0);
            }
        }
        for listener in &inventory.listeners {
            let conflicting = self.ambiguous_listeners.contains(listener);
            if conflicting {
                continue;
            }
            if self.seeded_listeners.insert(*listener) {
                let owner = ListenOwner {
                    tgid: self.tgid,
                    ambiguous: 0,
                    _pad: [0; 3],
                };
                let _ = self.listeners.insert(*listener, owner, 0);
            }
        }
        for socket in &inventory.held {
            self.verified.insert(socket.key);
            if socket.is_listener() {
                continue;
            }
            if self.seeded.contains_key(&socket.key) {
                continue;
            }
            // A record created by the kernel carries stronger evidence than a
            // descriptor observation, so it is never overwritten.
            if self.owners.get(&socket.key, 0).is_ok() {
                continue;
            }
            let role = if self.listener_ports.contains(&socket.key.dport) {
                TCP_ROLE_SERVER
            } else {
                TCP_ROLE_CLIENT
            };
            let owner = TcpOwner {
                tgid: self.tgid,
                role,
                origin: TCP_ORIGIN_SEEDED,
                awaiting: 0,
                _pad: 0,
                start_ns: 0,
                last_sample_ns: 0,
                listener_port: if role == TCP_ROLE_SERVER {
                    socket.key.dport
                } else {
                    0
                },
                _pad2: [0; 6],
            };
            if self.owners.insert(socket.key, owner, 0).is_ok() {
                self.seeded.insert(socket.key, socket.inode);
            }
        }
    }

    fn retire_missing(&mut self, inventory: &Inventory) {
        let held: BTreeSet<TcpKey> = inventory
            .held
            .iter()
            .filter(|socket| !socket.is_listener())
            .map(|socket| socket.key)
            .collect();
        let gone: Vec<TcpKey> = self
            .previously_held
            .iter()
            .copied()
            .filter(|key| !held.contains(key))
            .collect();
        for key in gone {
            self.seeded.remove(&key);
            let had_record = self.owners.remove(&key).is_ok();
            // A key that is still in the namespace's socket table but no
            // longer in the target's descriptor table left the process: it was
            // passed to another process or shared with it. A key that is gone
            // from both simply closed, which is not an exclusion.
            if had_record && inventory.netns_keys.contains(&key) {
                self.excluded = self.excluded.saturating_add(1);
            }
        }
        self.previously_held = held;
        let held_listeners: BTreeSet<ListenKey> = inventory.listeners.iter().copied().collect();
        let gone: Vec<ListenKey> = self
            .seeded_listeners
            .iter()
            .copied()
            .filter(|listener| !held_listeners.contains(listener))
            .collect();
        for listener in gone {
            self.seeded_listeners.remove(&listener);
            let _ = self.listeners.remove(&listener);
        }
    }

    /// Reads and sums the per-CPU counters.
    pub fn counters(&mut self) -> TcpCounters {
        let mut total = TcpCounters::default();
        for index in 0..TCP_STAT_COUNT {
            let Ok(values) = self.stats.get(&index, 0) else {
                continue;
            };
            let sum: u64 = values.iter().copied().sum();
            match index {
                0 => total.inserted = sum,
                1 => total.drops = sum,
                2 => total.removed = sum,
                3 => total.matched_rtt = sum,
                4 => total.unmatched_rtt = sum,
                5 => total.matched_retrans = sum,
                6 => total.unmatched_retrans = sum,
                7 => total.rate_limited = sum,
                8 => total.ambiguous_listeners = sum,
                9 => total.pending_inserted = sum,
                10 => total.pending_established = sum,
                11 => total.pending_failed = sum,
                _ => {}
            }
        }
        total
    }

    /// Why ownership cannot be established at all, when it cannot.
    pub fn unavailable_reason(&self) -> Option<&str> {
        self.unavailable.as_deref()
    }

    /// Connections whose record was removed because the target stopped
    /// holding the descriptor.
    pub fn excluded(&self) -> u64 {
        self.excluded
    }

    /// Listener addresses that could not be attributed.
    pub fn ambiguous_listeners(&self) -> usize {
        self.ambiguous_listeners.len()
    }

    /// Whether the target listens on `port`, which is how an accepted
    /// connection is told apart from an outgoing one in the report.
    pub fn is_listener_port(&self, port: u16) -> bool {
        self.listener_ports.contains(&port)
    }

    /// Whether the target's own socket table corroborates this connection.
    pub fn is_verified(&self, key: &TcpKey) -> bool {
        self.verified.contains(key)
    }
}
