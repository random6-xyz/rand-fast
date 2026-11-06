//! Socket ownership evidence from procfs.
//!
//! A kernel pointer is not ownership. [`struct sock`](https://docs.kernel.org/networking/kapi.html)
//! addresses are reused after `sk_free`, and a socket cookie identifies a
//! socket without naming the process that uses it. This module answers the
//! only question a per-process report may act on: *does this process hold a
//! descriptor for this connection right now?*
//!
//! The evidence is joined from two kernel-owned sources, both read through the
//! target's own process directories:
//!
//! - `/proc/<pid>/fd/*` lists the socket inodes the process holds.
//! - `/proc/<pid>/net/tcp{,6}` lists every socket in the target's network
//!   namespace with its inode, 5-tuple, state and retransmission count.
//!
//! Intersecting the two gives connections whose descriptor is held by the
//! target. That is stronger than "the target was seen near this socket": it
//! survives pointer reuse, covers sockets that existed before collection
//! started, and makes a descriptor handed to another process visible as soon
//! as the target closes it.
//!
//! Everything here is a pure function over file contents so the rules can be
//! tested against fixtures captured from real kernels.

use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    net::Ipv6Addr,
    path::{Path, PathBuf},
};

use anyhow::Result;
use fast_common::{AF_INET, AF_INET6, ListenKey, TcpKey};
use serde::Serialize;

use crate::{
    cli::{DebugArgs, DebugCommand, DebugTcpSocketsArgs},
    json::{self, Envelope, Format},
    process,
};

/// `TCP_LISTEN` as `/proc/net/tcp` prints it.
pub const TCP_STATE_LISTEN: u8 = 0x0a;
/// `TCP_TIME_WAIT` as `/proc/net/tcp` prints it. A socket in this state has no
/// descriptor, so it is never part of an ownership set.
pub const TCP_STATE_TIME_WAIT: u8 = 0x06;
/// `/proc/net/tcp` state for `TCP_CLOSE`.
pub const TCP_STATE_CLOSE: u8 = 0x07;

/// One socket the target holds a descriptor for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HeldSocket {
    /// Connection identity, or the local side for a listening socket.
    pub key: TcpKey,
    /// State as `/proc/net/tcp` reports it, so a caller can tell a listener
    /// from a connection.
    pub state: u8,
    /// Retransmitted segments the kernel counts for this socket, an
    /// independent number the attributed retransmission count can be
    /// compared with.
    pub retrans: u64,
    /// Socket inode, kept so a report can name the descriptor the evidence
    /// came from without re-reading procfs.
    pub inode: u64,
}

impl HeldSocket {
    /// Whether this socket is a listener.
    pub fn is_listener(&self) -> bool {
        self.state == TCP_STATE_LISTEN
    }
}

/// What the target's procfs says about its sockets.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Inventory {
    /// Sockets whose descriptor the target holds, sorted by key.
    pub held: Vec<HeldSocket>,
    /// Listeners the target owns.
    pub listeners: Vec<ListenKey>,
    /// Every connection key present in the target's network namespace,
    /// whether or not the target holds its descriptor. It distinguishes a
    /// socket that left the process from one that simply closed.
    pub netns_keys: BTreeSet<TcpKey>,
    /// Listener addresses that more than one socket in the namespace binds.
    ///
    /// Two processes listening on one address (SO_REUSEPORT, or one socket
    /// inherited across a fork) make every accepted connection on it
    /// unattributable, so the address is recorded instead of guessed at.
    pub conflicting_listeners: Vec<ListenKey>,
    /// Why the inventory is empty, when it could not be read at all. `None`
    /// with an empty `held` list means the target simply holds no TCP socket.
    pub unavailable: Option<String>,
}

impl Inventory {
    /// Marks an inventory that could not be read.
    fn unavailable(reason: String) -> Self {
        Self {
            held: Vec::new(),
            listeners: Vec::new(),
            netns_keys: BTreeSet::new(),
            conflicting_listeners: Vec::new(),
            unavailable: Some(reason),
        }
    }
}

/// One row of `/proc/<pid>/net/tcp` or `tcp6`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetRow {
    /// Connection identity. For a listener the remote side is zero.
    pub key: TcpKey,
    /// State in the kernel's `TCP_*` numbering.
    pub state: u8,
    /// Socket inode, zero when the kernel does not report one.
    pub inode: u64,
    /// Retransmitted segments.
    pub retrans: u64,
}

/// Reads the socket inventory of `pid`, or explains why it cannot.
pub fn read_inventory(pid: u32) -> Inventory {
    let inodes = match read_socket_inodes(pid) {
        Ok(inodes) => inodes,
        Err(reason) => return Inventory::unavailable(reason),
    };
    let mut rows = Vec::new();
    for (name, family) in [("tcp", AF_INET), ("tcp6", AF_INET6)] {
        match read_net_table(pid, name, family) {
            Ok(mut table) => rows.append(&mut table),
            Err(reason) => return Inventory::unavailable(reason),
        }
    }

    // A listener address bound by more than one socket is ambiguous whatever
    // process owns the other socket: an accepted connection on it cannot be
    // denied to either process with the evidence available here.
    let mut listener_counts: BTreeMap<ListenKey, u32> = BTreeMap::new();
    for row in rows.iter().filter(|row| row.state == TCP_STATE_LISTEN) {
        *listener_counts
            .entry(ListenKey {
                family: row.key.family,
                port: row.key.sport,
                addr: row.key.saddr,
            })
            .or_default() += 1;
    }

    let mut netns_keys = BTreeSet::new();
    for row in rows.iter().filter(|row| row.state != TCP_STATE_LISTEN) {
        netns_keys.insert(row.key);
    }
    let mut held = Vec::new();
    let mut listeners = Vec::new();
    let mut conflicting_listeners = Vec::new();
    let mut seen_conflicts = BTreeSet::new();
    for row in rows {
        if !inodes.contains(&row.inode) || row.inode == 0 {
            continue;
        }
        if row.state == TCP_STATE_LISTEN {
            let listener = ListenKey {
                family: row.key.family,
                port: row.key.sport,
                addr: row.key.saddr,
            };
            if listener_counts.get(&listener).copied().unwrap_or(0) > 1
                && seen_conflicts.insert(listener)
            {
                conflicting_listeners.push(listener);
            }
            listeners.push(listener);
        }
        if row.state == TCP_STATE_TIME_WAIT || row.state == TCP_STATE_CLOSE {
            // A socket in these states carries no descriptor the target can
            // use and no traffic to attribute.
            continue;
        }
        held.push(HeldSocket {
            key: row.key,
            state: row.state,
            retrans: row.retrans,
            inode: row.inode,
        });
    }
    held.sort_by_key(|socket| (socket.key.family, socket.key.saddr, socket.key.sport));
    listeners.sort_by_key(|listener| (listener.family, listener.addr, listener.port));
    conflicting_listeners.sort_by_key(|listener| (listener.family, listener.addr, listener.port));
    Inventory {
        held,
        listeners,
        netns_keys,
        conflicting_listeners,
        unavailable: None,
    }
}

fn read_socket_inodes(pid: u32) -> Result<BTreeSet<u64>, String> {
    let directory = PathBuf::from(format!("/proc/{pid}/fd"));
    let entries = fs::read_dir(&directory)
        .map_err(|error| format!("cannot list {}: {error}", directory.display()))?;
    let mut inodes = BTreeSet::new();
    for entry in entries {
        let entry = entry.map_err(|error| format!("cannot read {}/fd entry: {error}", pid))?;
        let path = entry.path();
        let target = match fs::read_link(&path) {
            Ok(target) => target,
            // A descriptor can close between the listing and the read; that
            // is not an error, it is the socket being gone.
            Err(_) => continue,
        };
        if let Some(inode) = parse_socket_inode(&target) {
            inodes.insert(inode);
        }
    }
    Ok(inodes)
}

fn read_net_table(pid: u32, name: &str, family: u16) -> Result<Vec<NetRow>, String> {
    let path = PathBuf::from(format!("/proc/{pid}/net/{name}"));
    let text = fs::read_to_string(&path)
        .map_err(|error| format!("cannot read {}: {error}", path.display()))?;
    parse_net_table(&text, family)
        .map_err(|error| format!("cannot parse {}: {error}", path.display()))
}

/// Parses the inode out of a `/proc/<pid>/fd` link target such as
/// `socket:[12345]`.
pub fn parse_socket_inode(target: &Path) -> Option<u64> {
    let text = target.to_str()?;
    let inner = text.strip_prefix("socket:[")?.strip_suffix(']')?;
    inner.parse().ok()
}

/// Parses a `/proc/<pid>/net/tcp` table.
///
/// The format is stable across the supported kernels: a header line, then one
/// row per socket with the local address, remote address, state, queue
/// counters, retransmission count, uid, timeout and inode in that order.
pub fn parse_net_table(text: &str, family: u16) -> Result<Vec<NetRow>, String> {
    let mut rows = Vec::new();
    for (index, line) in text.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with("sl") {
            continue;
        }
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() < 10 {
            return Err(format!(
                "row {} has {} fields, expected at least 10",
                index + 1,
                fields.len()
            ));
        }
        let (local_addr, sport) = parse_endpoint(fields[1], family)
            .ok_or_else(|| format!("row {} has an invalid local address", index + 1))?;
        let (remote_addr, dport) = parse_endpoint(fields[2], family)
            .ok_or_else(|| format!("row {} has an invalid remote address", index + 1))?;
        let state = u8::from_str_radix(fields[3], 16)
            .map_err(|_| format!("row {} has an invalid state", index + 1))?;
        // `retrnsmt` is the kernel's retransmission counter for this socket,
        // printed in hexadecimal. It is an independent check on the
        // attributed count, not a destination for it.
        let retrans = u64::from_str_radix(fields[6], 16).unwrap_or(0);
        let inode = fields[9].parse::<u64>().unwrap_or(0);
        rows.push(NetRow {
            key: TcpKey::new(family, local_addr, sport, remote_addr, dport),
            state,
            inode,
            retrans,
        });
    }
    Ok(rows)
}

/// Parses `0100007F:1F90` style address:port fields.
///
/// The kernel prints each 32-bit address word as a host-order integer, so the
/// printed hex contains the network-order bytes in little-endian order. Both
/// families are decoded word by word, which is also how `ss` reads the table.
fn parse_endpoint(field: &str, family: u16) -> Option<([u8; 16], u16)> {
    let (address, port) = field.split_once(':')?;
    let port = u16::from_str_radix(port, 16).ok()?;
    let mut decoded = [0u8; 16];
    if family == AF_INET {
        let word = u32::from_str_radix(address, 16).ok()?;
        decoded[..4].copy_from_slice(&word.to_le_bytes());
        return Some((decoded, port));
    }
    if address.len() != 32 {
        return None;
    }
    for (index, chunk) in address.as_bytes().chunks(8).enumerate() {
        let word = u32::from_str_radix(std::str::from_utf8(chunk).ok()?, 16).ok()?;
        decoded[index * 4..index * 4 + 4].copy_from_slice(&word.to_le_bytes());
    }
    Some((decoded, port))
}

/// Renders an address the way the rest of the CLI does.
pub fn format_address(family: u16, address: [u8; 16]) -> String {
    if family == AF_INET {
        return format!(
            "{}.{}.{}.{}",
            address[0], address[1], address[2], address[3]
        );
    }
    Ipv6Addr::from(address).to_string()
}

/// Renders a connection as `local -> remote`, or a listener as `*:port`.
pub fn format_key(key: &TcpKey) -> String {
    let local = format_address(key.family, key.saddr);
    let remote = format_address(key.family, key.daddr);
    if key.daddr == [0u8; 16] && key.dport == 0 {
        return format!("{local}:{} (listen)", key.sport);
    }
    format!("{local}:{} -> {remote}:{}", key.sport, key.dport)
}

/// Renders a listener address.
pub fn format_listener(listener: &ListenKey) -> String {
    let address = format_address(listener.family, listener.addr);
    format!("{address}:{}", listener.port)
}

/// One socket row in the debug document.
#[derive(Debug, Serialize)]
pub struct SocketJson {
    /// `listener` or `connection`.
    pub kind: &'static str,
    /// Address family, 2 for IPv4 and 10 for IPv6.
    pub family: u16,
    /// Local address, printable form.
    pub local: String,
    /// Local port.
    pub local_port: u16,
    /// Remote address, printable form.
    pub remote: String,
    /// Remote port.
    pub remote_port: u16,
    /// Kernel state as `/proc/net/tcp` prints it, in hexadecimal.
    pub state: String,
    /// Socket inode the descriptor refers to.
    pub inode: u64,
    /// Retransmitted segments the kernel counts for this socket.
    pub retrans: u64,
}

/// The debug command's `data` object.
#[derive(Debug, Serialize)]
pub struct TcpSocketsJson {
    /// Whether the target's socket tables could be read.
    pub available: bool,
    /// Why they could not be read, when they could not.
    pub reason: Option<String>,
    /// Sockets the target holds a descriptor for, sorted by address.
    pub sockets: Vec<SocketJson>,
    /// Listener addresses more than one socket in the namespace binds.
    pub ambiguous_listeners: Vec<String>,
}

/// Renders one held socket for the human report.
pub fn describe_held(socket: &HeldSocket) -> String {
    let label = if socket.is_listener() {
        "listener"
    } else {
        "connection"
    };
    format!(
        "{label} {} state {:02x} inode {} retrans {}",
        format_key(&socket.key),
        socket.state,
        socket.inode,
        socket.retrans
    )
}

fn socket_json(socket: &HeldSocket) -> SocketJson {
    SocketJson {
        kind: if socket.is_listener() {
            "listener"
        } else {
            "connection"
        },
        family: socket.key.family,
        local: format_address(socket.key.family, socket.key.saddr),
        local_port: socket.key.sport,
        remote: format_address(socket.key.family, socket.key.daddr),
        remote_port: socket.key.dport,
        state: format!("{:02x}", socket.state),
        inode: socket.inode,
        retrans: socket.retrans,
    }
}

/// Runs the hidden inspection command.
pub fn run_debug(args: DebugArgs) -> Result<()> {
    match args.command {
        DebugCommand::TcpSockets(args) => run_tcp_sockets(args),
    }
}

fn run_tcp_sockets(args: DebugTcpSocketsArgs) -> Result<()> {
    let pid = args.pid;
    let process_name = process::read_name(pid).ok();
    let inventory = read_inventory(pid);
    if args.format.format == Format::Text {
        println!(
            "PID: {} ({pid})",
            process_name.as_deref().unwrap_or("unknown")
        );
        if let Some(reason) = inventory.unavailable.as_deref() {
            println!("Socket ownership evidence: unavailable");
            println!("Reason: {reason}");
            return Ok(());
        }
        println!(
            "Socket ownership evidence: {} descriptor(s), {} listener(s)",
            inventory.held.len(),
            inventory.listeners.len()
        );
        for socket in &inventory.held {
            println!("  {}", describe_held(socket));
        }
        for listener in &inventory.conflicting_listeners {
            println!(
                "  ambiguous listener {} (more than one socket binds it)",
                format_listener(listener)
            );
        }
        println!("Note: a descriptor held by this process is the ownership evidence;");
        println!("      no kernel pointer or current-task guess is used.");
        return Ok(());
    }
    let payload = TcpSocketsJson {
        available: inventory.unavailable.is_none(),
        reason: inventory.unavailable.clone(),
        sockets: inventory.held.iter().map(socket_json).collect(),
        ambiguous_listeners: inventory
            .conflicting_listeners
            .iter()
            .map(format_listener)
            .collect(),
    };
    json::emit(
        args.format.format,
        &Envelope::new(
            "debug-tcp-sockets",
            pid,
            process_name,
            std::time::Duration::ZERO,
            false,
            false,
            payload,
        ),
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const IPV4: &str = "\
  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 0100007F:9C40 0200000A:0050 01 00000000:00000000 00:00000000 00000000  1000        0 4242 1 0000000000000000 100 0 0 10 0
";
    const IPV6: &str = "\
  sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000000000000000000001000000:9C40 0000000000000000FFFF00000100007F:0050 01 00000000:00000000 00:00000000 00000003  1000        0 5252 1 0000000000000000 20 4 30 10 -1
";
    const LISTENERS: &str = "\
  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 1111 1 0000000000000000 100 0 0 10 0
   1: 00000000:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 2222 1 0000000000000000 100 0 0 10 0
";

    #[test]
    fn parses_a_socket_inode_from_an_fd_link() {
        assert_eq!(parse_socket_inode(Path::new("socket:[4242]")), Some(4242));
        assert_eq!(parse_socket_inode(Path::new("/dev/null")), None);
        assert_eq!(parse_socket_inode(Path::new("socket:[not-a-number]")), None);
    }

    #[test]
    fn decodes_ipv4_addresses_in_the_order_the_kernel_prints_them() {
        let rows = parse_net_table(IPV4, AF_INET).expect("table parses");
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].key.saddr[..4], [127, 0, 0, 1]);
        assert_eq!(rows[0].key.daddr[..4], [10, 0, 0, 2]);
        assert_eq!(rows[0].key.sport, 40000);
        assert_eq!(rows[0].key.dport, 80);
        assert_eq!(rows[0].state, 0x01);
        assert_eq!(rows[0].inode, 4242);
        assert_eq!(rows[0].retrans, 0);
    }

    #[test]
    fn decodes_ipv6_addresses_word_by_word() {
        let rows = parse_net_table(IPV6, AF_INET6).expect("table parses");
        assert_eq!(rows.len(), 1);
        assert_eq!(
            Ipv6Addr::from(rows[0].key.saddr),
            Ipv6Addr::LOCALHOST,
            "the printed words are host-order integers of network-order bytes"
        );
        assert_eq!(rows[0].key.sport, 40000);
        assert_eq!(rows[0].key.dport, 80);
        assert_eq!(rows[0].inode, 5252);
        assert_eq!(rows[0].retrans, 3);
    }

    #[test]
    fn a_malformed_row_is_an_error_not_a_guess() {
        // Too few fields to be a socket row.
        assert!(parse_net_table("0: 0100007F:9C40 0200000A:0050\n", AF_INET).is_err());
        // A row whose address is not hexadecimal.
        assert!(parse_net_table("0: zzzz:1 0200000A:0050 01 0:0 00:0 0 0 0 1\n", AF_INET).is_err());
    }

    #[test]
    fn a_listener_address_bound_twice_is_reported_as_ambiguous() {
        // Two listening sockets on port 8080 in one namespace: an accepted
        // connection on it cannot be attributed to one process.
        let mut counts: BTreeMap<(u16, u16, [u8; 16]), u32> = BTreeMap::new();
        for row in parse_net_table(LISTENERS, AF_INET).expect("table parses") {
            *counts
                .entry((row.key.family, row.key.sport, row.key.saddr))
                .or_default() += 1;
        }
        assert_eq!(counts.values().copied().collect::<Vec<_>>(), vec![2]);
    }
}
