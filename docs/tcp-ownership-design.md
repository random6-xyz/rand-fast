# TCP ownership and lifecycle attribution

Status: implemented. This document is the design behind `fast net`,
`fast diagnose` and the daemon's TCP signals. It states what is measured, what
evidence an attribution rests on, and where the measurement stops being
possible.

## The problem

The kernel tracepoints that carry TCP measurements (`tcp_probe`,
`tcp_retransmit_skb`, `sock:inet_sock_set_state`) fire for every socket on the
host, and they do not run in a predictable task context:

- `tcp_probe` runs on the receive path and can run in softirq context, where
  the current task is whatever was interrupted, not the socket's user.
- A socket address (`skaddr`) is a kernel pointer. It is reused after
  `sk_free`, so a remembered pointer says nothing about who owns the socket
  now.
- A socket cookie identifies a socket, not a process, and does not survive a
  descriptor being passed to another process.
- The 6.1 and 6.6 `tcp_probe` payload has no `skaddr` at all.

An earlier implementation attributed events to whichever target thread was
current, or to a pointer remembered from an earlier event. Both are guesses,
and a wrong attribution is worse than an unavailable measurement, so the
feature was disabled rather than shipped.

## What attribution rests on now

Two kinds of evidence, joined by one key:

| Evidence | Where it comes from | What it proves |
| --- | --- | --- |
| Creation | `sock:inet_sock_set_state` with the target's own thread group as the current task, at `TCP_SYN_SENT` (client) or `TCP_LISTEN` (server) | The target started this connection, or listens on this address |
| Possession | `/proc/<pid>/fd` joined with `/proc/<pid>/net/tcp{,6}` by inode | The target holds a descriptor for this socket right now, whether or not this run saw it created |

The key is the connection's **5-tuple** (`family`, source address, source
port, destination address, destination port), never a pointer. Two live
sockets cannot share a tuple in a network namespace, and the record is removed
when the socket reaches `TCP_CLOSE`, so a reused address cannot inherit an old
owner.

The descriptor evidence is what makes a report usable on a process that is
already running: a server that started before collection has no creation
events, but it does hold its listening socket and its accepted connections.
Those are seeded at startup and reconciled once a second while the run
continues.

### Ownership rules in full

- **Client connection**: a `TCP_SYN_SENT` transition whose current thread
  group is the target. The kernel assigns the local port *after* that
  transition, so the handshake is tracked by socket address until
  `TCP_ESTABLISHED`, where the full tuple is recorded. The pointer is a
  correlation handle between two events of one live socket, never ownership
  evidence; the recorded remote endpoint is checked again at establishment, so
  a recycled address cannot produce a latency sample for an unrelated
  connection.
- **Accepted connection**: the connection's local port matches a listener the
  target owns, either because the kernel saw the target call `listen` or
  because the target holds the listening descriptor.
- **Pre-existing connection**: presence in the target's descriptor table.
  Reported with `origin: "seeded"` so a reader can tell it apart from a
  connection this run saw created.
- **Ambiguous listener**: when two sockets in the namespace bind the same
  address, an accepted connection on it belongs to neither process provably.
  The address is recorded as ambiguous and its connections are never
  attributed.
- **Shared or transferred descriptor**: a socket the target no longer holds is
  removed at the next reconcile. If the connection is still in the namespace's
  socket table, it left the process and is counted in `excluded_endpoints`.
  A socket both processes still hold is attributed to the process that created
  it; the report says "creator plus current holder", which is the strongest
  claim the evidence supports.
- **Threads only**: fork and exec create new thread groups. A child process's
  sockets are outside the observed process, which matches the tool's scope.

### Verification at report time

The kernel keys ownership by tuple, which is not scoped to a network
namespace. Every endpoint is therefore checked once more before it is
published: it must either have produced a creation event in this run or appear
in the target's own socket table. Endpoints that fail the check are dropped
and counted in `unverified_endpoints`.

## Measurement

| Signal | Source | Unit | Sampling |
| --- | --- | --- | --- |
| RTT | `tcp_probe`, `srtt >> 3` | µs | at most one sample per connection per 10 ms |
| Retransmission | `tcp_retransmit_skb` | count, /s | every event |
| Connection setup | `TCP_SYN_SENT` → `TCP_ESTABLISHED` | µs | every client handshake |
| Failed connect | `TCP_SYN_SENT` → `TCP_CLOSE` before establishing | count | every attempt |

The RTT interval is what keeps a busy connection from flooding the perf
buffer. The report says "samples", not "packets", and `Samples` is the number
of attributed samples after that limit.

The server side of a handshake is not measurable: the kernel sets a child
socket's initial `TCP_SYN_RECV` state directly instead of going through
`inet_sock_set_state`, so there is no observable start. Accepted sockets have
RTT and retransmissions, and their connection latency is reported as
unavailable with that reason rather than guessed at.

`retrans_ratio` stays null. The tracepoints carry no transmitted-segment
denominator, and dividing a retransmission count by a receive-side event count
would be a number that means nothing. The report gives the count and the
per-second rate instead; a rate over the collection window is a real
measurement, a ratio without a denominator is not.

## Kernel objects

| Object | Type | Bound | Purpose |
| --- | --- | --- | --- |
| `TCP_OWNERS` | hash map, tuple → owner | 8192 | verified owners; a full map drops new records instead of evicting an owner |
| `TCP_LISTENERS` | hash map, address → owner | 512 | listeners, including the ambiguous ones |
| `TCP_PENDING_CONNECTS` | LRU hash map, address → handshake | 1024 | pairs `TCP_SYN_SENT` with `TCP_ESTABLISHED` |
| `TCP_OWNER_STATS` | per-CPU counters | 12 | attribution outcomes, summed by userspace |
| `NET_EVENTS`, `CONN_EVENTS` | perf arrays | 64 pages/CPU, 8 pages/CPU | RTT/retransmission samples, handshake outcomes |

Cost: one map lookup per TCP state change in the namespace (to invalidate a
record on close and to attribute accepted connections), one lookup plus a
counter per measurement event, and one map insert per connect/accept. A busy
host costs a few percent of one CPU in the softirq path even when the target
is idle; that is the price of not guessing, and it is measured by the
benchmark gate.

## Unavailable behavior

TCP attribution is unavailable, with an explicit reason, when:

- the running kernel's tracepoint layout does not match the verified fixtures
  (the collector refuses to start rather than misread a payload);
- the target's descriptor table or socket table cannot be read (permissions,
  or a target that exited mid-run);
- the target holds no TCP socket at all — that is *available with zero
  samples*, not unavailable, because it is a real reading.

In every other case a null measurement means "not measured", never zero. The
daemon refuses to fire `--trigger-retrans` when attribution is unavailable and
says so at startup.

## Verification

`tools/qemu-smoke.sh` runs `check_tcp_ownership` inside the real-kernel guest:

- attribution and exclusion: the target's own endpoints are published, an
  unrelated process running the same fixture is never attributed, and a socket
  handed to a forked child over `SCM_RIGHTS` is counted as excluded;
- IPv6 endpoints, a reused 4-tuple, two failed connects, and a handshake
  delayed past a retransmission timeout (the listener's accept queue is
  starved for 200 ms, so the client's SYN is dropped and retried);
- the JSON, human, diagnose and daemon documents agree, and an incident is
  written from attributed retransmissions.

The layout fixtures in `fast/tests/fixtures/tracepoints` cover 6.1.191,
6.6.161, 6.12.105, 6.12.115, 7.2.0-rc6 and 7.2.15. All six carry the tuple and
state fields the collector consumes; `skaddr` is not required, which is why the
LTS kernels are supported.
