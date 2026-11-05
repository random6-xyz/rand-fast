# TCP ownership and lifecycle attribution

Status: design and proof-of-concept report. TCP reporting and triggers remain
disabled. This document is the deliverable for issue #71 and the prerequisite
for #72/#73; it does not claim that attribution is ready to enable.

## Why the current code reports nothing

`fast net`, `fast diagnose` and the daemon currently report
`tcp_available: false` and keep RTT/retransmission fields null. That is a
deliberate contract, not a missing feature.

The kernel tracepoints that carry TCP measurements do not carry a reliable
owner:

- `tcp_probe` and `tcp_retransmit_skb` can run in softirq context. The current
  task at that point is whatever was interrupted, not the task that owns the
  socket.
- A socket address (`skaddr`) is a kernel pointer. It can be freed and reused
  by a different process, so a remembered pointer alone proves nothing.
- A socket cookie identifies a socket, but not a process. It also does not
  survive descriptor passing as an ownership statement: the receiving process
  is not the creating or connecting task.
- The 6.1/6.6 `tcp_probe` payload has no `skaddr` at all, so those kernels have
  no per-socket key for RTT samples.

The previous implementation attributed a tracepoint event to whichever target
thread was current, or remembered a pointer after a target thread was seen on
it. That is exactly the unproven attribution this issue is about; it was
removed.

## Ownership evidence considered

The only points where the kernel has both a socket and the task that created
the relationship are:

| Event | Kernel hook | What it proves |
| --- | --- | --- |
| Client connect | `tcp_connect(struct sock *sk)` entry | This task called connect on this socket. |
| Server accept | `inet_csk_accept()` return | This task accepted this new socket. |
| Socket destruction | `sk_free(struct sock *sk)` | The address is about to become reusable; drop the record. |

A record is written only when the current thread group is the observed process.
The record is keyed by the socket address and removed at `sk_free`. The
tracepoint then requires a record for the exact address before emitting an
event; there is no fallback to the current task.

This gives the following safe and unsafe cases:

- Safe: a socket created by `connect`/`accept` in the target after attachment,
  with the target still alive, and the record not yet removed.
- Excluded: sockets that existed before attachment. They have no record and are
  never attributed.
- Excluded: sockets created by another process. Their record is never written.
- Excluded: a reused address after `sk_free`; the record is gone.
- Not proven: a socket created by the target and then passed to another
  process. The record still names the creator. This is creator attribution,
  not proof of the current user, and must be either detected (for example via
  file reference counts) or documented as a limitation before enabling.
- Not proven: sockets created by a forked child. The child's TGID differs, so
  its connects are not recorded; the target's pre-existing descriptors are
  excluded by the attachment rule.

## Prototype and observed result

A prototype added three kprobes (`tcp_connect`, `inet_csk_accept`,
`sk_free`) and a map from socket address to `{tgid, start_ns}`. The two TCP
tracepoints looked up that map only after validating the checked-in payload
layout, and `net` gained a hidden `--experimental-tcp` switch so the default
contract stayed unavailable.

The QEMU workload (7.2.0-rc6, KVM) exercised:

- a client that connects after attachment;
- a second, unrelated process connecting at the same time;
- a connection created before attachment;
- a stalled reader intended to induce retransmissions.

The prototype recorded the target's connect and accept sockets and correctly
excluded the unrelated process and the pre-existing connection. However, the
TCP tracepoint lookups for the recorded addresses did not match, so no
attributed sample was emitted. The experiment was stopped rather than shipping
an `available` report with zero samples or, worse, a guessed fallback. The
prototype code and its hidden flag were removed; the default path is unchanged.

This is the remaining blocker for #72/#73. Before enabling anything, the
prototype must be reduced to a minimal reproducer and the lookup failure
understood. Candidate explanations to test are map lifetime/instance sharing
between kprobe and tracepoint programs, the exact socket pointer carried by
`tcp_probe` on the tested kernel, and whether an accepted socket is the same
object the tracepoint reports. None of these may be guessed around with a
fallback.

## Required evidence before enabling (#72/#73)

1. A minimal kprobe-to-tracepoint map handoff that returns the recorded owner
   for a known socket, with the map instance and key verified independently.
2. RTT cross-checked against an independent source (`ss -ti` or the workload's
   own round-trip p50) on the supported kernels, with the scale documented.
3. An induced retransmission attributed to the same owned connection, and none
   attributed to an unrelated process.
4. Lifetime tests: pre-existing socket, close/reopen, address reuse, target
   exit, shared/transferred descriptor, IPv4 and IPv6.
5. Event-loss accounting and a bounded map policy when a target opens more
   sockets than the owner map can hold.
6. Explicit unavailable behavior for 6.1/6.6 (no `skaddr`), missing
   capabilities, and any ambiguous ownership case.

Connection latency (#73) additionally needs connect/accept timestamps from the
same proven records; RTT alone is not a connection-establishment metric.

## Feature detection and unavailable behavior

- RTT attribution requires a `tcp_probe` layout with `skaddr` (verified 6.12
  and 7.2 fixtures). On 6.1/6.6 the report must say why it is unavailable.
- Retransmission attribution requires `tcp_retransmit_skb` `skaddr` (present on
  all verified kernels) plus a proven owner record.
- Missing kprobe symbols, tracefs, BTF or capabilities produce an explicit
  unavailable line, never a zero measurement.
- Triggers (`--trigger-retrans`) stay disabled while attribution is
  unavailable; a configured trigger that cannot fire must remain visible and
  must not fabricate an incident.

## Cost and bounds

The kprobes do one map insert per connect/accept and one remove per socket
free; both are O(1) and run only in the target's context, except `sk_free`,
which runs for every socket but does only a map remove. The tracepoints do one
map lookup per event. The owner map is bounded; when full, new records are
dropped and those sockets are unattributed rather than evicting an unrelated
owner. The map holds only the socket address, TGID and start timestamp.

## Current product behavior

Until the evidence above exists:

- `fast net` prints `TCP attribution: unavailable (...)` and null samples.
- `fast diagnose` keeps `tcp_available: false` and null TCP evidence.
- The daemon keeps `tcp_available: false` and never fires the retransmission
  trigger.
- `tools/qemu-smoke.sh` keeps the TCP unavailable contract and the negative
  tests for unrelated and pre-existing connections.
