# TCP attribution unavailable

TCP RTT and retransmission attribution is disabled. The verified kernel invokes
`tcp_probe` from `tcp_rcv_established`, including receive processing in softirq
context. The current task can be unrelated to the socket. The retransmission
tracepoint contains a socket pointer but no socket cookie. A pointer can be
reused after destruction, and even a cookie would not establish process or
thread ownership, including for shared or transferred sockets. Neither the
current task nor a remembered pointer is proof of ownership.

The TCP tracepoint programs emit no events, and the application does not attach
them. The number of omitted events cannot be counted per target without the
very attribution that is unavailable; perf buffer loss does not include those
omissions. `net` reports `tcp_available: false` in JSON and an unavailable notice
in text. Diagnose marks TCP unavailable and does not score packet loss, while
independently measured off-CPU socket waits may still contribute to a network
cause. Daemon interval and incident JSON reports `retrans: null` and
`tcp_available: false`; the retransmission trigger cannot fire. Previously
recorded retransmission counts are not reliable and are not re-emitted as
measurements. `net`, `diagnose`, `daemon`, and daemon incident documents use `rand-fast/v2`:
net samples and retransmissions, diagnose TCP samples and retransmission ratio,
and daemon interval retransmissions are null when unavailable. Other commands
continue to use v1. Consumers must migrate these commands to v2 and handle
null values; v1 incident history remains readable, but its unreliable TCP
counts are never re-emitted as measurements.

Restoring attribution requires a verified ownership acquisition path and a
socket lifetime identity that covers sharing, process exit, destruction, and
reuse. The existing tracepoint layouts do not provide that proof.

The source regression test asserts that both TCP programs are unconditional
no-ops, the event map is never referenced outside its declaration, and none
of the three commands attaches either program. Because no TCP event can be
emitted for any pointer, context, or socket lifetime, destruction, address
reuse, sharing, and task exit cannot change an attribution. This is a proof of
the disabled path, not a kernel lifecycle simulation; any future ownership
collector must add real lifecycle and reuse tests before enabling attribution.
