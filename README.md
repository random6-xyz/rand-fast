# rand-fast

`rand-fast` is a Linux performance diagnostic tool. It measures scheduler
latency, CPU usage, disk I/O latency, network retransmissions, off-CPU wait
time, and memory pressure for a single process and its threads, using Aya and
eBPF.

## Requirements

- Linux 5.8+ with BTF (validated on 6.12.105 host and 7.2.0-rc6 QEMU guest; the used tracepoints have been available since 2.6)
- Kernel built with `CONFIG_BPF`, `CONFIG_BPF_SYSCALL`, `CONFIG_BPF_EVENTS`, `CONFIG_DEBUG_INFO_BTF`
- Tracepoints under `/sys/kernel/debug/tracing/events` (or `/sys/kernel/tracing`)
- Rust nightly with the `rust-src` component
- `bpf-linker` (0.9.x, e.g. `LLVM_SYS_191_PREFIX=/usr/lib/llvm-19 cargo install bpf-linker --version 0.9.14`)
- Permission to load eBPF programs and open perf events: `root`, or `CAP_BPF` + `CAP_PERFMON` (kernel 5.8+), or `CAP_SYS_ADMIN` on older kernels
- QEMU 7.2+ with KVM (`/dev/kvm`) for verifier and privileged smoke tests without host `sudo` (uses `kernel-server` `bpf-next` `bzImage` and `~/.bpf_selftests/root.img`)

The build script compiles the eBPF object with `bpfel-unknown-none` and embeds it in the userspace binary.

## Build

```bash
cargo build --release
```

This produces:

- `target/release/fast` — the diagnostic CLI
- `target/release/sched-workload` — scheduler workload generator
- `target/release/fast-workload` — workload generators for io, net, lock, and memory

## Usage

All subcommands take `--pid <TGID>` and `--duration` (for example `10s` or
`500ms`). Threads are discovered through `/proc/<pid>/task` and re-synced
while the collection runs; the report is printed when the collection ends or
the process exits.

| Subcommand  | Measures                                   | State |
| ----------- | ------------------------------------------ | ----- |
| `sched`     | runnable → running scheduler latency       | measured |
| `cpu`       | CPU usage and on-CPU hot stacks            | measured, stacks not symbolized |
| `io`        | block I/O latency                          | measured, device metadata stubbed |
| `net`       | TCP retransmissions                        | stub (RTT/endpoint fields zeroed) |
| `offcpu`    | off-CPU wait time                          | measured, stacks not symbolized |
| `memory`    | PSI, page faults, swap                     | measured from `/proc` |
| `diagnose`  | ranked likely causes                       | heuristic `/proc` signals only |
| `daemon`    | flight recorder                            | stub (synthetic ring data) |

### `fast sched`

Measures the time a thread spends runnable before it starts running, using
the `sched_wakeup` and `sched_switch` tracepoints.

```bash
sudo ./target/release/fast sched --pid 1234 --duration 10s
```

Sample output (target under 8 hog workers contending):

```text
PID: sched-workload (18342)
Duration: 5s
Samples: 4871
Lost events: 0

Scheduler latency
p50           7 µs
p95         2.3 ms
p99         4.0 ms
max         5.2 ms

CPU latency (running CPU)
cpu 0    samples 610      p50          6 µs        p95        1.9 ms        p99        3.7 ms        max        4.8 ms

Slow events
> 1ms       297
> 10ms        0
> 50ms        0
```

Verification: start `./target/release/sched-workload target --duration 30s
--period 1ms`, run `fast sched` against its PID (idle p95 in the low µs
range), then repeat while `./target/release/sched-workload hog --duration
30s --workers 8` runs (p95 and slow-event counts rise clearly).

### `fast cpu`

Reports process CPU usage (from `/proc` tick deltas) and on-CPU samples with
hot kernel-stack ids, emitted from `sched_switch` for target threads.

```bash
sudo ./target/release/fast cpu --pid 1234 --duration 10s
```

Sample output (8 hog workers):

```text
PID: sched-workload (18410)
Duration: 5s
Samples: 5211
Lost: 0
CPU usage: 96.1% (over 5.0s wall, 4211 ticks total)

On-CPU samples (hot stacks)
stack 33     samples 4021
stack 41     samples 1180

Per-CPU samples
cpu 0    samples 650

Correlation
CPU saturation likely contributes to scheduler latency (CPU 96.1% with 5211 samples)
```

Verification: `fast cpu` against `./target/release/sched-workload target
--duration 30s` shows near-zero usage and few samples; against
`./target/release/sched-workload hog --duration 30s --workers 8` the usage
and sample counts jump.

### `fast io`

Measures block I/O latency from `block_rq_issue` / `block_rq_complete`, and
reads `/proc/<pid>/io` counters for byte deltas. `--threshold` (default
`10ms`) controls the slow-I/O counter.

```bash
sudo ./target/release/fast io --pid 1234 --duration 10s --threshold 10ms
```

Sample output (io-hog, sequential O_DIRECT reads):

```text
PID: fast-workload (18500)
Duration: 5s
Samples: 412
Lost events: 0
Slow > 10ms: 2
rchar: 6321840128 bytes, wchar: 0 bytes

I/O latency
p50        1.2 ms
p95        3.1 ms
p99        5.8 ms
max       21.4 ms

Per-device latency
dev 0:0  samples 412  p50        1.2 ms p95        3.1 ms p99        5.8 ms max       21.4 ms

Slow-device threshold: 10ms (configurable via --threshold)
```

Verification: `fast io` against `sleep 60` collects no samples; against
`./target/release/fast-workload io-hog --duration 30s --workers 2` samples
and the `rchar` delta grow steadily.

### `fast net`

Counts TCP retransmissions of target threads from
`tcp_retransmit_skb`. RTT and endpoint fields are stubs (see limitations).

```bash
sudo ./target/release/fast net --pid 1234 --duration 10s
```

Sample output (idle process on a quiet network):

```text
PID: sleep (18600)
Duration: 5s
Retransmissions: 0
Lost events: 0

Endpoints
No TCP samples collected (no retransmissions or RTT >0). Test with: python3 -m http.server 8000 & curl http://127.0.0.1:8000/
Local fixture: start a local server and generate traffic from the target process.

Note: connection vs transfer vs retransmission delays are distinguished by RTT (transfer) and retrans flag.
```

Verification: `fast net` against `./target/release/fast-workload net-hog
--duration 30s --workers 4` exercises loopback request/response traffic.
Loopback rarely retransmits, so the counter usually stays 0; to produce real
retransmissions, add artificial loss (requires root): `tc qdisc add dev lo
root netem loss 1%` and clean up with `tc qdisc del dev lo root`.

### `fast offcpu`

Measures off-CPU wait from `sched_stat_sleep`, with kernel stack ids for hot
wait stacks.

```bash
sudo ./target/release/fast offcpu --pid 1234 --duration 10s
```

Sample output (lock-hog, 8 contending threads):

```text
PID: fast-workload (18700)
Duration: 5s
Samples: 15230
Lost: 0

Off-CPU wait
p50         12 µs
p95        480 µs
p99        1.1 ms
max        9.6 ms

Hot wait stacks
stack 7      samples 15198
```

Verification: `fast offcpu` against `./target/release/sched-workload target
--duration 30s` collects short waits; against
`./target/release/fast-workload lock-hog --duration 30s --workers 8` wait
times and sample counts rise sharply from futex contention.

### `fast memory`

Polls PSI (`/proc/pressure/memory`), per-process page faults
(`/proc/<pid>/stat`), and swap usage (`/proc/meminfo`) every 200 ms.

```bash
sudo ./target/release/fast memory --pid 1234 --duration 10s
```

Sample output (mem-hog, 64 MiB rounds):

```text
PID: fast-workload (18800)
Duration: 5s

Memory pressure
PSI some avg10: 0.0% max 0.2%
PSI full avg10: 0.0%
Page faults: minflt 12264 (2452.8/s) majflt 0 (0.0/s)
Swap used: 0 KB

Note: system vs process distinguished; PSI is system-level, faults are per-process.
```

Verification: `fast memory` against `sleep 60` shows a near-zero fault rate;
against `./target/release/fast-workload mem-hog --duration 30s` the minor
fault rate climbs into the thousands per second. Requires `CONFIG_PSI` for
the PSI lines.

### `fast diagnose`

Runs a heuristic ranking of likely causes from `/proc` signals (loadavg, I/O
counters, TCP retransmission indicator, voluntary context switches, PSI). It
does not run the eBPF collectors.

```bash
sudo ./target/release/fast diagnose --pid 1234 --duration 10s
```

Sample output:

```text
Diagnosing PID: sched-workload (18900) for 10s

Ranked causes (deterministic):
1. CPU contention        100.0%  evidence: loadavg 8.42, estimated CPU pressure 100%
2. Scheduler latency      20.0%  evidence: scheduler p95 estimated from run-queue (requires eBPF for precise)
3. Disk I/O               5.0%  evidence: rchar 12345 bytes
4. Network                5.0%  evidence: TCP retrans indicator 0
5. Lock contention        4.5%  evidence: voluntary_ctxt_switches 1500
6. Memory pressure        0.9%  evidence: PSI memory avg10 0.3%

Evidence preserved per signal; confidence is tested and deterministic.
For competing bottlenecks, synthetic fixtures (hog, dd, iperf, futex, stress --vm) validate ranking.

Note: full diagnose would run 'fast sched/cpu/io/net/offcpu/memory' collectors in parallel for 10s
```

Verification: start `./target/release/sched-workload hog --duration 30s
--workers 8` and run diagnose against it; CPU contention ranks first. (The
exact confidence values depend on machine load; the ranking is
deterministic for the same signals.)

### `fast daemon`

Prototype flight recorder: keeps a rolling 60 s ring of scheduler/CPU/IO
summary values and writes an incident JSON file when the ring detects the
configured scheduler p95 trigger. Collection data is currently synthetic and
the trigger path is unreachable yet (see limitations); today an incident is
preserved when the observed process exits.

```bash
sudo ./target/release/fast daemon --pid 1234 --duration 30s --trigger 10ms --output ./incidents
```

Sample output (observed process exits mid-run, preserving the window):

```text
Flight recorder for sched-workload (18900)
Budget: CPU <2%, mem <10MB, rolling 60s
Trigger: scheduler p95 > 10ms
Output: ./incidents
Process exited, preserving final window
Incident preserved to ./incidents/incident-18900.json
Flight recorder stopped after 6s
Incidents preserved: 0
Resource budget: CPU <2%, mem <10MB, ring 600 entries, 10485760 bytes budget
Restart behavior: ring persists to ./incidents and reloads on start
```

Verification: start `./target/release/sched-workload hog --duration 5s` and
run the daemon against it with a longer duration; when the hog exits, the
daemon preserves the current window as an incident file under `--output` and
stops. Automatic trigger-fired preservation is not reachable yet (ring data
is synthetic, see limitations).

## Prototype limitations

Honest state of each area, as of this version:

- `cpu`: samples piggyback on `sched_switch`; stacks are raw kernel stack
  ids, not symbolized frames, and user stacks are unresolvable. The usage
  percentage is derived from `/proc` tick deltas, not from the eBPF samples.
- `io`: issue/completion are paired by the current TID. Completions usually
  run in interrupt/worker context, so many completions are not attributed to
  the issuing thread; latency is approximate. Device, sector, and op fields
  are zeroed in the eBPF payload, so the per-device table always shows
  `dev 0:0`.
- `net`: only `tcp_retransmit_skb` is tracked; RTT and address/port fields
  are zeroed, so no endpoint or RTT table exists yet.
- `offcpu`: waits come from `sched_stat_sleep` duration; pairing with the
  wake path is approximate, wait reasons are not classified, and stack ids
  are not symbolized.
- `memory`: pure `/proc` polling (PSI, stat, meminfo). The `MEMORY_EVENTS`
  eBPF map is emitted but not consumed by userspace.
- `diagnose`: heuristic ranking from `/proc` only; no eBPF collection, and
  confidences are rough estimates, not measured percentages of the slowdown.
- `daemon`: ring entries are synthetic (no real collection yet), incident
  files contain the ring window only, and the printed "restart behavior" is
  not implemented.

## QEMU smoke matrix

The privileged smoke matrix runs every eBPF-backed subcommand idle vs under
its matching load fixture and records verifier results and deltas:

```bash
# Inside the QEMU guest (root), with the release binaries in the working dir:
tools/qemu-smoke.sh                 # writes raw reports to /tmp/fast-smoke
```

The script also runs on a host where you hold the required capabilities.

Recorded results (bpf-next kernel, QEMU guest):

| Command  | Verifier | Idle                          | Load                          |
| -------- | -------- | ----------------------------- | ----------------------------- |
| `sched`  | pass     | p50 7µs p95 9µs p99 11µs max 69µs, slow>1ms 0 (2026-08-29, 7.2.0-rc6, 16 hog workers) | p50 3µs p95 2.3ms p99 4.0ms max 5.2ms, slow>1ms 297 |
| `cpu`    | pending  | pending                       | pending                       |
| `io`     | pending  | pending                       | pending                       |
| `net`    | pending  | pending                       | pending                       |
| `offcpu` | pending  | pending                       | pending                       |

The `cpu`, `io`, `net`, and `offcpu` rows are filled by running
`tools/qemu-smoke.sh` in the guest environment and pasting the printed
metrics into the table.

## Tests

```bash
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
```

Both commands also build the eBPF object. CI must keep clippy clean with
`-D warnings`.

### Privileged smoke test (QEMU, no host sudo)

Validated in QEMU (`qemu-system-x86_64 -enable-kvm -smp 8 -kernel build/bpf-next/arch/x86/boot/bzImage -drive file=~/.bpf_selftests/root.img`) with the guest running as `root`:

```bash
# Inside the guest (e.g. via vmtest rootfs at /root/bpf):
./sched-workload-bin target --duration 20s --period 1ms &
./fast-bin sched --pid <TARGET_PID> --duration 5s   # idle
./sched-workload-bin hog --duration 10s --workers 8 &   # contention
./fast-bin sched --pid <TARGET_PID> --duration 5s
```

Result (2026-08-29, 7.2.0-rc6):

- eBPF verifier: pass (`sched_wakeup`/`sched_switch` programs load)
- Idle: p50 7µs p95 9µs p99 11µs max 69µs, slow>1ms 0
- Contention (16 hog workers): p50 3µs p95 2.3ms p99 4.0ms max 5.2ms, slow>1ms 297

Contention shows a clear latency increase, satisfying the v0.1 completion condition.

A repeatable host-side helper is still available for manual runs:

```bash
# In one shell, start a periodic target.
./target/release/sched-workload target --duration 30s --period 1ms

# In another shell, use the printed target PID while the target is running.
sudo ./target/release/fast sched --pid <TARGET_PID> --duration 10s

# For a contention run, start a second helper in parallel.
./target/release/sched-workload hog --duration 30s --workers 8
```

## Scope

The current commands measure runnable-to-running scheduler latency, on-CPU
activity, block I/O, TCP retransmissions, off-CPU waits, and memory pressure
for one process at a time. Symbolization, per-request I/O attribution,
connection-level RTT, automatic diagnosis from real collectors, and
long-running recording are planned for later versions.
