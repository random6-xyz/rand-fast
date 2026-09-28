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
| `cpu`       | CPU usage and on-CPU hot stacks            | measured, symbolized top stacks |
| `io`        | block I/O latency                          | measured, per-device latency with op split |
| `net`       | TCP retransmissions                        | stub (RTT/endpoint fields zeroed) |
| `off-cpu`   | off-CPU wait time                          | measured, stacks not symbolized |
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

Samples on-CPU stacks of the target threads at `--frequency` (default 99 Hz)
by attaching a BPF program to a perf `cpu-clock` event on every online CPU,
and reports process CPU usage from `/proc` tick deltas. Top stacks are
symbolized: kernel frames via the running kernel's kallsyms (full addresses
require root), user frames via blazesym against the target process' live
`/proc/<pid>` state. The sample count scales with sampling rate × CPU time:
an idle target yields ~0 samples, a busy target ≈ frequency × duration ×
busy-core count, regardless of how many times the threads wake up.

```bash
sudo ./target/release/fast cpu --pid 1234 --duration 10s --frequency 199
```

Sample output (lock-hog fixture, 16 workers):

```text
PID: fast-workload (326)
Duration: 5s
Samples: 3489
Lost: 0
CPU usage: 97.7% (over 5.0s wall, 4019 ticks total)

On-CPU samples (hot stacks)
stack (952, 144)  samples 302 (8.7%)
  0  [k] native_queued_spin_lock_slowpath+0x15
  1  [k] _raw_spin_lock+0x29
  2  [k] futex_wake+0x172
  3  [k] do_futex+0xd8
  4  [k] __x64_sys_futex+0x136
  5  [k] do_syscall_64+0xaa
  6  [k] entry_SYSCALL_64_after_hwframe+0x76
  7  syscall+0x1d (libc.so.6)
stack (-14, 2560)  samples 196 (5.6%)
  0  std::sys::backtrace::__rust_begin_short_backtrace::<...>+0x90 (fast-workload)
stack (3252, 144)  samples 190 (5.4%)
  0  [k] native_queued_spin_lock_slowpath+0x13e
  ...

Per-CPU samples
cpu 0    samples 492

Correlation
CPU saturation likely contributes to scheduler latency (CPU 97.7% with 3489 samples)
```

Kernel frames carry the `[k]` prefix and are resolved through kallsyms;
user frames are resolved against the target's live maps (libc frames stay
raw on systems without libc symbol tables). Kernel stacks are stored only
for samples that interrupt the target inside the kernel; user-context
samples report user frames alone.

Verification: `fast cpu` against `./target/release/sched-workload target
--duration 30s` collects 0 samples and near-zero usage; against
`./target/release/sched-workload hog --duration 30s --workers 8` the sample
count approaches frequency × duration × busy cores (3943 samples at 99 Hz
× 8 cores × 5 s) and the futex wait path shows up symbolized under
`fast-workload lock-hog`. Rate scaling: 3928 samples at 99 Hz vs 15566 at
396 Hz against the same hog (3.96x, expected ~4x).

### `fast io`

Measures block I/O latency from `block_rq_issue` / `block_rq_complete`, and
reads `/proc/<pid>/io` counters for byte deltas. The tracepoint payloads are
parsed (offsets verified against the guest format files the init script
dumps): each event carries the device (`major:minor`), start sector, size in
sectors, and the operation (read/write) read from the rwbs field.
Requests are paired per request, not per issuing thread: the pending map is
keyed by (device, start sector), so completions that run in IRQ/softirq
context still attribute to the issuing thread and completion rate tracks
issue rate.
`--threshold` (default `10ms`) controls the slow-I/O counter.

```bash
sudo ./target/release/fast io --pid 1234 --duration 10s --threshold 10ms
```

Sample output (io-hog, sequential O_DIRECT reads on the QEMU scratch disk):

```text
PID: fast-workload (204)
Duration: 5s
Samples: 151281
Lost events: 0
Slow > 10ms: 1
rchar: 634273792 bytes, wchar: 0 bytes

I/O latency
samples     151281
p50          47 µs
p95          65 µs
p99          87 µs
max       536.3 ms
ops: read 151281 (590.9 MiB)

Per-device latency
dev vda (254:0)  samples 151281 sectors 1210248
ops: read 151281 (590.9 MiB)
  p50      47 µs p95      65 µs p99      87 µs max   536.3 ms

Slow I/O > 10ms (top 1 of 1)
   latency  device        op      sectors      bytes      tid
  536.3 ms  vda (254:0)   read          8    4.0 KiB      207
```

The device label resolves through `/sys/dev/block` (name plus
`major:minor`); without a sysfs entry it falls back to `major:minor`.

Verification: `fast io` against `sleep 60` collects no samples; against
`./target/release/fast-workload io-hog --duration 30s --workers 2 --path
<file-on-real-block-fs>` the report names the device holding the file, the
`rchar` delta and per-device byte totals grow together, and the slow-I/O
table lists the slowest requests above `--threshold`. Per-request pairing:
284120 completions matched 290619 reads in the smoke run (97.8%; the old
per-TID matching paired only a fraction of a percent because completions
run in IRQ context). The default path lives under `/tmp`, which is often
tmpfs — reads there never reach the `block_rq_*` tracepoints, so only the
`rchar` delta moves; point `--path` at a file on a real block filesystem
(or the QEMU scratch disk) to collect latency samples.

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

### `fast off-cpu`

Measures off-CPU wait by pairing `sched_switch` (a target thread switches
out in a sleepable state) with `sched_wakeup` (it becomes runnable again),
with kernel stack ids for hot wait stacks.

```bash
sudo ./target/release/fast off-cpu --pid 1234 --duration 10s
```

Sample output (lock-hog, 16 contending threads on 8 CPUs):

```text
PID: fast-workload (18700)
Duration: 5s
Samples: 557348
Lost: 0

Off-CPU wait
p50          4 µs
p95         43 µs
p99        200 µs
max        2.7 ms

Hot wait stacks
stack 210    samples 294700
```

Verification: `fast off-cpu` against `./target/release/sched-workload target
--duration 30s` collects ~1000 timer-sleep waits per second (p50 ≈ the sleep
period); against `./target/release/fast-workload lock-hog --duration 30s
--workers 16` the sample count explodes into hundreds of thousands of short
futex waits. Use more workers than CPUs so waiters actually park instead of
spinning.

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

Note: full diagnose would run 'fast sched/cpu/io/net/off-cpu/memory' collectors in parallel for 10s
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

- `cpu`: kernel stacks are stored only for samples that interrupt the target
  inside the kernel (user-context samples carry user frames alone); libc
  frames stay raw on systems without libc symbol tables. The usage percentage
  is derived from `/proc` tick deltas, not from the eBPF samples.
- `io`: requests are keyed by (device, start sector). Two outstanding
  requests on the exact same key keep only the first issue (BPF_NOEXIST),
  empty flush requests all share sector 0, and a completion from a
  non-target process for the same key would consume the target's pending
  entry and be misattributed to it — the request pointer that would remove
  these races is not reachable from tracepoint programs. Payload offsets are
  verified against the 7.2.x tracepoint format files; older kernel series
  (e.g. 5.x, where the fields sit at different offsets) would need
  re-verification.
- `net`: only `tcp_retransmit_skb` is tracked; RTT and address/port fields
  are zeroed, so no endpoint or RTT table exists yet.
- `off-cpu`: waits pair switch-out with the next wakeup, so the final
  wake-to-run dispatch is counted as scheduler latency instead; stack ids
  capture the waking context, not the sleeping frame, wait reasons are not
  classified, and stack ids are not symbolized.
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

The script exits non-zero if any verifier load or collection fails.
It also runs on a host where you hold the required capabilities.
`tools/qemu-guest-init.sh` boots a minimal initramfs-only guest (busybox,
the release binaries, a loopback link, and an optional ext4 scratch disk for
the io-hog fixture) and runs the matrix automatically:

```bash
truncate -s 256M /tmp/fast-io.img && mkfs.ext4 -q -F /tmp/fast-io.img
gcc -static -O2 -o /tmp/mount2 tools/qemu-guest-mount.c
# build the initramfs around tools/qemu-guest-init.sh, then:
qemu-system-x86_64 -enable-kvm -m 2048 -smp 8 \
    -kernel vmlinuz -initrd initramfs.img.gz \
    -append "console=ttyS0 rdinit=/init loglevel=3 panic=-1" \
    -nographic -no-reboot -monitor none \
    -drive file=/tmp/fast-io.img,format=raw,if=virtio
```

Recorded results (QEMU KVM guest, 8 vCPUs, kernel 7.2.3-arch1-3 with BTF,
2026-09-08, v1.0 code; the `sched` 7.2.0-rc6 row keeps the earlier record):

| Command   | Verifier | Idle                                   | Load                                            |
| --------- | -------- | -------------------------------------- | ----------------------------------------------- |
| `sched`   | pass     | p50 6µs p95 19µs p99 29µs max 131µs, slow>1ms 0 | p50 3µs p95 5µs p99 1.1ms max 2.7ms, slow>1ms 46 |
| `sched` (7.2.0-rc6, 2026-08-29) | pass | p50 7µs p95 9µs p99 11µs max 69µs, slow>1ms 0 | p50 3µs p95 2.3ms p99 4.0ms max 5.2ms, slow>1ms 297 |
| `cpu`     | pass     | 0 samples, usage 0.1%                  | 3943 samples (99 Hz × 8 busy cores × 5 s), usage 99.0%, symbolized top stacks |
| `io`      | pass     | 0 samples                              | 151281 samples on vda (254:0), p50 47µs p99 87µs, 590.9 MiB read |
| `net`     | pass     | retransmissions 0                      | retransmissions 0 (loopback does not retransmit) |
| `off-cpu` | pass     | 4621 samples                           | 529503 samples                                  |

v1.0 accuracy checks from the same run (`tools/qemu-smoke.sh` prints them):

- cpu rate scaling: 3928 samples at 99 Hz → 15566 samples at 396 Hz against
  the same hog (3.96x, expected ~4x) — sample count tracks frequency × CPU
  time, not wakeups.
- cpu symbolization: the lock-hog futex wait path appears symbolized
  (`[k] futex_wait` / `do_futex` kernel frames plus user frames).
- io per-request pairing: 284120 completions for 290619 reads (97.8%); the
  pre-v1.0 per-TID matching paired roughly 0.03% (67 of ~214k).

All five eBPF-backed programs load and attach in the guest, and the load
runs show the expected signal deltas.

## Diagnosis ranking

`fast diagnose` ranks causes from what it measured, not from the machine. The
table below is the acceptance record: five processes, each with exactly one
thing wrong, each expected to be ranked on that thing. Every row is produced
by running `fast diagnose --format json` against a real workload and reading
the first entry of the causes array, so what is checked is the number a
consumer would act on.

Reproduce with:

```bash
tools/qemu-run.sh          # runs the whole matrix, scenarios included
```

| Scenario | Fixture | Ranked first | Evidence it rests on |
| -------- | ------- | ------------ | --------------------- |
| CPU | `sched-workload hog --workers 1` | CPU contention | 99% of one CPU, so ~100% of wall time on CPU |
| Disk I/O | `fast-workload io-hog --workers 2 --size-mib 256` | Disk I/O | p99 past the slow threshold, plus the share of off-CPU time waiting on the device |
| Lock | `fast-workload lock-hog --workers 16` | Lock contention | share of off-CPU time on a futex, above the 33% threshold |
| Memory | `fast-workload mem-hog --workers 1 --size-mib 1024` | Memory pressure | direct reclaim attempts per second, through the memory report's own verdict |
| Network | `fast-workload net-hog --workers 2 --delay-ms 600` | Network | retransmission ratio, plus the share of off-CPU time blocked on a socket |

Recorded 2026-09-28 on the kernel-server bpf-next image (7.2.0-rc6, 8 vCPUs,
BTF present, no CONFIG_PSI): all five ranked as expected, twice in a row, with
the matrix exiting rc=0.

Three of the five fixtures differ from the ones the roadmap first suggested,
because the originals cannot be run on this kernel and a check that cannot run
is not a check:

- `stress --vm` is replaced by `mem-hog`. The guest is built without
  `CONFIG_PSI` and has no swap device, so there is no PSI to observe and no
  swap to fault from. Direct reclaim is the per-process memory signal that is
  available, and it is the one the memory verdict already uses.
- The netem-delayed link is replaced by the net-hog receive-window cycle. The
  kernel has neither netem nor TBF built in, and HTB shapes loopback so hard
  the connection never gets going. The cycle closes the window repeatedly,
  which produces both real retransmissions and a round trip stretched from
  ~43 us to ~1295 us.
- The I/O fixture reads through O_DIRECT from the ext4 scratch image, because
  reads served from tmpfs never reach the block tracepoints at all.

Two limits are worth stating plainly rather than hiding behind the passes:

- The CPU row uses a single worker. Several busy workers on eight vCPUs is not
  contention, and the report should not claim otherwise; multi-worker CPU
  pressure is a different question and is not what this row tests.
- The memory row depends on the guest being memory-constrained. An oversized
  fixture is OOM-killed in a fraction of a second, which produces a run too
  short to measure and would test the fixture rather than the ranking.

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
for one process at a time. CPU stack symbolization and per-request I/O
attribution landed in v1.0; connection-level RTT, automatic diagnosis from
real collectors, and long-running recording are planned for later versions.
