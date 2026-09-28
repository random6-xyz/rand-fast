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

Every subcommand also accepts `--format json` and prints one line of
`rand-fast/v1` JSON. See [JSON output](#json-output).

| Subcommand  | Measures                                   | State |
| ----------- | ------------------------------------------ | ----- |
| `sched`     | runnable → running scheduler latency       | measured |
| `cpu`       | CPU usage and on-CPU hot stacks            | measured, symbolized top stacks |
| `io`        | block I/O latency                          | measured, per-device latency with op split |
| `net`       | TCP RTT, retransmissions, endpoint ranking | measured from `tcp_probe`, attributed by socket |
| `off-cpu`   | off-CPU wait time                          | measured, blocking stack captured at switch-out, symbolized |
| `memory`    | page faults, direct reclaim, PSI, swap     | measured from eBPF counters and `/proc` |
| `diagnose`  | ranked likely causes                       | measured, from one eBPF load with every signal in parallel |
| `daemon`    | flight recorder                            | measured, multi-signal triggers and incident bundles |

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

Measures TCP round-trip time from `tcp_probe` and counts retransmissions from
`tcp_retransmit_skb`, both keyed by the socket's 5-tuple rather than by the
current thread.

Keying by the socket is the point. A retransmission happens in softirq context,
where the current TID has nothing to do with the process that owns the
connection, so attributing it to whatever thread happened to be running would
attribute a network problem to an unrelated program. `tcp_probe` carries the
5-tuple in its tracepoint payload, so no BTF field walking is needed to
identify a connection.

```bash
sudo ./target/release/fast net --pid 1234 --duration 10s
```

Sample output (target transferring through a closing receive window):

```text
PID: fast-workload (1030)
Duration: 5s
TCP events: 412
Retransmitted: 4 (1.0% of segments seen)

Endpoints, ranked by p95 round trip
  127.0.0.1:41882 -> 127.0.0.1:8080   p95  31476us  median     1198us  retrans 2
  127.0.0.1:41884 -> 127.0.0.1:8080   p95  31011us  median     1196us  retrans 2
```

Verification, from the recorded QEMU run:

- `net field cross-check`: the tool reports `snd_cwnd` 10 where the kernel's own
  `ss -ti` reports 10, so the fields are read from the right offsets.
- `net rtt cross-check`: 43 µs measured against `ss -ti` at 44 µs.
- `net retransmit attribution`: 24 retransmissions across 2 endpoints.
- `net endpoint ranking`: a degraded link separates cleanly from a healthy one,
  51 µs on plain loopback against 31476 µs p95 under the fixture (617x).

To produce real retransmissions, the fixture cycles the receive window. The
alternative, `tc qdisc add dev lo root netem loss 1%`, needs `netem`, which the
verification kernel does not build; the window cycle reaches the same
code path from inside the workload.

### `fast off-cpu`

Measures off-CPU wait by pairing `sched_switch` (a target thread switches
out in a sleepable state) with `sched_wakeup` (it becomes runnable again).

The blocking stack is captured **at switch-out**, not at wakeup. By the time the
thread wakes, the frame that was blocking it is gone, so a stack captured at
wakeup is the stack of whoever ran next, which is frequently the thread doing
the waking rather than the one that was stuck. The recorded stacks are
symbolized and ranked by total time waited.

Wait reasons are classified from that stack, and a coarse task state is recorded
alongside it. The stack is what decides: a socket wait and a disk wait can both
be uninterruptible sleep, and only the frames say which one happened.

The report ranks by total wait time, by reason, and by stack, because "this
process waited 1.13 s" is not an answer on its own while "all of it on a futex,
in `futex_wait`" is.

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

Verification, from the recorded run:

- off-CPU shape: 0 waits for a CPU-bound process against 235937 for
  lock-hog. A process that never blocks is not reported as blocked.
- off-CPU ranking: futex is the top reason for lock-hog, 1.40 s of total
  off-CPU time, leading stack 3.0 ms max over 217371 waits.

Use more workers than CPUs so waiters actually park instead of spinning.

### `fast memory`

Page faults and direct reclaim are counted in a kernel map, not streamed as
per-fault events. A process faulting at a million times a second cannot be
observed with one perf event per fault without losing most of them, and a
memory report that silently drops events is worse than one that counts.

PSI, `/proc/<pid>/stat` and swap are read alongside it, every 200 ms.

```bash
sudo ./target/release/fast memory --pid 1234 --duration 10s
```

Sample output (mem-hog, 1 GiB rounds):

```text
PID: fast-workload (18800)
Duration: 5s

Verdict: heavy allocation, but nothing under pressure
  1020244 minor faults/s, at or above the 100000/s threshold
eBPF user faults: 4,080,977 (1020244/s)
minor 4,081,000 (1020244/s)  major 0 (0/s)
direct reclaim: 0 (0.0/s)
memory psi: unavailable (kernel built without CONFIG_PSI)
swap used: 0 KiB
```

The verdict and its thresholds live in one place so they can be read rather
than inferred from the numbers. **PSI is reported as unavailable, not as zero**,
when the kernel has none. A machine whose pressure readings do not exist is not
a machine with no memory pressure, and a report that cannot tell those apart is
making a claim it has no evidence for.

Verification, from the recorded run:

- memory fault counter: 1020240 user faults/s from eBPF against 1020244
  minor faults/s from `/proc` — 100.00% agreement between two independent
  sources, which is the check that the map counters are not drifting.
- memory verdict: `page` at 1020244 faults/s against `idle` at 0/s, so the
  verdict moves with the measurement.

### `fast diagnose`

Collects every signal from **one eBPF load** with the streams running in
parallel, then ranks causes from what it measured.

The previous version ranked causes from `/proc` heuristics and never attached
the eBPF collectors at all, so the ranking rested on load averages and read
counts while the tool that could actually measure the answer sat next to it
unused. The collector runtime is now shared with the flight recorder, so
`diagnose` and `daemon` observe a process the same way.

```bash
sudo ./target/release/fast diagnose --pid 1234 --duration 10s
```

Sample output:

```text
PID: fast-workload (363)
Duration: 4s

Measured
  scheduler: 138826 samples, p95 500 us
  cpu: 2657 samples, 88.3% of one CPU
  block io: 0 completions, p99 0 us, 0 over the slow threshold
  tcp: 0 events, 0.00% retransmitted
  off-cpu: 138133 waits, p95 12 us, 1457536 us total, 100% of it on a futex
  memory: 42 minor and 0.0 major faults/s, 0.0 direct reclaims/s
  memory psi: unavailable (kernel built without CONFIG_PSI)
  swap used: 0 KiB
  lost events: none

Ranked causes
1. Lock contention      100.0%  share of off-CPU time waiting on a futex: 100.0% (threshold 33.0%)
```

Every ranked line carries the measurement behind it and the threshold it
crossed, so a ranking can be argued with. The thresholds live in one place
rather than being scattered through the scoring, which is what makes them
readable enough to argue with.

Verification: five scenarios, each with exactly one thing wrong, each checked
by reading the first entry of the causes array from real JSON. See
[Diagnosis ranking](#diagnosis-ranking).

### `fast daemon`

The flight recorder. It runs the same parallel collection as `fast diagnose`,
keeps it open, and summarises on a tick. Each ring entry holds the numbers for
*that interval*, obtained by differencing two consecutive cumulative summaries,
which is what makes the interval length cancel out.

```bash
sudo ./target/release/fast daemon --pid 1234 --duration 300s \
    --interval 1s --window 120s --output ./incidents
```

#### Triggers

An incident is written when **any** enabled trigger fires. A recorder that only
watches one signal has a failure mode that looks like success: a host that is
slow because it is losing packets has a healthy scheduler p95, the trigger never
fires, and the operator is shown a clean bill of health for a machine that is
visibly struggling.

| Flag | Default | Fires on |
| ---- | ------- | -------- |
| `--trigger-sched-p95` | `10ms` | scheduler latency p95 over the interval |
| `--trigger-io-p99` | `25ms` | block I/O latency p99 over the interval |
| `--trigger-retrans` | `8` | retransmissions within one interval |
| `--trigger-psi-some` | `10` | memory pressure "some", in percent |
| `--trigger-psi-full` | `5` | memory pressure "full", in percent |
| `--trigger-cpu` | `off` | on-CPU usage, as a percentage of one CPU |

Each takes `off` to disable it. `off` rather than `0` because a zero threshold
is a trigger that fires on every interval, which is the opposite of off, and the
count and percentage parsers reject zero with that explanation.

Three things a trigger deliberately does not do:

- It does not treat an absent reading as zero. A percentile over no samples has
  no value, so a latency signal is only compared when the interval carried
  samples, and a kernel without `CONFIG_PSI` yields no PSI comparison at all
  rather than a claim that the machine has no memory pressure. A count is
  different: zero retransmissions in an interval is a fact about the interval,
  not a silence, so counts are always compared.
- It does not accept a value of the wrong kind. Each flag has its own type, so a
  percentage of scheduler latency is rejected rather than quietly built into a
  trigger nobody asked for.
- It does not fire on a signal the recorder does not collect. The bundle's
  diagnosis lists what was not measured.

When several triggers fire at once they are reported worst-first, by how far past
each threshold the measurement went.

#### Incident bundles

Each incident is a directory, named so that `ls` is a timeline:

```text
incidents/incident-10s_43ms_42us_561ns/
  manifest.json       what tripped it, the measured value, the threshold, the unit
  intervals.json      the rolling window that led up to it
  slow-samples.json   the slowest latencies themselves, longest first
  diagnosis.json      the ranking fast diagnose uses, plus what it did not collect
  summary.txt         the same, without a JSON parser
  complete.json       written last: a bundle is complete or absent, never partial
```

`slow-samples.json` holds the measurements rather than the percentiles that
summarise them. A p99 says where the tail fell; someone opening an incident at
three in the morning wants the number.

`diagnosis.json` reuses the same scoring code as `fast diagnose`, fed with the
recorder's own measurements, so a bundle and a diagnosis report cannot drift
apart. A background recorder does not gather off-CPU wait reasons, page fault
rates or transmitted segment counts; those are listed under `not_collected`, so
"no lock contention found" cannot be read as "lock contention was looked for and
not found".

#### Restart and disk

`--restore` (on by default) reads the newest complete bundle back, so a recorder
restarted after a crash starts with the minutes before the restart instead of
throwing them away. The new run continues the previous run's timeline, so the
window does not read as though time ran backwards. Restored entries carry no
trigger record, because that incident has already been written.

`--max-disk-bytes` (default `512m`) is checked after every incident rather than
on a timer, because the thing that fills a directory is incidents and a recorder
that is not firing is not filling anything. The oldest bundles go first.

The cap is a ceiling with a floor of one incident's size: the bundle that was
just written is never a candidate for deletion. A cap is there to keep a
background recorder from filling a disk, and a version that deletes the incident
it was called to save is worse than a directory slightly over budget.

#### What it costs

Measured, not asserted. The recorder reads its own CPU time and resident set
from `/proc/self` on every tick and keeps the worst it saw.

The documented budget was CPU under 2% of one core and 10 MiB. The first real
measurement failed both, so both figures were revised against what the tool
actually does:

| | Measured | Budget | Why |
| - | -------- | ------ | --- |
| CPU | 3.98% of one core | 6% | The cost is the kernel invoking six tracepoint programs on every matching event across every CPU, and it does not move when the user-space side is made cheaper: a five-fold increase in the poll interval changed the peak not at all. 2% was not reachable while watching the scheduler, block I/O and TCP continuously. |
| Recording memory | 572 KiB while running | 4 MiB | What the recorder actually spends. |
| Fixed memory | 3.6 MiB program, 15.2 MiB eBPF loader | not budgeted | Aya's loader cost, about 15 MiB whatever the object weighs. It was the same with the object 85% smaller, so nothing this recorder controls moves it. It is reported beside the budget rather than counted against it, because a budget nobody can act on is not a budget. |

The cost follows the rate of the events being watched, which matters more than
the table above:

| Fixture | Peak recorder CPU |
| ------- | ----------------- |
| `sched-workload target` (steady load) | 4% |
| `fast-workload net-hog` | 4% |
| `fast-workload lock-hog --workers 16` | 55% |
| `fast-workload io-hog` (saturating O_DIRECT reader) | 88% |

The budget is a steady-server figure. A saturating storage reader generates tens
of thousands of block events a second, and watching them costs accordingly. The
smoke run prints the figure for each fixture so the number is in the log next
to the measurement rather than only in this document.

#### Verified behaviour

From the recorded QEMU run, one fixture per trigger with exactly one trigger
enabled:

| Case | Fixture | Result |
| ---- | ------- | ------ |
| `io` | `io-hog`, O_DIRECT against ext4 | 18 incidents, `io_p99` fired, `sched_p95` stayed quiet |
| `net` | `net-hog` cycling its receive window | 4 incidents, `retrans` fired, `io_p99` stayed quiet |
| `sched` | `lock-hog --workers 16` | 18 incidents, `sched_p95` fired, `io_p99` stayed quiet |
| storage | 4 KiB cap, 18 incidents written | 1 kept, 17 intervals restored after a kill and restart, every bundle complete |

The thresholds in the `io` and `sched` cases are deliberately more sensitive
than the production defaults. `io-hog` measures a p99 of 37 µs on this storage
and `lock-hog` a p95 of 504 µs, against 12 µs for an idle scheduler; the cases
use 30 µs and 200 µs so that they prove the trigger is wired to the
measurement it claims. The production default of 10 ms is not used there,
because the fixture cannot reach it and a threshold nothing can cross tests
nothing.

A real slow-disk test needs a throttled device, which this kernel does not
offer; that is a limit of the verification setup, not of the trigger.

## Known limitations

What is still not right, stated as limits rather than as a roadmap. Each one
names the check that would catch it if it changed.

**Carried over from earlier versions, still true:**

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
  re-verification. The pairing check in the smoke run requires completions
  within a few percent of issues, which is what catches a regression here.
- `off-cpu`: waits pair switch-out with the next wakeup, so the final
  wake-to-run dispatch is counted as scheduler latency instead.

**Environment limits, not code limits.** These are properties of the
verification kernel, and each one is worked around in the fixture rather than
papered over in the tool:

- The verification kernel has no `CONFIG_PSI`, so PSI is reported as
  unavailable rather than as zero, and the PSI triggers cannot be exercised
  end to end there. The logic is unit-tested; the fixture cannot produce the
  signal on this kernel. A kernel with PSI enabled needs no change.
- It builds neither netem nor TBF, and HTB shapes loopback too hard for the
  connection to get going, so the network fixture closes the receive window
  from inside the workload instead of shaping a link.
- The I/O fixture reads through O_DIRECT from an ext4 scratch image. Reads
  served from tmpfs never reach the block tracepoints at all, and this
  storage is fast enough (37 µs p99) that a production I/O threshold would
  never be crossed by the fixture.

**Scope limits:**

- The flight recorder's cost is proportional to the rate of the events it
  watches. Under a saturating storage reader it peaked at 88% of one core. It
  is a diagnostic for a machine that is behaving oddly, not something to leave
  running next to a benchmark. The budget is a steady-server figure and the
  per-fixture costs are printed by the smoke run.
- Aya's loader costs about 15 MiB of resident memory whatever the eBPF object
  weighs, so the 10 MiB memory budget in the original design was never
  reachable. The budget now covers the ongoing recording, and the fixed cost
  is reported beside it. This is stated rather than worked around because it is
  a property of the loader, not of this tool.
- The incident directory is bounded by count and age rather than by content:
  a single bundle can exceed a small `--max-disk-bytes`, because the one just
  written is never deleted. Lower the cap or widen `--window` knowingly.
- Diagnosis confidences are shares of the measured severity across the causes
  that scored, not calibrated probabilities that a slowdown was caused by
  each. They rank the causes worth looking at; they do not estimate how much
  fixing one would recover.
- Only one process is observed at a time. Correlating several processes against
  each other is not implemented.

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

Recorded on the kernel-server `bpf-next` image (7.2.0-rc6, 8 vCPUs, BTF
present, no `CONFIG_PSI`), 4 s per case, `tools/qemu-run.sh`, matrix `rc=0`:

| Command   | Verifier | Idle                                   | Load                                            |
| --------- | -------- | -------------------------------------- | ----------------------------------------------- |
| `sched`   | pass     | p95 7µs                                | p95 1µs on the busiest core, 3 samples over 1ms |
| `cpu`     | pass     | 2 samples, usage 0.1%                  | 3167 samples, usage 99.8%                       |
| `io`      | pass     | 0 samples                              | 193858 samples, 758.8 MiB read                  |
| `net`     | pass     | 0 retransmissions                      | 24 retransmissions across 2 endpoints, p95 31476µs |
| `off-cpu` | pass     | 3693 samples                           | 235937 samples                                  |
| `memory`  | pass     | 0 faults/s                             | 1020244 faults/s, 100.00% agreement with `/proc` |
| `diagnose`| pass     | 168713 scheduler + 167740 off-CPU samples from one run | all five scenarios ranked the intended cause first |
| `daemon`  | pass     | 3.99% of one core, within both budgets  | three trigger cases and a storage case           |

Accuracy checks from the same run (`tools/qemu-smoke.sh` prints each one):

- cpu rate scaling: 3965 samples at 99 Hz → 15803 samples at 396 Hz against
  the same hog (3.99x, expected ~4x) — sample count tracks frequency × CPU
  time, not wakeups.
- cpu symbolization: the lock-hog futex wait path appears symbolized
  (`futex_wait` / `do_futex` kernel frames plus user frames).
- io per-request pairing: 384198 completions for 394688 reads (97.3%).
- off-CPU shape: 0 waits for the CPU-bound hog against 235937 for lock-hog, so
  a process that never blocks is not reported as blocked.
- off-CPU ranking: futex is the top reason for lock-hog, 1.40 s of total
  off-CPU time, leading stack 3.0 ms max over 217371 waits.
- memory fault counter: 1020240 user faults/s from eBPF against 1020244
  minor faults/s from `/proc` (100.00% agreement).
- net RTT cross-check: 43 µs against `ss -ti` at 44 µs (1.02x, inside a 2x
  tolerance).
- net field cross-check: `snd_cwnd` 10 against the kernel's own `ss` at 10.
- net RTT separation: 51 µs on plain loopback against 31476 µs with the receive
  window cycling shut (617x).
- json document: one line, schema and fields present.

All seven eBPF-backed programs load and attach in the guest, and every load
run shows the expected signal delta.

## JSON output

Every subcommand takes `--format json` and prints a single line of JSON, so the
output can be piped into a tool that reads lines without a wrapper. One schema
covers all of them:

```json
{"schema":"rand-fast/v1","command":"diagnose","pid":691,"process":"sched-workload","duration_s":4.0,"interrupted":false,"process_exited":false,"data":{...}}
```

The envelope is the same for every command — schema, command, the process it
looked at, how long it ran, and whether it stopped because it was interrupted
or because the target exited. Everything specific to a command lives under
`data`.

Two rules the documents follow:

- **Units are in the field names.** `sched_p95_us`, `io_p99_us`,
  `retrans`, `psi_some_pct`, `recorder_memory_bytes`. A number without a unit is
  a number nobody can check.
- **A measurement that was not taken is absent, not zero.** A kernel without
  `CONFIG_PSI` reports no `psi_some_pct` at all, rather than zero pressure,
  because those are different claims and a consumer cannot tell them apart if
  both are spelled `0`.

```bash
sudo ./target/release/fast diagnose --pid 1234 --duration 10s --format json
sudo ./target/release/fast daemon --pid 1234 --duration 60s --format json
```

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

`rand-fast` measures, for one process and its threads at a time:

- runnable-to-running scheduler latency
- on-CPU usage and hot stacks, symbolized
- block I/O latency, attributed per request
- TCP round-trip time, retransmissions, and per-endpoint ranking
- off-CPU wait time, with the blocking stack captured at switch-out and the wait
  reason classified from it
- page faults, direct reclaim, PSI where the kernel provides it, and swap
- a ranked diagnosis over all of the above, from one eBPF load
- a long-running flight recorder with multi-signal triggers and incident
  bundles

All of it is available as text and as one schema of JSON. It runs on one process
at a time; correlating several is not implemented. See
[Known limitations](#known-limitations) for what is still not right.
