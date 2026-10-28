# rand-fast

`rand-fast` answers one question about a Linux server: **why is this process
slow?** It watches a single PID and its threads with eBPF, measures the waits
that usually explain a regression, and ranks the likely causes instead of
showing another dashboard.

```bash
sudo fast diagnose --pid 1234 --duration 10s
```

## What it measures

| Command | Signal | State |
| --- | --- | --- |
| `sched` | time runnable before running | measured |
| `cpu` | CPU usage and on-CPU hot stacks | measured, symbolized |
| `io` | block I/O completion latency | measured, per device and operation |
| `off-cpu` | where threads wait while not running | measured, blocking stack captured |
| `memory` | page faults, direct reclaim, PSI, swap | measured |
| `net` | TCP RTT and retransmissions | **unavailable** in this build |
| `diagnose` | ranked causes from every available signal | measured |
| `daemon` | rolling flight recorder with incident bundles | measured |

TCP attribution is deliberately disabled. The tracepoints do not identify the
owning process reliably: `tcp_probe` runs on the receive path, retransmissions
run in softirq context, and raw socket pointers are reused. Reporting those
events under the wrong process would be worse than reporting nothing, so `net`
and `diagnose` say that TCP is unavailable. Network ranking still uses
independently measured off-CPU socket waits. See
[`fast/docs/tcp-attribution.md`](fast/docs/tcp-attribution.md).

## Requirements

- Linux with BTF enabled: `CONFIG_BPF`, `CONFIG_BPF_SYSCALL`,
  `CONFIG_BPF_EVENTS`, `CONFIG_DEBUG_INFO_BTF`.
- Tracepoints under `/sys/kernel/tracing` or `/sys/kernel/debug/tracing`.
- Permission to load eBPF and open perf events: `root`, or `CAP_BPF` +
  `CAP_PERFMON` on kernel 5.8+, or `CAP_SYS_ADMIN` on older kernels.
- A kernel whose scheduler, block-request, and TCP tracepoint layouts match the
  verified layouts. Startup rejects an unrecognised layout rather than
  collecting numbers from the wrong offsets. Verified on 6.12.105 and
  7.2.0-rc6.

The prebuilt binary embeds the eBPF object; a release does not need Rust,
`rust-src`, or `bpf-linker`.

## Install a release

Prebuilt archives target Linux x86_64. Pick a version from
[GitHub Releases](https://github.com/random6-xyz/rand-fast/releases/latest) and
replace `v0.2.0` below with that tag.

```bash
VERSION=v0.2.0
BASE_URL="https://github.com/random6-xyz/rand-fast/releases/download/${VERSION}"
ARCHIVE="rand-fast-${VERSION}-linux-x86_64.tar.gz"

curl --fail --location --remote-name "${BASE_URL}/${ARCHIVE}"
curl --fail --location --remote-name "${BASE_URL}/SHA256SUMS"
sha256sum --check SHA256SUMS
tar -xzf "$ARCHIVE"
cd "rand-fast-${VERSION}"
sudo ./fast diagnose --pid "$TARGET_PID" --duration 10s
```

## Commands

Every command takes `--pid <TGID>` and `--duration` (`10s`, `500ms`). Threads
are discovered through `/proc/<pid>/task` and re-synced while collection runs.
The report is printed when the duration ends, the process exits, or you press
Ctrl-C.

| Command | Use it for |
| --- | --- |
| `fast diagnose` | one command, every available signal, ranked causes |
| `fast sched` | run-queue latency, percentiles, slow-event counts |
| `fast cpu` | CPU usage and symbolized on-CPU stacks |
| `fast io` | block I/O latency per device, slow requests |
| `fast off-cpu` | who is waiting, how long, and on what |
| `fast memory` | faults, reclaim, PSI, swap pressure |
| `fast net` | explains that TCP attribution is unavailable |
| `fast daemon` | keeps a rolling window and writes incidents |

### Diagnose

```bash
sudo fast diagnose --pid 1234 --duration 10s
```

```text
PID: app (1234)
Duration: 10s

Measured
  scheduler: 12034 samples, p95 41 us
  cpu: 980 samples, 72.4% of one CPU
  block io: 0 completions, 0 unmatched, p99 0 us, 0 over the slow threshold
  tcp: unavailable (socket ownership cannot be established)
  off-cpu: 8032 waits, p95 210 us, 745000 us total, 8% of it on a futex
  memory: 12 minor and 0.0 major faults/s, 0.0 direct reclaims/s
  memory psi: unavailable (kernel built without CONFIG_PSI)
  lost events: none

Ranked causes
1. CPU contention      92.1%  share of wall time on CPU: 72.4% ...
```

Every ranked line carries the measurement behind it and the threshold it
crossed. The confidence is each cause's share of the measured slowdown, not a
probability. Thresholds live in
[`fast/src/scoring.rs`](fast/src/scoring.rs).

### Flight recorder

```bash
sudo fast daemon --pid 1234
```

The recorder runs until interrupted or the target exits. `--duration` bounds it.
It summarises on `--interval` (default `1s`) and keeps `--window` of history.

Each interval is measured on its own: scheduler p95 and I/O p99 come from the
samples collected in that interval, and the slow-sample lists reset at the same
boundary. The samples live in a bounded histogram and a bounded userspace queue,
so memory does not grow with the length of the recording. The histogram makes a
percentile a bucket lower bound; it can be up to 12.5% low at nanosecond scale,
and a trigger within that margin can fire one interval late. A reported loss
count includes both kernel perf drops and userspace queue drops.

Each incident is a directory with `manifest.json`, the recent `intervals.json`,
`slow-samples.json`, `diagnosis.json`, and a plain-text `summary.txt`. The
window and the trigger that fired are preserved together, so an incident can be
read without the machine it came from.

Triggers: `--trigger-sched-p95` (default `10ms`), `--trigger-io-p99` (`25ms`),
`--trigger-psi-some` (`10`), `--trigger-psi-full` (`5`), `--trigger-cpu` (`off`),
and `--trigger-retrans` (`8`, **cannot fire while TCP attribution is
unavailable**). The recorder warns at startup when the retransmission trigger is
configured; pass `--trigger-retrans off` to silence it.

#### Where incidents are written

The default output is trusted and safe under `sudo`:

- root: `/var/lib/rand-fast/incidents`
- non-root: `$HOME/.local/state/rand-fast/incidents` (or a UID-specific `/tmp`
  path when `HOME` is unusable)

Explicit `--output` paths must have trusted ancestors: the recorder refuses a
group- or world-writable ancestor without the sticky bit, and it never follows a
symlink. Rotation removes only bundles it can prove it created. Legacy bundles
and unrelated files are counted against the cap but are never deleted. See
[`fast/INCIDENT-MIGRATION.md`](fast/INCIDENT-MIGRATION.md).

`--max-disk-bytes` (default `512m`) is checked after each incident. It is a soft
ceiling: an incident larger than the cap, an unreadable entry, or an interrupted
bundle can leave the directory over budget, and the recorder says so instead of
claiming otherwise.

## JSON output

Every command accepts `--format json` and prints one line. Dispatch on both
`schema` and `command`.

- `sched`, `cpu`, `io`, `off-cpu`, `memory`: `rand-fast/v1`
- `net`, `diagnose`, `daemon`: `rand-fast/v2`

Version 2 exists because v1 retyped measurements that were not actually
measured: `net` and `diagnose` emit `retrans_ratio: null` and
`tcp_available: false`; the daemon emits `null` for an unavailable CPU reading
and for retransmissions. Consumers that assumed a number must handle `null`.
See [`docs/network-v2-migration.md`](docs/network-v2-migration.md) and
[`docs/daemon-json-v2.md`](docs/daemon-json-v2.md).

```bash
sudo fast diagnose --pid 1234 --duration 10s --format json
```

## Known limitations

- **No TCP attribution.** `net` reports why it is unavailable; it does not
  invent an RTT, endpoint ranking, or loss rate. Restoring it requires a
  trustworthy ownership source for both RTT and retransmission events.
- **One process.** This is a per-PID tool, not a host-wide profiler. A host-wide
  view needs a separate collector and is out of scope.
- **BTF layouts are verified, not universal.** A kernel with a different
  tracepoint layout is rejected at startup. The verified versions are listed in
  Requirements.
- **PSI may be absent.** A kernel without `CONFIG_PSI` reports PSI as unavailable
  rather than as zero pressure.
- **The recorder costs CPU.** The kernel invokes tracepoint programs for every
  matching scheduler, block, and TCP event, even though TCP events are not
  emitted. The measured peak is around 4–7% of one core on the QEMU fixtures;
  the recorder reports its own peak with every run.
- **Incident retention is best-effort.** The cap is a soft ceiling and rotation
  never deletes data it cannot prove it owns. See the migration guide.
- **Percentiles are approximate in the recorder.** Interval latency uses a
  bounded histogram, so a value is a bucket lower bound rather than an exact
  nearest-rank percentile. Single-shot commands keep exact samples.
- **A full userspace queue drops data.** The queue is deliberately bounded so a
  runaway event rate cannot exhaust memory; drops are counted and surfaced next
  to the kernel's own perf losses.

## Verify

```bash
tools/verify.sh
```

The gate runs formatting, Clippy with `-D warnings`, a release build, the unit
tests, shell regression tests, a CJK check, and license metadata checks.

The privileged eBPF path needs a real kernel. `tools/qemu-run.sh` boots the
provided kernel under KVM and runs the smoke matrix without host `sudo`:

```bash
tools/qemu-run.sh --duration 5s
```

The last recorded results and what each case proves are in
[`docs/verification.md`](docs/verification.md).

## Build from source

Source builds need Rust nightly with the `rust-src` component and
`bpf-linker` 0.9.x.

```bash
LLVM_SYS_191_PREFIX=/usr/lib/llvm-19 cargo install bpf-linker --version 0.9.14
cargo build --release
```

This produces `target/release/fast`, `target/release/sched-workload`, and
`target/release/fast-workload`. Release packaging also uses `cargo-about`
0.9.2 to generate third-party license notices.

## Scope

In scope: per-process scheduler, CPU, block I/O, off-CPU, memory, and ranked
diagnosis on a verified Linux kernel; a bounded flight recorder with incident
bundles.

Out of scope for now: host-wide aggregation, containers and Kubernetes
metadata, HTML reports, remote telemetry, and any network signal that cannot be
attributed to the observed process with evidence.

## License

Licensed under either the [MIT License](LICENSE-MIT) or the
[Apache License, Version 2.0](LICENSE-APACHE). The release archive also includes
third-party Rust dependency license texts.
