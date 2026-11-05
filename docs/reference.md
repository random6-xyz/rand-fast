# Reference

## Commands

Every command observes one process ID (TGID) and its threads. Threads are
found through `/proc/<pid>/task` and re-synchronized during collection. Use
`fast --help` and `fast <command> --help` for all options.

| Command | Purpose |
| --- | --- |
| `diagnose` | Collect available signals and rank likely causes. |
| `sched` | Measure run-queue latency and slow events. |
| `cpu` | Measure CPU usage and symbolized on-CPU stacks. |
| `io` | Measure block I/O latency by device and operation. |
| `off-cpu` | Measure waits and blocking stacks. |
| `memory` | Measure faults, reclaim, PSI, and swap pressure. |
| `net` | Report TCP measurement availability. |
| `daemon` | Keep a rolling window and write incident bundles. |

All commands take `--pid` and `--format text|json`. Single-shot commands
except `diagnose` require `--duration`; `diagnose` defaults to `10s`. The
daemon defaults to `0s`, meaning it runs until interrupted or the process
exits. Durations accept values such as `10s` and `500ms`. `cpu --frequency`
defaults to 99 Hz; `io --threshold` defaults to `10ms`.

`fast diagnose --progress` writes collection progress to stderr: a start
line, one update per second, and one final status line (`complete`,
`interrupted`, `target exited`, or `failed`). The start line is written once
collection begins, after every program is attached; a failure while loading
or attaching prints only the ordinary error. Progress is written even when stderr is redirected and
when `--format json` is selected; stdout and the JSON document are unchanged.
Intermediate updates stop below 100%, so only a collection that actually
finished prints a completion line. A run shorter than the update interval
prints the start and final status only.

```bash
sudo fast diagnose --pid 1234 --duration 10s --format json
sudo fast cpu --pid 1234 --duration 10s --frequency 99
sudo fast daemon --pid 1234 --trigger-retrans off
```

Diagnosis ranks causes using the measured evidence and thresholds in
[`fast/src/scoring.rs`](../fast/src/scoring.rs). Confidence is a cause's share
of the measured slowdown, not a probability. Missing measurements are not
proof that a bottleneck is absent.

## Flight recorder

The daemon records an interval every `--interval` (default `1s`) and retains a
rolling `--window` (default `60s`). It writes an incident when any enabled
trigger fires:

| Option | Default | Meaning |
| --- | --- | --- |
| `--trigger-sched-p95` | `10ms` | Interval scheduler latency p95. |
| `--trigger-io-p99` | `25ms` | Interval block I/O latency p99. |
| `--trigger-psi-some` | `10` | Memory PSI some, percent. |
| `--trigger-psi-full` | `5` | Memory PSI full, percent. |
| `--trigger-cpu` | `off` | CPU usage as a percentage of one CPU. |
| `--trigger-retrans` | `8` | Unavailable; cannot fire without TCP attribution. |

Use `off` to disable an individual trigger. The recorder warns when the
unavailable retransmission trigger is configured; pass `--trigger-retrans off`
to silence the warning. `--restore` defaults to `true` and controls whether
history from a previous run is restored.

Each interval's scheduler p95 and I/O p99 use its own samples, and slow-sample
lists reset at the interval boundary. A bounded histogram reports a bucket
lower bound: it can be up to 12.5% low at nanosecond scale, so a trigger near a
threshold can fire one interval late. Bounded userspace queues prevent unbounded
memory growth; both kernel and userspace drops are counted. Recorder CPU and
memory costs are reported. PSI can be unavailable, rather than zero.

An incident bundle contains `manifest.json`, `intervals.json`,
`slow-samples.json`, `diagnosis.json`, `summary.txt`, and `complete.json`.
It preserves the trigger and recent history leading up to it; the manifest
states how many intervals were carried. The diagnosis identifies signals that
were not collected.

### Output and retention

The default output depends on the effective user:

- Root: `/var/lib/rand-fast/incidents`, regardless of `HOME` or the current
  directory.
- Non-root with an absolute `HOME`: `$HOME/.local/state/rand-fast/incidents`.
- Otherwise: `/tmp/rand-fast-UID/incidents`, where `UID` is the effective UID.
  Files under `/tmp` may be cleared; another user can pre-create the name to
  deny service, but a directory owned by that user is rejected.

`--output` selects another path. The output directory must be owned by the
effective user and must not be writable by group or others. Each ancestor must
be owned by root or that user and must not be group- or world-writable unless
it has the sticky bit, as with `/tmp`. Symlink components are rejected. Missing
directories are created with mode `0700`; existing ownership and permissions
are not changed. Other processes running as the effective user are trusted.

If startup reports `unsafe incident output`, check owners, permissions, and
symlinks; choose a trusted path or ask an administrator to prepare one. Do not
recursively change ownership or permissions of a directory other users can
modify. In particular, do not use a normal user's home as an ancestor of a
root daemon's output.

`--max-disk-bytes` defaults to `512m`. The cap is checked after writing an
incident and is a **soft ceiling**. Rotation retains the newest incident and
only deletes bundles it can prove it owns. Legacy bundles and unrelated files
are counted but not deleted; an oversized incident, unreadable entry,
interrupted bundle, or rotation failure can also leave the directory over the
cap. The recorder warns when the size cannot be fully verified.

### Upgrading existing installations

The old default was `./incidents`. Leave it as an archive and use the new
default or another trusted output path; the new output starts with empty
history. Do not point a root daemon at a user-owned legacy directory or
recursively change its ownership. A trusted existing output can still be
selected explicitly; complete legacy bundles can be restored, but bundles
without the ownership marker are not automatically deleted. Manually archive or
remove legacy and unrelated files only after verifying their ownership and
contents. Do not copy untrusted ownership markers into a trusted output.

## JSON output

Every command accepts `--format json` and emits a single-line report. Dispatch
on **both** `schema` and `command` and ignore unknown fields:

| Schema | Commands |
| --- | --- |
| `rand-fast/v1` | `sched`, `cpu`, `io`, `off-cpu`, `memory` |
| `rand-fast/v2` | `net`, `diagnose`, `daemon` |

The report envelope includes `schema`, `command`, `pid`, `duration_s`,
`interrupted`, `process_exited`, and command-specific `data`; `process` is
omitted when its name cannot be read. Latencies use microseconds (`_us`), rates
use per-second units (`_per_s`), and byte counts use bytes (`_bytes`).

Unavailable measurements in v2 can be `null`; do not interpret `null` as zero:

- `net` reports `tcp_available: false`, `samples: null`,
  `retransmissions: null`, and an empty `endpoints` array.
- `diagnose` reports `data.measured.tcp_available: false`, with
  `net_samples` and `retrans_ratio` set to `null`. It does not score packet
  loss; independently measured off-CPU socket waits can contribute to a
  network cause.
- Daemon intervals report `tcp_available: false` and `retrans: null`.
  `cpu_percent` is `null` when process accounting is unavailable. A failed
  `/proc` read breaks the baseline; the next successful read starts a new one.
  CPU triggers do not fire on `null`; values above 100 are valid for a
  multithreaded process.

Incident `manifest.json`, `complete.json`, and `diagnosis.json` use v2;
`intervals.json` is an array identified by the manifest's schema. The recorder
can restore v1 incident history. A v1 CPU zero cannot be distinguished from
missing accounting and is not corrected retroactively. Historical TCP counts
are unreliable and are never re-emitted as fresh measurements. A new bundle
can contain restored v1 intervals alongside v2 intervals. Consumers of earlier
reports must handle the v2 schema and unavailable values rather than assuming
all fields are numeric.

## Compatibility and limitations

- Only one process and its threads are observed; this is not a host-wide
  profiler. Container metadata, HTML reports, and remote telemetry are out of
  scope.
- Tracepoint layouts are checked at startup. An unrecognized layout is rejected
  rather than interpreted using unverified offsets. See the requirements in the
  [README](../README.md#requirements) and the support policy below.
- PSI may be unavailable when the kernel lacks `CONFIG_PSI`. Data loss and
  approximate recorder percentiles can affect interpretation.
- Collection has overhead. On the QEMU fixtures, the recorded daemon peak was
  around 4–7% of one CPU; the cost depends on the workload and host.

### Tested kernels and support policy

The compatibility matrix pins a source tarball, a checksum, a configuration
profile and a build record for each cell. A version is advertised as supported
only when its required real-kernel verifier and collector checks pass; a boot
or a skipped check is never evidence of support.

| CI cell | Kernel | Scheduler, CPU, block I/O, off-CPU, memory | TCP attribution |
| --- | --- | --- | --- |
| `6.1.191` | 6.1.191 | supported | unavailable |
| `6.6.161` | 6.6.161 | supported | unavailable |
| `6.12.115` | 6.12.115 | supported | unavailable |
| `7.2.15` | 7.2.15 | supported | unavailable |
| `6.12.115-nopsi` | 6.12.115 | supported; PSI unavailable is explicit | unavailable |

Layout fixtures also exist for 6.12.105 and 7.2.0-rc6, the kernels that were
validated before the matrix was introduced. They are retained as regression
fixtures for the same layout family as 6.12.115 and 7.2.15, but they are not
separate CI cells and are not advertised as independently supported cells.

The layout fixtures record the exact consumed tracepoint fields for each
kernel. 6.1 and 6.6 expose `tcp_probe` without an `skaddr` field, so the
existing TCP profile is not applicable there; TCP is disabled on every kernel
for the ownership reason below, and the matrix therefore tests the non-TCP
collectors. PSI is enabled in the matrix profiles, and the separate 6.12.115
`nopsi` cell proves that missing memory pressure information is reported as
unavailable rather than as zero.

To add a kernel: pin its tarball URL and SHA256 in `tools/kernel/kernels.tsv`
with a configuration profile, add the matrix cell, build the image, capture the
tracefs formats the collectors read, add a fixture and make the fixture test
validate every consumed field, then record the cell result in this table. A
layout change is handled by adding an explicit verified profile, never by
loosening the comparison to guessed offsets.

### Overhead measurement

`tools/bench.sh` records paired baseline/instrumented runs for CPU, I/O, lock
and network workloads and writes `target/bench-report.json`. It reports target
throughput and latency, collector CPU and peak RSS, event loss, and the
kernel/accelerator metadata. The benchmark is reproducible locally and in CI;
see [the benchmark guide](benchmark.md).

### TCP attribution

TCP RTT and retransmission attribution is disabled. `tcp_probe` can run on the
receive path in softirq context, where the current task need not own the
socket. The retransmission tracepoint supplies a socket pointer without a
socket cookie; pointers can be reused, and even a cookie alone does not prove
ownership for shared or transferred sockets. Neither current task nor a
remembered pointer establishes ownership.

The TCP tracepoint programs are not attached and emit no events. Omitted TCP
events cannot be counted per target without reliable attribution, and perf
loss counts do not include those omissions. Restoring this feature requires a
verified ownership source and socket lifetime identity covering sharing, exit,
destruction, and reuse, plus corresponding lifecycle tests. The
[ownership design](tcp-ownership-design.md) records the candidate sources, the
prototype result, and the evidence required before enabling; the prototype did
not establish positive attribution, so the feature remains off.
