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
| `net` | Measure TCP RTT, retransmissions and connection setup for owned connections. |
| `daemon` | Keep a rolling window and write incident bundles. |
| `incidents` | Read, summarize, and export recorded incident bundles. |

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

`manifest.json` records `recorded_at_s` (elapsed from the start of the run) and,
from v0.4.0, `recorded_at_unix_s` and `recording_started_unix_s` (whole seconds
of wall clock). The wall clock is what places an incident in an operator's day;
the elapsed value is what places it inside its own recording. Bundles written
before v0.4.0 have no wall clock, and readers report it as absent rather than
estimating it.

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

`--max-disk-bytes` defaults to `512m`; `--max-incidents` defaults to off. Both
caps are checked after writing an incident and are **soft ceilings**. When the
directory is over either cap, the oldest bundles are removed first and the
incident that just triggered is never removed. Rotation only deletes bundles it
can prove it owns. Legacy bundles and unrelated files are counted but not
deleted; an oversized incident, unreadable entry, interrupted bundle, or
rotation failure can also leave the directory over the cap. The recorder warns
when the size cannot be fully verified.

### Upgrading existing installations

The old default was `./incidents`. Leave it as an archive and use the new
default or another trusted output path; the new output starts with empty
history. Do not point a root daemon at a user-owned legacy directory or
recursively change its ownership. A trusted existing output can still be
selected explicitly; complete legacy bundles can be restored, but bundles
without the ownership marker are not automatically deleted. Manually archive or
remove legacy and unrelated files only after verifying their ownership and
contents. Do not copy untrusted ownership markers into a trusted output.

### Reading incidents

`fast incidents` reads what the recorder wrote. The commands are read-only, do
not load eBPF, and need only filesystem read access, so a root-owned recording
can be inspected with `sudo` and a user's own recording without it.

```bash
sudo fast incidents list                       # newest first, with what was skipped
sudo fast incidents list --since 24h --limit 5
sudo fast incidents show latest                # one bundle in full
sudo fast incidents summary --since 7days      # aggregate over the window
sudo fast incidents export latest --format markdown --output incident.md
```

| Command | Options | Notes |
| --- | --- | --- |
| `list` | `--limit N`, `--since DURATION`, `--dir`, `--format` | `--limit 0` shows all. |
| `show` | `NAME\|latest`, `--dir`, `--format` | Incomplete bundles are shown, not refused. |
| `export` | `NAME\|latest`, `--format text\|markdown\|json`, `--output PATH\|-`, `--force` | Default file name is `NAME.EXT`. |
| `summary` | `--since DURATION`, `--dir`, `--format` | Counts what the directory holds; deleted incidents are gone. |

`--dir` defaults to the daemon's default output for the effective user, so
`sudo fast incidents list` reads root's directory. `latest` is the newest
readable bundle by recorded wall-clock time; bundles without one are ordered by
name, which is why a v0.3.0 bundle can still be inspected.

The reader enforces its own rules, which are looser than the writer's and
stricter than a plain directory listing:

- Every bundle and bundle file is opened relative to an already-open directory
  with `O_NOFOLLOW`; symlinked components, symlinked bundles, and files that are
  not regular files are refused instead of followed.
- The `.rand-fast-incident` marker defines a bundle. A directory without it is
  reported as skipped user data, not as a damaged incident.
- Every read is bounded: 1 MiB for `manifest.json`, `diagnosis.json`,
  `complete.json`, and `summary.txt`; 8 MiB for `intervals.json` and
  `slow-samples.json`; at most 64 files per bundle.
- Ownership equality and the "not group/other writable" rule are **not**
  enforced on read: reading root's directory as root, or another user's bundle
  with permission, is the point. A reader that demanded the writer's rules
  could not do either.

Nothing is recomputed. A bundle's `manifest.json` and `diagnosis.json` are
reported as recorded; an unavailable measurement stays unavailable and is never
rendered as zero. A bundle that fails to parse is named with the offending file
and the command exits 1 rather than printing a plausible report.

`list` and `summary` exit 0 on a missing or empty directory; `show` and `export`
exit 1 when there is nothing readable to select. Usage errors exit 2. Rotation
means history is bounded: `summary` covers what the directory still holds and
states that rotated-away incidents are not included.

## JSON output

Every command accepts `--format json` and emits a single-line report. Dispatch
on **both** `schema` and `command` and ignore unknown fields:

| Schema | Commands |
| --- | --- |
| `rand-fast/v1` | `sched`, `cpu`, `io`, `off-cpu`, `memory` |
| `rand-fast/v2` | `net`, `diagnose`, `daemon` |
| `rand-fast/v3` | `incidents.list`, `incidents.show`, `incidents.export`, `incidents.summary` |

The report envelope includes `schema`, `command`, `pid`, `duration_s`,
`interrupted`, `process_exited`, and command-specific `data`; `process` is
omitted when its name cannot be read. Latencies use microseconds (`_us`), rates
use per-second units (`_per_s`), and byte counts use bytes (`_bytes`).

Unavailable measurements in v2 can be `null`; do not interpret `null` as zero:

- `net` reports `tcp_available` as whether ownership was established, not
  whether traffic happened. A target that holds no TCP socket is available
  with `samples: 0` and an empty `endpoints` array; `tcp_reason` explains every
  unavailable measurement when attribution itself failed.
- `net` endpoints are per-direction connections keyed by 5-tuple. `role` is
  `client` for a connection the target opened and `server` for one accepted on
  a listener it owns; `origin` is `created` when this run saw the connection
  created and `seeded` when the target's descriptor table is the evidence.
  `ownership_verified` is always true for a published row: an unverified row is
  dropped and counted in `attribution.unverified_endpoints`.
- `connection_latency` covers client handshakes only. Accepted sockets and
  pre-existing connections have no observable start, so `available` is false
  with a reason instead of a zero.
- `retrans_ratio` is always `null`: the tracepoints carry no
  transmitted-segment denominator. Use `retransmissions` and
  `retransmissions_per_second`.
- `attribution` states how many endpoints were excluded because the target
  stopped holding the socket, how many owner records the kernel dropped, and
  how many events had no owner.
- `diagnose` reports `data.measured.tcp_available` and `tcp_reason`, plus
  `net_rtt_p95_us`, `net_connect_p95_us`, `net_connects`,
  `net_connect_failures`, `retrans_per_second`. All TCP fields are `null` when
  attribution is unavailable, and the ranking then falls back to
  independently measured off-CPU socket waits.
- Daemon intervals report `tcp_available`, `tcp_reason`, `retrans` (null when
  attribution is unavailable), `net_rtt_p95_us`, `net_connect_p95_us`,
  `net_connects`, and `net_connect_failures`.
  `cpu_percent` is `null` when process accounting is unavailable. A failed
  `/proc` read breaks the baseline; the next successful read starts a new one.
  CPU and retransmission triggers do not fire on `null`; values above 100 are
  valid for a multithreaded process.

Incident reader documents use v3 and do not follow the report envelope: they
describe a directory or a bundle, not a process run. They embed the bundle's
own documents verbatim (raw JSON, not a re-serialization) so a consumer reads
exactly what the recorder wrote. `incidents.list` reports `directory_exists`,
the applied filters, `count`/`total`, `unreadable_count`,
`excluded_without_timestamp`, and a `skipped` list with a reason per entry.
`incidents.show` reports the file list, the missing files, and the documents.
`incidents.summary` reports counts, the observed time range, trigger and
top-cause counts, and `share_of: "readable bundles"` for its shares.

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
| `6.1.191` | 6.1.191 | supported | supported |
| `6.6.161` | 6.6.161 | supported | supported |
| `6.12.115` | 6.12.115 | supported | supported |
| `7.2.15` | 7.2.15 | supported | supported |
| `6.12.115-nopsi` | 6.12.115 | supported; PSI unavailable is explicit | supported |

Layout fixtures also exist for 6.12.105 and 7.2.0-rc6, the kernels that were
validated before the matrix was introduced. They are retained as regression
fixtures for the same layout family as 6.12.115 and 7.2.15, but they are not
separate CI cells and are not advertised as independently supported cells.

The layout fixtures record the exact consumed tracepoint fields for each
kernel. 6.1 and 6.6 expose `tcp_probe` without an `skaddr` field; the collector
does not read that field, because ownership and the event join both use the
connection tuple, so those kernels are supported for TCP as well. PSI is enabled in the matrix profiles, and the separate 6.12.115
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
see [the benchmark guide](benchmark.md). Calibrated thresholds and the baseline
refresh procedure are in [the gate policy](benchmark-gates.md).

### TCP attribution

A TCP measurement is published only for a connection whose owner is proven:
either the target's own thread group created it (`connect`, `listen`) or the
target holds its descriptor according to `/proc/<pid>/fd` and
`/proc/<pid>/net/tcp{,6}`. The join key is the connection 5-tuple, never a
kernel pointer, and the record is removed when the socket closes. An unrelated
process, a pre-existing connection that was handed away, and an address whose
listener has more than one owner are reported as unattributed rather than
guessed at.

Measurement limits, all stated in the output:

- RTT samples come from `tcp_probe`'s smoothed RTT, at most one per connection
  per 10 ms. `samples` counts those samples, not packets.
- Retransmissions are counted from `tcp_retransmit_skb`; there is no
  transmitted-segment denominator, so no ratio is reported.
- Connection setup latency covers client handshakes only. Accepted sockets
  have no observable handshake start.
- A busy host costs a short map lookup per TCP state change in the namespace;
  the benchmark gate measures the collector's own overhead.

The [ownership design](tcp-ownership-design.md) records the evidence rules,
the kernel objects, and the unavailable cases in full.
