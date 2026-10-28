# Daemon JSON v2 migration

Daemon reports and incident bundles use `rand-fast/v2`. Other command reports
remain on `rand-fast/v1`. In a report the version is the envelope's `schema`
field; in a bundle it appears in `manifest.json`, `complete.json`, and
`diagnosis.json`. `intervals.json` is an array whose version is identified by
the bundle manifest.

## Unavailable values are null

- `cpu_percent` is a number when measured and `null` when process accounting is
  unavailable. A failed `/proc` read breaks the baseline; the next successful
  read starts a new one instead of averaging across the gap. CPU triggers do not
  fire on `null`. Values above 100 are valid for a multi-threaded process.
- `retrans` is `null` and `tcp_available` is `false` because this build does not
  attribute TCP events. The retransmission trigger cannot fire; the recorder
  warns at startup when it is configured.

Consumers must distinguish `null` from a measured zero.

## Restoring v1 history

The recorder still restores v1 incident history. A numeric `cpu_percent` is read
as recorded, but a recorded zero cannot be distinguished from missing accounting
and is not retroactively corrected. TCP numbers from v1 bundles are retained as
history and are never re-emitted as fresh measurements. New bundles may contain
restored v1 intervals alongside v2 intervals; each number retains its original
meaning.

## Interval semantics

Scheduler p95 and I/O p99 are computed from the samples in that interval, not
from the whole run. The recorder uses a bounded histogram, so a percentile is a
bucket lower bound and can be up to 12.5% low for a sample in that bucket.
Triggers close to a threshold can therefore be delayed by one interval. Queue
and kernel perf losses are reported separately from samples.
