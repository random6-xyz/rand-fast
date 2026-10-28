# Daemon JSON v2 migration

Daemon JSON reports and incident bundles now use `rand-fast/v2`. Other command
reports continue to use `rand-fast/v1`. In a daemon report, the version appears
in the envelope's `schema` field. In an incident bundle it appears in
`manifest.json`, `complete.json`, and `diagnosis.json`; `intervals.json` is an
array whose version is identified by the bundle manifest.

In `data.intervals_detail` and incident `intervals.json`, `cpu_percent` remains
a number when measured, but is `null` when process accounting is unavailable.
Consumers must distinguish `null` from a measured zero and accept values above
100 for workloads using multiple CPUs. A failed read breaks the accounting
baseline, so the next successful read establishes a new baseline rather than
reporting a multi-interval average. CPU triggers do not fire on `null`.

The daemon still restores v1 incident history: a numeric `cpu_percent` is read
as recorded. Previously recorded zeroes cannot be distinguished from missing
accounting in v1 and are not retroactively corrected. New bundles may contain
restored v1 intervals alongside v2 intervals; their numbers retain their
original meaning.
