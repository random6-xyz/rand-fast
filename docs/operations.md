# Operating the flight recorder

This guide is for the person who runs `fast daemon` on a server and reads what
it recorded later. It does not explain the measurements themselves; the
[reference](reference.md#flight-recorder) does that.

## Start the recorder

```bash
sudo fast daemon --pid 1234 --trigger-retrans off
```

The recorder runs until it is interrupted or the target exits. Run
`sudo fast daemon --pid 1234 --duration 0s` when you want an unbounded run
explicitly, and set `--output` when the default path is not the right place.

`fast daemon --help` lists the thresholds, the interval and window lengths, and
the retention options. The defaults are chosen for a long-running server: a one
second interval, a 60 second window, and a 512 MiB cap on the output directory.

### Under systemd

`contrib/systemd/rand-fast@.service` is a template unit that starts a recorder
for one process ID:

```bash
sudo install -D -m 0644 contrib/systemd/rand-fast@.service /etc/systemd/system/rand-fast@.service
sudo systemctl daemon-reload
sudo systemctl enable --now rand-fast@1234
```

The unit runs as root with `StateDirectory=rand-fast`, so bundles land in
`/var/lib/rand-fast/incidents`, and keeps the newest 200 bundles. Restarting
the unit restores the previous window when it can.

A recorder is tied to a process ID, which is not stable across a redeploy.
Start a new instance with the new PID and stop the old one; do not point two
recorders at the same output directory, because both would rotate the other's
bundles.

## Read what was recorded

```bash
sudo fast incidents list
sudo fast incidents show latest
sudo fast incidents summary --since 24h
sudo fast incidents export latest --format markdown --output incident.md
```

`list` prints one row per incident, newest first, and states what it left out:
unreadable bundles, entries that are not bundles, and, when `--since` is used,
bundles that carry no recorded time. `show` prints one bundle in full. `export`
writes the bundle's own `summary.txt` (or a generated report when it is
missing) to a file or to standard output; it refuses to overwrite an existing
file without `--force`.

Read commands never need eBPF and never write to the incident directory. They
require only the file permissions to read it, so a root-owned production
directory can be read with `sudo`, and a user's own recordings can be read
without it. `--dir` selects another directory; the default follows the same
rule as the daemon.

Rotation deletes the oldest bundles. A read command can only report what is
still on disk, and no command reconstructs a deleted incident: `summary` says so
explicitly. If you need a long history, export the bundles you care about.

### Bundles written before v0.4.0

A bundle written by v0.3.0 has no wall-clock time in its manifest; it records
only how far it was into its own recording. `fast incidents` shows such a
bundle as `-` in the time column, never guesses a time from the file's
modification time, and leaves it out of any `--since` window while counting it.
Everything else about the bundle is read normally.

## Retention

Two independent caps apply, and both are checked after each incident write:

- `--max-disk-bytes` (default `512m`) bounds the bytes the directory holds.
- `--max-incidents` (default off) bounds the number of bundles.

When the directory is over a cap, the oldest bundles are removed first, and the
incident that just triggered is never removed. Rotation only deletes bundles it
can prove the recorder created: the ownership marker, the expected file set,
and file ownership are re-checked immediately before deletion. Anything else,
including bundles from an older version and unrelated files, is counted and
left in place. Both caps are soft: an oversized or unreadable entry can leave
the directory over its cap, and the recorder warns when that happens.

For a host that trips often, set both: a byte cap alone bounds the disk but can
leave thousands of small bundles, which makes `list` and `summary` slow to read.

## Troubleshooting

- `unsafe incident output`: the output path has an untrusted ancestor, a
  symlink, or group/world-writable permissions. Choose a trusted path; see the
  [reference](reference.md#output-and-retention).
- `no readable incident`: the directory holds nothing a reader can use. Check
  `list` for the entries it skipped and why.
- `is unreadable` or `is damaged`: a bundle was changed after the recorder
  wrote it, or a write was interrupted. The message names the file; the bundle
  is not repaired or guessed at.
- The daemon exits when the target exits. For a service that restarts often,
  supervise the recorder and restart it with the new process ID.
