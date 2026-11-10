# rand-fast

`rand-fast` helps answer one question about a Linux server: **why is this
process slow?** It observes one process and its threads with eBPF, measures
scheduler, CPU, block I/O, off-CPU, and memory signals, and ranks likely causes.
A flight recorder can also retain recent intervals when a trigger fires.

## Requirements

- Linux with `CONFIG_BPF`, `CONFIG_BPF_SYSCALL`, `CONFIG_BPF_EVENTS`, and
  `CONFIG_DEBUG_INFO_BTF`, plus tracefs mounted under `/sys/kernel/tracing` or
  `/sys/kernel/debug/tracing`.
- Permission to load eBPF and open perf events: root, or `CAP_BPF` and
  `CAP_PERFMON` on kernel 5.8+, or `CAP_SYS_ADMIN` on older kernels.
- Read access to `/proc/<pid>/fd` and `/proc/<pid>/net/tcp{,6}` for the
  observed process, which is how TCP socket ownership is evidenced. Root, or
  the same user as the target, has it; without it TCP is reported as
  unavailable with a reason and the other collectors still run.
- Recognized scheduler, block-request, and TCP tracepoint layouts. Unrecognized
  layouts are rejected at startup. The CI matrix pins Linux 6.1.191, 6.6.161,
  6.12.115 and 7.2.15, plus a PSI-off 6.12.115 cell; layout fixtures also cover
  6.12.105 and 7.2.0-rc6. See the
  [support policy](docs/reference.md#tested-kernels-and-support-policy).

TCP RTT, retransmissions and connection setup latency are reported for
connections whose owner is proven: either the target created the connection or
it holds the socket's descriptor. Events from unrelated processes are never
attributed. See the [reference](docs/reference.md#tcp-attribution) for the
limits, including why accepted sockets have no handshake latency and why no
retransmission ratio is reported.

## Install a release

Prebuilt archives target Linux x86_64 and embed the eBPF object. Pick a version
from [GitHub Releases](https://github.com/random6-xyz/rand-fast/releases/latest)
and replace `v0.4.0` below with that tag.

```bash
VERSION=v0.4.0
BASE_URL="https://github.com/random6-xyz/rand-fast/releases/download/${VERSION}"
ARCHIVE="rand-fast-${VERSION}-linux-x86_64.tar.gz"

curl --fail --location --remote-name "${BASE_URL}/${ARCHIVE}"
curl --fail --location --remote-name "${BASE_URL}/SHA256SUMS"
sha256sum --check SHA256SUMS
tar -xzf "$ARCHIVE"
cd "rand-fast-${VERSION}"
```

## Start diagnosing

Replace `1234` with the target process ID:

```bash
sudo ./fast diagnose --pid 1234 --duration 10s
```

The report lists measurements and ranks likely causes. A confidence value is a
cause's share of the measured slowdown, **not** the probability that it is the
root cause. Use `--format json` for machine-readable output. For TCP, the
report names the connections it attributes, excludes sockets the target no
longer holds, and states when a measurement is unavailable instead of showing
a zero.

To record a rolling window and write incidents when a threshold is crossed:

```bash
sudo ./fast daemon --pid 1234 --trigger-retrans off
```

The daemon runs until interrupted or the target exits; `--duration` can bound
it. `--max-incidents` and `--max-disk-bytes` bound what it keeps.

Read what it recorded:

```bash
sudo fast incidents list --since 24h
sudo fast incidents show latest
sudo fast incidents export latest --format markdown --output incident.md
```

These commands are read-only and report unavailable measurements as
unavailable, never as zero. A bundle written before v0.4.0 carries no wall
clock; it is reported that way rather than dated from its file timestamp.

See the [reference](docs/reference.md) for command options, JSON output,
incident storage, and measurement limitations, and
[operations](docs/operations.md) for running the recorder under systemd and
reading it on a production host. Run `./fast --help` or
`./fast <command> --help` for the complete CLI options.

## Documentation

- [Reference](docs/reference.md): commands, JSON, incident storage, and limits.
- [Operations](docs/operations.md): running the recorder and reading incidents.
- [Development](docs/development.md): project structure, building, and QEMU
  verification.

## License

Licensed under either the [MIT License](LICENSE-MIT) or the
[Apache License, Version 2.0](LICENSE-APACHE). Release archives also include
third-party Rust dependency license texts.
