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
- Recognized scheduler, block-request, and TCP tracepoint layouts. Unrecognized
  layouts are rejected at startup; layouts have been verified on Linux 6.12.105
  and 7.2.0-rc6.

TCP RTT and retransmission attribution is **unavailable**: the tracepoints do
not reliably identify a socket's owning process. Network ranking may still use
independently measured off-CPU socket waits. See the
[reference](docs/reference.md#tcp-attribution) for the limitations.

## Install a release

Prebuilt archives target Linux x86_64 and embed the eBPF object. Pick a version
from [GitHub Releases](https://github.com/random6-xyz/rand-fast/releases/latest)
and replace `v0.2.1` below with that tag.

```bash
VERSION=v0.2.1
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
root cause. Use `--format json` for machine-readable output.

To record a rolling window and write incidents when a threshold is crossed:

```bash
sudo ./fast daemon --pid 1234 --trigger-retrans off
```

The daemon runs until interrupted or the target exits; `--duration` can bound
it. See the [reference](docs/reference.md) for command options, output formats,
incident storage, and measurement limitations. Run `./fast --help` or
`./fast <command> --help` for the complete CLI options.

## Documentation

- [Reference](docs/reference.md): commands, JSON, incident storage, and limits.
- [Development](docs/development.md): project structure, building, and QEMU
  verification.

## License

Licensed under either the [MIT License](LICENSE-MIT) or the
[Apache License, Version 2.0](LICENSE-APACHE). Release archives also include
third-party Rust dependency license texts.
