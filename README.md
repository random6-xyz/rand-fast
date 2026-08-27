# rand-fast

`rand-fast` is a Linux performance diagnostic tool. The first version measures scheduler latency for a process and its threads using Aya and eBPF.

## Requirements

- Linux with scheduler tracepoints available
- Rust nightly with the `rust-src` component
- `bpf-linker`
- Permission to load eBPF programs and open perf events (`root`, or suitable `CAP_BPF`/`CAP_PERFMON` capabilities)

The build script compiles the eBPF object with `bpfel-unknown-none` and embeds it in the userspace binary.

## Build

```bash
cargo build --release
```

## Usage

```bash
sudo ./target/release/fast sched --pid 1234 --duration 10s
```

`--pid` is the process ID (TGID). Existing threads are discovered through `/proc/<pid>/task` and synchronized while the collection is running.

The report contains overall p50, p95, p99, and maximum latency, running-CPU summaries, slow-event thresholds, and perf-buffer loss counts.

## Tests

```bash
cargo test -p fast-common -p fast
cargo clippy -p fast --all-targets -- -D warnings
```

The eBPF object is built as part of these commands. A privileged Linux smoke test is still required to verify tracepoint attachment and to compare idle and CPU-contention workloads.

A small tracked workload helper is available for that comparison:

```bash
# In one shell, start a periodic target.
./target/release/sched-workload target --duration 30s --period 1ms

# In another shell, use the printed target PID while the target is running.
sudo ./target/release/fast sched --pid <TARGET_PID> --duration 10s
```

For a contention run, start a second helper in parallel:

```bash
./target/release/sched-workload hog --duration 30s --workers 4
```

## Scope

The v0.1 command measures runnable-to-running scheduler latency only. Disk, network, memory, lock contention, profiling, automatic diagnosis, and long-running recording are planned for later versions.
