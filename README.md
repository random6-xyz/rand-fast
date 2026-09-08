# rand-fast

`rand-fast` is a Linux performance diagnostic tool. The first version measures scheduler latency for a process and its threads using Aya and eBPF.

## Requirements

- Linux 5.8+ with BTF (validated on 6.12.105 host and 7.2.0-rc6 QEMU guest; `sched_wakeup`/`sched_switch` tracepoints have been available since 2.6)
- Kernel built with `CONFIG_BPF`, `CONFIG_BPF_SYSCALL`, `CONFIG_BPF_EVENTS`, `CONFIG_DEBUG_INFO_BTF`
- Scheduler tracepoints at `/sys/kernel/debug/tracing/events/sched/sched_wakeup` (or `/sys/kernel/tracing`)
- Rust nightly with the `rust-src` component
- `bpf-linker` (0.9.x, e.g. `LLVM_SYS_191_PREFIX=/usr/lib/llvm-19 cargo install bpf-linker --version 0.9.14`)
- Permission to load eBPF programs and open perf events: `root`, or `CAP_BPF` + `CAP_PERFMON` (kernel 5.8+), or `CAP_SYS_ADMIN` on older kernels
- QEMU 7.2+ with KVM (`/dev/kvm`) for verifier and privileged smoke tests without host `sudo` (uses `kernel-server` `bpf-next` `bzImage` and `~/.bpf_selftests/root.img`)

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
```

For a contention run, start a second helper in parallel:

```bash
./target/release/sched-workload hog --duration 30s --workers 8
```

## Scope

The v0.1 command measures runnable-to-running scheduler latency only. Disk, network, memory, lock contention, profiling, automatic diagnosis, and long-running recording are planned for later versions.
