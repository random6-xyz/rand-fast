# Verification

Two gates cover `rand-fast`. The first runs on the development host; the second
needs a real kernel and runs inside QEMU, without host `sudo`.

## Host gate

```bash
tools/verify.sh
```

It runs, in order:

1. `cargo fmt --all -- --check`
2. `cargo clippy --workspace --all-targets -- -D warnings`
3. `cargo build --release`
4. `cargo test --workspace`
5. `tools/test-qemu-smoke.sh` — mock verifier/load failures propagate and
   children are stopped
6. `tools/test-qemu-run.sh` — documented argument forms reach the help path
7. `tools/check-no-cjk.sh` — no CJK characters in tracked content
8. `tools/check-license-metadata.sh` — every workspace package declares both
   licenses

A run is only good when the script exits zero.

## QEMU gate

```bash
tools/qemu-run.sh --duration 5s
```

The runner builds the initramfs around `tools/qemu-guest-init.sh`, boots the
bpf-next kernel under KVM, runs `tools/qemu-smoke.sh` inside the guest, and
prints the reports. `OUT_DIR` selects a host staging directory; `KERNEL` selects
another bzImage. The guest is packed root-owned with normal permissions so it
looks like a real Linux root filesystem to the incident store.

The matrix covers:

- one verifier/load run per collector, plus `diagnose` running every stream
  from one load
- scheduler latency on an idle target against external contention
- CPU sampling rate scaling and symbolized on-CPU stacks
- per-request block I/O attribution, including same-sector concurrency
- off-CPU waits on a CPU-bound hog against a futex-bound workload, thread-exit
  cleanup, and wait-reason ranking
- memory fault counters against `/proc`, PSI availability, and the memory verdict
- diagnosis ranking for five single-bottleneck fixtures
- daemon rolling intervals, its self-measured cost, each trigger, incident
  storage, restart restoration, and disk-cap rotation
- the TCP-unavailable contract for `net`, `diagnose`, `daemon`, and incident
  bundles, including the disabled retransmission trigger

TCP tracepoint programs are intentionally not attached. A verifier pass for
them is not claimed; the guest prints `TCP verifier: SKIP` instead.

Last recorded result for the storage/collection work: the full matrix passed on
the bpf-next 7.2.0-rc6 image with 8 vCPUs and no `CONFIG_PSI`, including the
daemon cost budget and storage rotation. Absolute latency and cost numbers vary
with the host and are not acceptance thresholds except where the smoke script
states one.
