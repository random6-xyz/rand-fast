# CI duration

Why a pull request spends about an hour of runner time on the kernel gate, what
the measurement says about where it goes, and which changes were applied to
shorten it.

## What the jobs cost

Measured on run `45138094447` (a `main` push, so the full matrix ran):

| Job | Wall clock | Notes |
| --- | --- | --- |
| `verify` | 4m11s | one cell, no QEMU |
| `qemu-real-kernel` (6.12.115) | 12m54s | of which the guest run is 10m03s |
| `kernel-matrix` (6.1.191) | 11m21s | |
| `kernel-matrix` (6.6.161) | 12m04s | |
| `kernel-matrix` (7.2.15) | 12m55s | |
| `kernel-matrix` (6.12.115-nopsi) | 12m47s | |

A pull request that touches the kernel surface therefore bills roughly 67
minutes across five cells while finishing in about 13 minutes of wall clock.
The two numbers move together only because the cells run in parallel.

Inside one cell the 10m03s guest run is the gate itself: nine scenarios at four
seconds of collection each plus a fixture, about thirty `fast` invocations of
three to thirteen seconds, eighteen trigger bundles, and the TCP ownership
check, all under QEMU's TCG. The rest of the cell is fixed cost: a release build
with the embedded eBPF object plus initramfs staging (1m09s), and toolchain,
LLVM, and apt setup (about 1m35s).

## Where the time goes

| Symptom | Cause |
| --- | --- |
| About 10 minutes of guest time per cell | `tools/qemu-smoke.sh` runs the whole scenario matrix, the trigger bundles, and the TCP ownership check inside one serial guest boot. |
| Five cells per pull request | `tools/kernel/changes.py` treated any change under `fast/` as kernel-sensitive, so report, daemon, incident, and CLI changes demanded the whole matrix. |
| 1m09s of build per cell | `tools/qemu-run.sh` ran `cargo build --release` unconditionally, and each cell starts from a fresh checkout. |
| Repeated toolchain cost | `setup-rust-ebpf` ran `cargo install bpf-linker` in every job with no cache, rebuilding a tool that changes only with its version. |
| A failed pull request can hold a runner for an hour | The guest timeout was 4200s (70 minutes) and the job timeout 180 minutes; with the panic retry a wedged cell could occupy a runner for up to 140 minutes. Run `42817067416` (kernel 6.1.191) spent 1h03m before failing with `missing:rc=0 missing:matrix-pass`. |

## Changes applied

1. **Guest and job timeouts.** `run-qemu-gate` now defaults `guest-timeout` to
   1500s (2.5x the measured 10-minute run), and both QEMU jobs use
   `timeout-minutes: 60`. A wedged cell now fails in at most about 25 minutes,
   50 with the panic retry.
2. **Toolchain cache.** `setup-rust-ebpf` caches `~/.cargo/bin`,
   `~/.cargo/registry`, and `~/.cargo/git`, and skips `cargo install` when
   `bpf-linker --version` already reports 0.9.14.
3. **One build, shared artifact.** A new `build` job builds the release
   binaries on `ubuntu-22.04` and uploads `fast-binaries`; the QEMU jobs depend
   on it, restore the artifact into `target/release`, restore the executable
   bit, and pass `SKIP_BUILD=1` to `tools/qemu-run.sh`. The binary presence
   checks still run, so a staging error is not hidden.
4. **Narrower change classification.** `tools/kernel/changes.py` now treats a
   path as kernel-sensitive only when it can change what a kernel does with the
   program: `fast-ebpf/`, `fast-common/`, the collectors that read a tracepoint
   or a socket (`fast/src/{tracepoint_layout,io_request_layout,tcp_ownership,tcp,network,memory}.rs`),
   the object's build inputs (`fast/build.rs`, `fast/Cargo.toml`, `Cargo.toml`,
   `Cargo.lock`, `rust-toolchain*`, `.cargo/`), the harness (`tools/kernel/`,
   `tools/qemu-*`, `tools/scenarios*`, `tools/check-qemu-results.sh`,
   `tools/rank-eval.sh`, the guest workloads), and `.github/`. A change to
   report formatting, the daemon, incidents, the CLI, the tests, or the
   documentation keeps the always-on 6.12.115 gate and skips the matrix.

## Expected effect

- Kernel-surface pull request: about 60 minutes billed once the kernel cache
  is warm, about 11 minutes of wall clock.
- User-space-only pull request: about 25 minutes billed (one gate cell plus
  `verify`), unchanged wall clock of about 13 minutes.
- A wedged cell: at most about 25 minutes instead of an hour.
- Scheduled and `main`-push runs keep the full five-cell matrix, so the
  compatibility claim is unchanged.

## Measured after the change

The first kernel-surface run that went through the new layout was PR #98
(run 45343837317, commit `a5a595d`):

| Job | Before | After |
| --- | --- | --- |
| `build` | 4m6s | 2m3s |
| `verify` | 4m11s | 3m8s |
| gate cell 6.12.115 | 12m55s | 11m0s |
| gate cell 6.12.115-nopsi | 11m55s | 10m49s |
| matrix 6.6.161 | 11m55s | 10m13s |
| matrix 6.1.191 | 11m21s | 16m37s |
| matrix 7.2.15 | 11m29s | 16m5s |
| billed total | about 67 min | about 70 min |
| wall clock | 12m57s | 18m45s |

Warm cells shed the build they no longer perform and land at 10-11 minutes
after losing the roughly 1.5 minutes of `cargo build` each had paid. The two
16-minute cells are the caveat: the kernel cache is keyed per branch and is
only written on a successful cell, so the earlier run on the same branch that
died at the binary check left nothing behind and both of those cells built
their kernels from source. A first run on any branch can pay that cost, which
is why the billed total did not move on this measurement even though the
steady-state per-cell time did.

The structural win is the user-space path, where the matrix no longer runs at
all; the kernel path stays guest-bound until the guest run itself is split.

## Not done

- **Sharding the guest run.** Splitting the scenarios across cells, or running
  several guests per cell, is the largest remaining win, but it multiplies the
  kernel download and boot cost and complicates the single-log audit that makes
  the gate meaningful. It needs its own design.
- **KVM runners.** A self-hosted runner with `/dev/kvm` would cut the guest time
  by an order of magnitude. That is an infrastructure decision, not a workflow
  change, so it stays a documented option.
- **Caching the built kernel across cells.** The existing per-cell kernel cache
  already covers the common case; sharing it across jobs would need an artifact
  of several hundred megabytes and does not pay off on a cache hit.

## Rollback

The four changes are independent: reverting the commit that introduced one
leaves the others working. `SKIP_BUILD` defaults to 0, so a local
`tools/qemu-run.sh` invocation behaves exactly as before.
