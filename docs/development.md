# Development

## Project structure

- `fast/`: CLI, collectors, diagnosis, reporting, and flight recorder.
- `fast-ebpf/`: eBPF programs loaded into the kernel.
- `fast-common/`: types shared by kernel and userspace.
- `tools/`: verification, QEMU runner, release packaging, test workloads, and
  the pinned kernel pipeline under `tools/kernel/`.
- `fast/tests/fixtures/tracepoints/`: tracepoint layout test fixtures.

## Build

Source builds need Rust nightly with `rust-src`, LLVM 19, and `bpf-linker`
0.9.x. The repository's `rust-toolchain.toml` selects nightly and `rust-src`.
With LLVM 19 already installed, install the linker and build:

```bash
LLVM_SYS_191_PREFIX=/usr/lib/llvm-19 cargo install bpf-linker --version 0.9.14
cargo build --release
```

The build produces `target/release/fast`, `target/release/sched-workload`, and
`target/release/fast-workload`. Release packaging also requires `cargo-about`
0.9.2 to generate third-party license notices.

## Verification

`tools/verify.sh` runs the development gate:

1. `cargo fmt --all -- --check`
2. `cargo clippy --workspace --all-targets -- -D warnings`
3. `cargo build --release`
4. `cargo test --workspace`
5. `tools/test-qemu-smoke.sh`: mock verifier/load failure propagation and child
   cleanup
6. `tools/test-qemu-run.sh`: runner argument handling
7. `tools/test-scenarios.sh`: the scenario manifest and the generated guest
   table agree, including fixture-argument quoting
8. `tools/test-rank-eval.sh`: the ranking gate rejects missing, empty, and wrong
   runs
9. `tools/test-qemu-ci.sh`: the CI guest-log audit rejects partial runs
10. `tools/test-kernel-build.sh`: the kernel pin table and build failure paths
11. `tools/check-license-metadata.sh`: workspace license metadata

The gate succeeds only when the script exits zero. The eBPF verifier and real
kernel behavior require the separate QEMU gate below; a host-only gate is not a
substitute for it.

### Diagnosis scenarios

`tools/scenarios.json` is the single source of truth for the diagnosis matrix:
each scenario declares its fixture, optional background commands, the
prerequisites it genuinely needs, its collection duration, and the evidence the
guest must observe. `tools/scenarios-generate.sh` turns it into the
dependency-free `tools/scenarios.sh` table that `tools/qemu-smoke.sh` sources;
`tools/test-scenarios.sh` fails the gate when the two disagree. Edit the JSON,
rerun the generator, and commit both.

A required prerequisite that is missing fails the scenario. The only
prerequisites currently declared are `tracefs`, `btf`, a real `block_device`
(the guest's ext4 virtio disk), and `cpu2`; PSI is not required by any
scenario. Fixtures write `--report` JSON themselves, so each case has an
independent record of its operations and latency next to the collector's
measurement, and `--ready-file` replaces fixed sleeps during startup.

Scenario kinds separate proof from ranking work: `positive` cases must produce
the declared measurement and at least one declared cause, `mixed` cases must
produce both declared signals and one accepted cause, and the `control` case
must not report any bottleneck cause.

### Real-kernel CI gate

The `qemu-real-kernel` job in `.github/workflows/ci.yml` runs on every pull
request and main push. It provisions QEMU and kernel build tools, builds the
kernel pinned in `tools/kernel/kernels.tsv` from its verified tarball with
`tools/kernel/config.fragment`, boots the guest with
`tools/qemu-run.sh`, and audits the guest log with
`tools/check-qemu-results.sh`.

The audit is what makes the job meaningful: a missing BTF/tracefs facility, a
required verifier check that did not run, an unexpected `SKIP`, a scenario
failure, the wrong kernel version, or a non-zero guest exit fails the job.
The only accepted skip is the documented TCP unavailable one. The job always
uploads the guest log, the kernel config and build record, the cell record, and
the loader diagnostics, including on failure. The kernel cache is keyed by the
version, the config fragment, and the build script, so a source change rebuilds
and an unchanged matrix does not.

GitHub-hosted runners have no `/dev/kvm`, so the job runs under QEMU's TCG
emulation with a 70-minute guest timeout and a 180-minute job timeout; the
kernel build dominates the first uncached run. The same path is reproducible on
a KVM host with `ACCEL=tcg CPUS=2 tools/qemu-run.sh`. `QEMU_TIMEOUT` bounds the guest
and `CPUS`/`MEM_MB` keep the guest inside the runner. A self-hosted runner with
`/dev/kvm` uses KVM automatically and records the accelerator in the log. The
local reproduction is the same command sequence documented above, with the
`KERNEL` path printed by `tools/kernel/build.sh 6.12.115`.

### Ranking accuracy

Ranking accuracy is measured separately by `tools/rank-eval.sh`, which repeats
every declared scenario (`RANK_REPETITIONS`, default 3), keeps each diagnose
document and fixture report under `$OUT_DIR/rank/raw/`, and writes
`runs.tsv`, `rank-report.json`, and `rank-summary.txt`. The guest has no shared
filesystem with the host, so the guest init prints the report, the row table,
the summary, and every raw document into the console log that `qemu-run.sh`
keeps as `$OUT_DIR/guest.log`; those are the CI artifacts. A host run leaves
the same content as files under `$RANK_OUT`.

The report separates two things that must not be confused:

- **Deterministic checks**: every run must satisfy its scenario's declared
  measurements and causes, including the control's excluded causes. A single
  violation fails the run.
- **Descriptive rates**: top-1 and top-3 rates, control false positives,
  missing-evidence runs, and lost-event runs are published so a systematic
  misclassification can be argued from data rather than guessed at.

Scoring is changed only when these rates show a reproduced misclassification;
the raw documents stay in the artifact set so the change can be checked. One
limitation is visible in the data rather than hidden by it: a fixture whose
target sleeps between cycles reports that self-imposed sleep as `Other waiting`,
so scheduler contention can be the second cause (top-3) while `Other waiting`
keeps the top-1 share. The manifest therefore requires the scheduler signal to
be present and ranked, not to outrank the fixture's own sleep.
Enable the evaluation with `RANK_EVAL=1 tools/qemu-run.sh` (the guest repeats
the matrix once more and gates on the deterministic checks).

### QEMU gate

Run the real-kernel tests inside QEMU without host root. Provide an appropriate
kernel image explicitly; the runner's built-in default points to a
machine-specific build path. The host needs `qemu-system-x86_64`, `cpio`, `busybox`, `e2fsprogs`, a C
compiler capable of static linking, and the source build requirements above.
KVM is used when `/dev/kvm` is usable; otherwise the runner falls back to TCG.
`ACCEL=auto|kvm|tcg` overrides that choice (`kvm` fails instead of falling
back, `tcg` forces the emulated path used by GitHub-hosted runners), and
`QEMU_TIMEOUT` bounds the guest.

```bash
KERNEL=/path/to/bzImage tools/qemu-run.sh --duration 5s
RANK_EVAL=1 KERNEL=/path/to/bzImage tools/qemu-run.sh
```

The runner builds release binaries and an initramfs, boots the guest under KVM,
runs `tools/qemu-smoke.sh` in the guest, and prints the results. `OUT_DIR`
selects the host staging directory; `CPUS`, `MEM_MB`, `FAST`, and `DURATION`
provide other overrides. `--keep` retains generated artifacts. The guest is
packed with root-owned files and normal permissions to exercise incident
storage as on a real root filesystem.

The matrix covers collector verifier/load paths, scheduler contention, CPU
sampling and stacks, block I/O attribution, off-CPU waits, memory and PSI,
diagnosis ranking, daemon triggers and storage, and the TCP-unavailable
contract. TCP programs are deliberately not attached; the guest reports
`TCP verifier: SKIP` rather than claiming a verifier pass.

The CI gate uses the pinned Linux 6.12.115 build with `CONFIG_PSI=y`, four
vCPUs, and TCG on GitHub-hosted runners; local validation uses the
kernel-server bpf-next 7.2.0-rc6 image with KVM and eight vCPUs. Latency and
cost vary by accelerator and host; only explicit smoke script thresholds are
acceptance criteria, and the accelerator is recorded in the guest log and the
cell artifact.
