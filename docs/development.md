# Development

## Project structure

- `fast/`: CLI, collectors, diagnosis, reporting, and flight recorder.
- `fast-ebpf/`: eBPF programs loaded into the kernel.
- `fast-common/`: types shared by kernel and userspace.
- `tools/`: verification, QEMU runner, release packaging, and test workloads.
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
8. `tools/check-license-metadata.sh`: workspace license metadata

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
must not report any bottleneck cause. Ranking accuracy is evaluated separately.

### QEMU gate

Run the real-kernel tests inside QEMU without host root. Provide an appropriate
kernel image explicitly; the runner's built-in default points to a
machine-specific build path. The host also needs KVM access, `qemu-system-x86_64`,
`cpio`, `busybox`, a C compiler capable of static linking, and the source build
requirements above.

```bash
KERNEL=/path/to/bzImage tools/qemu-run.sh --duration 5s
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

The last recorded storage/collection matrix passed on bpf-next 7.2.0-rc6 with
8 vCPUs and no `CONFIG_PSI`. Latency and cost vary by host; only explicit smoke
script thresholds are acceptance criteria.
