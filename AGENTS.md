# Working on rand-fast

- Start in `fast/src/` for CLI, collectors, reporting, and incident bundles.
  `fast-common/` and `fast-ebpf/` define the userspace-to-kernel boundary.
- Run `tools/verify.sh` for the host gate. It builds the eBPF object but does
  not exercise the kernel verifier. For runtime changes, run the real-kernel
  QEMU gate and audit the guest log as described in
  [Development](docs/development.md#qemu-gate).
- Consult the [CLI reference](docs/reference.md) before changing an output
  schema or an incident bundle. Keep compatibility tests with the code.
