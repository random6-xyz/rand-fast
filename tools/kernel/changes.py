#!/usr/bin/env python3
"""Print whether a Git comparison requires the expanded QEMU matrix.

The matrix exists to prove that the eBPF programs still load, and that the
collectors built against their tracepoints still measure, on every pinned
kernel. That surface is the eBPF programs, the layouts they share with Rust,
the collectors that read those layouts, the build inputs of the embedded
object, and the harness that drives the guest.

Everything else -- report formatting, the daemon, incidents, the CLI, the
landing page, documentation -- cannot change what a kernel does with the
program, so a change there runs the always-on 6.12.115 gate only.
"""

import argparse
import subprocess

EXACT_PATHS = frozenset({
    b"Cargo.toml",
    b"Cargo.lock",
    b"rust-toolchain",
    b"rust-toolchain.toml",
    b"fast/Cargo.toml",
    b"fast/build.rs",
    # Collectors that read a tracepoint, a task_struct, or a socket.
    b"fast/src/io_request_layout.rs",
    b"fast/src/memory.rs",
    b"fast/src/network.rs",
    b"fast/src/tcp.rs",
    b"fast/src/tcp_ownership.rs",
    b"fast/src/tracepoint_layout.rs",
    # Harness and assertions the matrix is measured with.
    b"tools/scenarios.json",
    b"tools/scenarios.sh",
    b"tools/rank-eval.sh",
    b"tools/check-qemu-results.sh",
    b".github/workflows/ci.yml",
})
PATH_PREFIXES = (
    b"fast-ebpf/",
    b"fast-common/",
    b".cargo/",
    b"tools/kernel/",
    b"tools/qemu-",
    b"tools/scenarios-",
    b"tools/sched-workload/",
    b"tools/fast-workload/",
    b".github/actions/run-qemu-gate/",
    b".github/actions/setup-rust-ebpf/",
)


def requires_matrix(base: str, head: str) -> bool:
    # A rename must check both the old and new paths. NUL-delimited output
    # avoids quoting or splitting filenames before matching their prefixes.
    changes = subprocess.run(
        ["git", "diff", "--name-only", "--no-renames", "-z", f"{base}...{head}", "--"],
        check=True,
        stdout=subprocess.PIPE,
    ).stdout
    return any(
        path in EXACT_PATHS or path.startswith(PATH_PREFIXES)
        for path in changes.split(b"\0")
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("base")
    parser.add_argument("head")
    args = parser.parse_args()
    try:
        required = requires_matrix(args.base, args.head)
    except (OSError, subprocess.CalledProcessError) as error:
        parser.exit(1, f"kernel changes: {error}\n")
    print("true" if required else "false")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
