#!/bin/sh
# Verification gate for rand-fast.
#
# Runs every check that must pass before a commit is considered good:
#   1. cargo fmt --check      formatting is canonical
#   2. cargo clippy -D warnings  no lint debt
#   3. cargo build --release  workspace and the embedded eBPF object compile
#   4. cargo test             unit tests pass
#   5. test-qemu-smoke.sh     mock verifier/load failures propagate and children stop
#   6. test-qemu-run.sh       documented argument forms reach the help path
#   7. test-scenarios.sh      the scenario manifest and generated table agree
#   8. test-rank-eval.sh      the ranking gate rejects missing/empty/wrong runs
#   9. test-qemu-ci.sh        the CI guest-log audit rejects partial runs
#  10. test-bench.sh          the paired benchmark accepts valid and rejects zero-work runs
#  11. test-kernel-build.sh   the kernel pin table and build failure paths
#  11. check-license-metadata.sh every workspace package declares both licenses
#
# The eBPF verifier needs a real kernel; tools/qemu-smoke.sh runs that inside
# the QEMU guest and is a separate, manual step.
#
# Usage: tools/verify.sh
# Exit status: 0 when every check passed, 1 otherwise.
set -u

cd "$(dirname "$0")/.." || exit 2

failures=0
step() {
    name=$1
    shift
    printf '\n=== %s ===\n' "$name"
    if "$@"; then
        printf '=== %s: OK ===\n' "$name"
    else
        printf '=== %s: FAILED ===\n' "$name" >&2
        failures=$((failures + 1))
    fi
}

step 'cargo fmt --check' cargo fmt --all -- --check
step 'cargo clippy -D warnings' cargo clippy --workspace --all-targets -- -D warnings
step 'cargo build --release' cargo build --release
step 'cargo test' cargo test --workspace
step 'QEMU smoke failure propagation' tools/test-qemu-smoke.sh
step 'QEMU runner argument parsing' tools/test-qemu-run.sh
step 'scenario manifest' tools/test-scenarios.sh
step 'ranking evaluation gate' tools/test-rank-eval.sh
step 'QEMU CI result audit' tools/test-qemu-ci.sh
step 'benchmark harness' tools/test-bench.sh
step 'kernel build contract' tools/test-kernel-build.sh
step 'license metadata' tools/check-license-metadata.sh

printf '\n'
if [ "$failures" -ne 0 ]; then
    echo "verify: $failures check(s) failed" >&2
    exit 1
fi
echo "verify: all checks passed"
