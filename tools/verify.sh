#!/bin/sh
# Verification gate for rand-fast.
#
# Runs every check that must pass before a commit is considered good:
#   1. cargo fmt --check      formatting is canonical
#   2. cargo clippy -D warnings  no lint debt
#   3. cargo build --release  workspace and the embedded eBPF object compile
#   4. cargo test             unit tests pass
#   5. check-no-cjk.sh        no CJK characters in tracked content
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
step 'check-no-cjk' tools/check-no-cjk.sh

printf '\n'
if [ "$failures" -ne 0 ]; then
    echo "verify: $failures check(s) failed" >&2
    exit 1
fi
echo "verify: all checks passed"
