#!/bin/sh
# Host-side regression tests for qemu-run.sh argument parsing.
set -u

ROOT=$(cd "$(dirname "$0")/.." && pwd)
QEMU_RUN="$ROOT/tools/qemu-run.sh"
FAILURES=0

run_help_case() {
    name=$1
    shift
    if output=$(sh "$QEMU_RUN" "$@" 2>&1); then
        echo "test-qemu-run: $name passed"
    else
        status=$?
        echo "test-qemu-run: FAIL $name exited $status"
        printf '%s\n' "$output"
        FAILURES=$((FAILURES + 1))
    fi
}

run_help_case separated-duration --duration 10s --help
run_help_case equals-duration --duration=10s --help
run_help_case keep-and-duration --keep --duration 10s --help

if output=$(sh "$QEMU_RUN" --definitely-unknown 2>&1); then
    echo "test-qemu-run: FAIL unknown option was accepted"
    FAILURES=$((FAILURES + 1))
else
    status=$?
    if [ "$status" -eq 2 ] && printf '%s\n' "$output" | grep -Fq 'unknown argument: --definitely-unknown'; then
        echo "test-qemu-run: unknown option rejected"
    else
        echo "test-qemu-run: FAIL unknown option had unexpected result (status=$status)"
        printf '%s\n' "$output"
        FAILURES=$((FAILURES + 1))
    fi
fi

if output=$(sh "$QEMU_RUN" --duration 2>&1); then
    echo "test-qemu-run: FAIL missing duration value was accepted"
    FAILURES=$((FAILURES + 1))
else
    status=$?
    if [ "$status" -eq 2 ] && printf '%s\n' "$output" | grep -Fq -- "--duration requires a value"; then
        echo "test-qemu-run: missing duration value rejected"
    else
        echo "test-qemu-run: FAIL missing duration had unexpected result (status=$status)"
        printf '%s\n' "$output"
        FAILURES=$((FAILURES + 1))
    fi
fi

# The accelerator override must reject a typo instead of silently choosing one.
tmp_kernel=$(mktemp) || exit 1
if output=$(ACCEL=bogus KERNEL="$tmp_kernel" sh "$QEMU_RUN" 2>&1); then
    echo "test-qemu-run: FAIL invalid ACCEL was accepted"
    FAILURES=$((FAILURES + 1))
else
    status=$?
    if [ "$status" -eq 1 ] && printf '%s\n' "$output" | grep -Fq 'ACCEL must be auto, kvm or tcg'; then
        echo "test-qemu-run: invalid ACCEL rejected"
    else
        echo "test-qemu-run: FAIL invalid ACCEL had unexpected result (status=$status)"
        printf '%s\n' "$output"
        FAILURES=$((FAILURES + 1))
    fi
fi
rm -f "$tmp_kernel"

if [ "$FAILURES" -ne 0 ]; then
    echo "test-qemu-run: $FAILURES failure(s)" >&2
    exit 1
fi
echo "test-qemu-run: all argument parsing cases passed"
