#!/bin/sh
# Runs the paired overhead benchmark in the pinned QEMU guest and extracts the
# machine-readable report from the guest console.
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
KERNEL=${KERNEL:?set KERNEL to the bzImage to boot}
OUT_DIR=${OUT_DIR:-"$ROOT/target/bench"}
BENCH_OUT=${BENCH_OUT:-"$ROOT/target/bench-report.json"}
BENCH_DURATION=${BENCH_DURATION:-3s}
BENCH_REPETITIONS=${BENCH_REPETITIONS:-1}
BENCH_WARMUP=${BENCH_WARMUP:-0}
BENCH_MODES=${BENCH_MODES:-cpu,io,lock,net}
QEMU_TIMEOUT=${QEMU_TIMEOUT:-1800}

rm -rf "$OUT_DIR"
mkdir -p "$OUT_DIR"
KERNEL="$KERNEL" OUT_DIR="$OUT_DIR" QEMU_SMOKE_CASE=bench \
    BENCH_DURATION="$BENCH_DURATION" \
    BENCH_REPETITIONS="$BENCH_REPETITIONS" \
    BENCH_WARMUP="$BENCH_WARMUP" \
    BENCH_MODES="$BENCH_MODES" \
    QEMU_TIMEOUT="$QEMU_TIMEOUT" \
    "$ROOT/tools/qemu-run.sh" --duration "$BENCH_DURATION"

tr -d '\r' <"$OUT_DIR/guest.log" | awk '
    /^----- bench-report-begin -----$/{inside=1; next}
    /^----- bench-report-end -----$/{inside=0}
    inside' >"$BENCH_OUT"

if [ ! -s "$BENCH_OUT" ]; then
    echo "bench: no report found in $OUT_DIR/guest.log" >&2
    exit 1
fi
if ! grep -q '"schema": "rand-fast/bench/v1"' "$BENCH_OUT"; then
    echo "bench: report has an unexpected schema" >&2
    exit 1
fi
echo "bench: wrote $BENCH_OUT"
