#!/bin/sh
# QEMU smoke matrix for all eBPF-backed fast subcommands.
#
# Records verifier results and idle-vs-load deltas for sched, cpu, io, net,
# and off-cpu, one case per line, so results can be pasted into the README
# matrix. Run it as root inside the QEMU guest (7.2.0-rc6 bpf-next bzImage,
# see README) or on a host where you hold CAP_BPF + CAP_PERFMON.
#
# Expected working directory contents (release binaries):
#   ./fast  ./sched-workload  ./fast-workload
#   (override with FAST, SCHED_WORKLOAD, FAST_WORKLOAD)
#
# Environment overrides:
#   DURATION    per-run collection length (default 5s)
#   OUT_DIR     where raw reports are written (default /tmp/fast-smoke)
#   IO_HOG_PATH file the io-hog reads; put it on a real block device (not
#               tmpfs) so block_rq_* tracepoints fire (default /tmp/fast-workload-io)
#
# Exit status: 0 when every verifier load and idle/load collection succeeded,
# 1 otherwise (failures are also counted in the summary).
set -u

FAST=${FAST:-./fast}
SCHED_WORKLOAD=${SCHED_WORKLOAD:-./sched-workload}
FAST_WORKLOAD=${FAST_WORKLOAD:-./fast-workload}
DURATION=${DURATION:-5s}
OUT_DIR=${OUT_DIR:-/tmp/fast-smoke}
IO_HOG_PATH=${IO_HOG_PATH:-/tmp/fast-workload-io}
FAILURES=0

cleanup() {
    kill $(jobs -p) 2>/dev/null
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

mkdir -p "$OUT_DIR"
for binary in "$FAST" "$SCHED_WORKLOAD" "$FAST_WORKLOAD"; do
    if [ ! -x "$binary" ]; then
        echo "missing executable: $binary" >&2
        exit 1
    fi
done

echo "kernel: $(uname -r)"
echo "duration: $DURATION"
echo

run_case() {
    # run_case <command> <fixture-cmd...>
    local command_name="$1"
    shift
    local report="$OUT_DIR/$command_name.txt"
    "$SCHED_WORKLOAD" target --duration 30s --period 1ms >/dev/null 2>&1 &
    local target_pid=$!
    sleep 0.3

    if "$FAST" "$command_name" --pid "$target_pid" --duration "$DURATION" \
        >"$report" 2>&1; then
        echo "$command_name verifier: pass (program loaded and attached)"
    else
        echo "$command_name verifier: FAIL"
        cat "$report"
        FAILURES=$((FAILURES + 1))
        kill "$target_pid" 2>/dev/null
        return
    fi

    # Load case: run the fixture for the target and collect again.
    "$@" >"$OUT_DIR/$command_name-fixture.log" 2>&1 &
    local load_pid=$!
    sleep 0.5
    if "$FAST" "$command_name" --pid "$load_pid" --duration "$DURATION" \
        >"$OUT_DIR/$command_name-load.txt" 2>&1; then
        : # counted as success; the report itself carries the numbers
    else
        echo "$command_name load collection: FAIL (see $OUT_DIR/$command_name-load.txt)"
        FAILURES=$((FAILURES + 1))
    fi
    kill "$load_pid" "$target_pid" 2>/dev/null
    wait "$load_pid" 2>/dev/null
    wait "$target_pid" 2>/dev/null

    echo "  idle report: $report"
    echo "  load report: $OUT_DIR/$command_name-load.txt"
    echo
}

run_sched_case() {
    # sched compares the same target idle vs under external contention.
    local report_idle="$OUT_DIR/sched.txt"
    local report_load="$OUT_DIR/sched-load.txt"

    "$SCHED_WORKLOAD" target --duration 30s --period 1ms >/dev/null 2>&1 &
    local target_pid=$!
    sleep 0.3
    if "$FAST" sched --pid "$target_pid" --duration "$DURATION" >"$report_idle" 2>&1; then
        echo "sched verifier: pass (program loaded and attached)"
    else
        echo "sched verifier: FAIL"
        cat "$report_idle"
        FAILURES=$((FAILURES + 1))
        kill "$target_pid" 2>/dev/null
        return
    fi

    "$SCHED_WORKLOAD" hog --duration 30s --workers 8 >/dev/null 2>&1 &
    local hog_pid=$!
    if "$FAST" sched --pid "$target_pid" --duration "$DURATION" >"$report_load" 2>&1; then
        : # counted as success
    else
        echo "sched load collection: FAIL (see $report_load)"
        FAILURES=$((FAILURES + 1))
    fi
    kill "$hog_pid" "$target_pid" 2>/dev/null
    wait 2>/dev/null

    echo "  idle report: $report_idle"
    echo "  load report: $report_load"
    echo
}

run_sched_case
run_case cpu "$SCHED_WORKLOAD" hog --duration 30s --workers 8
run_case io "$FAST_WORKLOAD" io-hog --duration 30s --workers 2 --path "$IO_HOG_PATH"
run_case net "$FAST_WORKLOAD" net-hog --duration 30s --workers 4
run_case off-cpu "$FAST_WORKLOAD" lock-hog --duration 30s --workers 16

echo "=== key metrics ==="
print_metrics() {
    # print_metrics <case-name> <grep pattern>
    local name="$1" pattern="$2" report
    for variant in "" "-load"; do
        report="$OUT_DIR/$name$variant.txt"
        [ -f "$report" ] || continue
        echo "--- $name$variant ---"
        grep -E "$pattern" "$report" || echo "(no match)"
    done
}

print_metrics sched 'p95|> 1ms'
print_metrics cpu 'Samples:|CPU usage:'
print_metrics io 'Samples:|rchar:'
print_metrics net 'Retransmissions:'
print_metrics off-cpu 'Samples:'
echo
echo "Raw reports saved under $OUT_DIR"

if [ "$FAILURES" -gt 0 ]; then
    echo "smoke matrix: FAILED ($FAILURES failure(s))"
    exit 1
fi
echo "smoke matrix: all cases passed"
