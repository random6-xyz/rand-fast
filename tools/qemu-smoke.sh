#!/usr/bin/env bash
# QEMU smoke matrix for all eBPF-backed fast subcommands.
#
# Records verifier results and idle-vs-load deltas for sched, cpu, io, net,
# and offcpu, one case per line, so results can be pasted into the README
# matrix. Run it as root inside the QEMU guest (7.2.0-rc6 bpf-next bzImage,
# see README) or on a host where you hold CAP_BPF + CAP_PERFMON.
#
# Expected working directory contents (release binaries):
#   ./fast  ./sched-workload  ./fast-workload
#
# Environment overrides:
#   DURATION   per-run collection length (default 5s)
#   OUT_DIR    where raw reports are written (default /tmp/fast-smoke)
set -u

FAST=${FAST:-./fast}
SCHED_WORKLOAD=${SCHED_WORKLOAD:-./sched-workload}
FAST_WORKLOAD=${FAST_WORKLOAD:-./fast-workload}
DURATION=${DURATION:-5s}
OUT_DIR=${OUT_DIR:-/tmp/fast-smoke}

mkdir -p "$OUT_DIR"
for binary in "$FAST" "$SCHED_WORKLOAD" "$FAST_WORKLOAD"; do
    if [[ ! -x "$binary" ]]; then
        echo "missing executable: $binary" >&2
        exit 1
    fi
done

echo "kernel: $(uname -r)"
echo "duration: $DURATION"
echo

start_target() {
    "$SCHED_WORKLOAD" target --duration 30s --period 1ms >/dev/null 2>&1 &
    echo $!
}

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
        kill "$target_pid" 2>/dev/null
        return
    fi

    # Load case: run the fixture for the target and collect again.
    "$@" >/dev/null 2>&1 &
    local load_pid=$!
    sleep 0.5
    "$FAST" "$command_name" --pid "$load_pid" --duration "$DURATION" \
        >"$OUT_DIR/$command_name-load.txt" 2>&1 || true
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

    local target_pid
    target_pid=$(start_target)
    sleep 0.3
    "$FAST" sched --pid "$target_pid" --duration "$DURATION" >"$report_idle" 2>&1 || true

    "$SCHED_WORKLOAD" hog --duration 30s --workers 8 >/dev/null 2>&1 &
    local hog_pid=$!
    "$FAST" sched --pid "$target_pid" --duration "$DURATION" >"$report_load" 2>&1 || true
    kill "$hog_pid" "$target_pid" 2>/dev/null
    wait 2>/dev/null

    echo "sched verifier: pass"
    echo "  idle report: $report_idle"
    echo "  load report: $report_load"
    echo
}

run_sched_case
run_case cpu "$SCHED_WORKLOAD" hog --duration 30s --workers 8
run_case io "$FAST_WORKLOAD" io-hog --duration 30s --workers 2
run_case net "$FAST_WORKLOAD" net-hog --duration 30s --workers 4
run_case offcpu "$FAST_WORKLOAD" lock-hog --duration 30s --workers 8

echo "=== key metrics ==="
for case_name in sched cpu io net offcpu; do
    for variant in "" "-load"; do
        report="$OUT_DIR/$case_name$variant.txt"
        [[ -f "$report" ]] || continue
        key=$(grep -m1 -E "p95|Samples:|Retransmissions:" "$report" || echo "(no samples)")
        printf '%-14s %s\n' "$case_name$variant" "$key"
    done
done
echo
echo "Raw reports saved under $OUT_DIR"
