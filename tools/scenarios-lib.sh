#!/bin/sh
# Shared helpers for the QEMU scenario matrix and the ranking evaluation.
#
# Sourced by tools/qemu-smoke.sh and tools/rank-eval.sh so both drive fixtures
# the same way: packed argv, readiness handshakes, bounded waits, and the same
# JSON readers. The caller defines FAST, SCHED_WORKLOAD, FAST_WORKLOAD,
# IO_HOG_PATH and OUT_DIR before sourcing.
top_cause() {
    sed -n 's/.*"causes":\[{"cause":"\([^"]*\)".*/\1/p' "$1" | head -1
}

SCENARIOS_SH=${SCENARIOS_SH:-"$(dirname "$0")/scenarios.sh"}

start_workload() {
    # start_workload <packed-argv> <log> <ready-file> <report>
    local packed="$1" log="$2" ready="$3" report="$4"
    local old_ifs=$IFS
    # Substitute before splitting so a path with spaces stays one word.
    packed=$(printf '%s' "$packed" | sed "s|@IO_HOG_PATH@|$IO_HOG_PATH|g")
    # A fixture argument is data, never a pattern: pathname expansion would
    # turn a future "*" or "?" into whatever file happens to match.
    set -f
    IFS=$(printf '\037')
    set -- $packed
    IFS=$old_ifs
    set +f
    "$@" --ready-file "$ready" --report "$report" >"$log" 2>&1 &
}

wait_for_ready() {
    # wait_for_ready <pid> <ready-file>
    local pid="$1" file="$2" waited=0
    while [ "$waited" -lt 100 ] && [ ! -f "$file" ]; do
        kill -0 "$pid" 2>/dev/null || break
        sleep 0.1
        waited=$((waited + 1))
    done
    [ -f "$file" ]
}

wait_for_exit() {
    # wait_for_exit <pid> <tenths-of-a-second>
    local pid="$1" limit="$2" waited=0
    while kill -0 "$pid" 2>/dev/null && [ "$waited" -lt "$limit" ]; do
        sleep 0.1
        waited=$((waited + 1))
    done
}

prereq_ok() {
    case "$1" in
        tracefs)
            [ -r /sys/kernel/tracing/events/sched/sched_wakeup/format ] \
                || [ -r /sys/kernel/debug/tracing/events/sched/sched_wakeup/format ]
            ;;
        btf) [ -r /sys/kernel/btf/vmlinux ] ;;
        block_device) [ "${FAST_BLOCK_DEVICE:-0}" = "1" ] ;;
        cpu2) [ "$(grep -c '^processor' /proc/cpuinfo)" -ge 2 ] ;;
        *) return 1 ;;
    esac
}

json_number() {
    # json_number <file> <key>
    sed -n "s/.*\"$2\":\(-\{0,1\}[0-9][0-9.]*\).*/\1/p" "$1" | head -1
}

json_causes() {
    tr ',' '\n' < "$1" | sed -n 's/.*"cause":"\([^"]*\)".*/\1/p'
}

# The check helpers append to scenario_problems. The scenario loop turns the
# accumulated list into one pass/fail line and keeps the raw JSON on failure.
measured_min() {
    local value
    value=$(json_number "$SCENARIO_JSON" "$1")
    if [ -z "$value" ] || ! awk -v a="$value" -v b="$2" 'BEGIN { exit (a + 0 >= b + 0) ? 0 : 1 }'; then
        scenario_problems="$scenario_problems $1>=${2}(got ${value:-absent-or-null})"
    fi
}

measured_max() {
    local value
    value=$(json_number "$SCENARIO_JSON" "$1")
    if [ -z "$value" ] || ! awk -v a="$value" -v b="$2" 'BEGIN { exit (a + 0 <= b + 0) ? 0 : 1 }'; then
        scenario_problems="$scenario_problems $1<=${2}(got ${value:-absent-or-null})"
    fi
}

top1_any() {
    local top wanted
    top=$(top_cause "$SCENARIO_JSON")
    if [ -z "$top" ]; then
        scenario_problems="$scenario_problems no-cause"
        return
    fi
    for wanted in "$@"; do
        [ "$top" = "$wanted" ] && return 0
    done
    scenario_problems="$scenario_problems top1=${top}(expected $*)"
}

contains_any() {
    local causes wanted
    causes=$(json_causes "$SCENARIO_JSON")
    for wanted in "$@"; do
        printf '%s\n' "$causes" | grep -Fqx "$wanted" && return 0
    done
    scenario_problems="$scenario_problems missing-cause($*)"
}

exclude_causes() {
    local causes unwanted
    causes=$(json_causes "$SCENARIO_JSON")
    for unwanted in "$@"; do
        if printf '%s\n' "$causes" | grep -Fqx "$unwanted"; then
            scenario_problems="$scenario_problems unexpected=${unwanted}"
        fi
    done
}

report_ops_min() {
    local ops
    ops=$(json_number "$SCENARIO_REPORT" ops)
    if [ -z "$ops" ] || ! awk -v a="$ops" -v b="$1" 'BEGIN { exit (a + 0 >= b + 0) ? 0 : 1 }'; then
        scenario_problems="$scenario_problems report-ops=${ops:-absent-or-null}"
    fi
}

report_p95_min() {
    local p95
    p95=$(json_number "$SCENARIO_REPORT" p95)
    if [ -z "$p95" ] || ! awk -v a="$p95" -v b="$1" 'BEGIN { exit (a + 0 >= b + 0) ? 0 : 1 }'; then
        scenario_problems="$scenario_problems report-p95=${p95:-absent-or-null}"
    fi
}

