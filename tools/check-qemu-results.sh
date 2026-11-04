#!/bin/sh
# Audits a QEMU guest log before CI calls the real-kernel gate green.
#
# A zero exit from qemu-run is necessary but not sufficient: a guest that never
# booted, skipped a required verifier check, or ran against the wrong kernel
# must fail the job. This script turns the log into that decision and writes a
# small machine-readable cell record for the job artifact.
#
# Usage: tools/check-qemu-results.sh --log <guest.log> --kernel <version>
#        [--accelerator kvm|tcg] --psi yes|no [--scenarios N]
#        [--output <cell.json>]
set -u

log=""
kernel=""
accelerator=""
psi=""
scenarios=""
output=""

while [ $# -gt 0 ]; do
    case "$1" in
        --log) log=$2; shift 2 ;;
        --kernel) kernel=$2; shift 2 ;;
        --accelerator) accelerator=$2; shift 2 ;;
        --psi) psi=$2; shift 2 ;;
        --scenarios) scenarios=$2; shift 2 ;;
        --output) output=$2; shift 2 ;;
        -h|--help)
            sed -n '2,15p' "$0" | sed 's/^# \{0,1\}//'
            exit 0
            ;;
        *)
            echo "check-qemu-results: unknown argument: $1" >&2
            exit 2
            ;;
    esac
done

[ -r "$log" ] || {
    echo "check-qemu-results: guest log not readable: ${log:-<missing>}" >&2
    exit 2
}
[ -n "$kernel" ] || {
    echo "check-qemu-results: --kernel is required" >&2
    exit 2
}

problems=""

if [ -z "$scenarios" ]; then
    table=$(dirname "$0")/scenarios.sh
    scenarios=$(sed -n 's/^SCENARIO_COUNT=\([0-9][0-9]*\)$/\1/p' "$table" 2>/dev/null)
fi
case "$scenarios" in
    ''|*[!0-9]*) problems="$problems scenarios-unknown" ;;
    0) problems="$problems scenarios-zero" ;;
esac

require() {
    grep -Fq -- "$1" "$log" || problems="$problems missing:$2"
}

forbid() {
    if grep -Eq -- "$1" "$log"; then
        problems="$problems unexpected:$2"
    fi
}

# The run has to have started and finished, not merely produced output.
require "=== smoke run finished with rc=0 ===" "rc=0"
require "smoke matrix: all cases passed" "matrix-pass"
require "guest: kernel $kernel" "kernel=$kernel"
require "guest: BTF present" "btf"
require "guest: tracefs mounted" "tracefs"
require "sched verifier: pass" "sched-verifier"
require "cpu verifier: pass" "cpu-verifier"
require "io verifier: pass" "io-verifier"
require "off-cpu verifier: pass" "off-cpu-verifier"
require "memory verifier: pass" "memory-verifier"
require "net collection: pass" "net-collection"
require "diagnose verifier: pass" "diagnose-verifier"
require "TCP unavailable contract: pass" "tcp-contract"

# PSI is a genuine optional capability. The caller states what this image was
# built with, and the guest proves it from /proc rather than from the build
# record: unavailable must be reported as unavailable, never as zero pressure.
case "$psi" in
    yes|no) ;;
    "") problems="$problems psi-missing" ;;
    *) problems="$problems psi-argument=$psi" ;;
esac
case "$psi" in
    yes)
        require "guest: pressure/memory available" "psi-available"
        require "guest: config PSI=y" "psi-config"
        ;;
    no)
        require "guest: pressure/memory unavailable" "psi-unavailable"
        require "guest: config PSI=disabled" "psi-config-disabled"
        ;;
esac

# The guest records which accelerator it actually used; the caller may pin it
# (a self-hosted runner with KVM), and a mismatch is a failure. When omitted,
# the recorded value is still required to exist and is copied into the cell.
recorded_accelerator=$(sed -n 's/^guest: accelerator //p' "$log" | head -1)
if [ -z "$recorded_accelerator" ]; then
    problems="$problems missing:accelerator"
elif [ -n "$accelerator" ] && [ "$recorded_accelerator" != "$accelerator" ]; then
    problems="$problems accelerator=$recorded_accelerator(wanted $accelerator)"
fi
[ -n "$accelerator" ] || accelerator=$recorded_accelerator

# The TCP skip is deliberate and documented; every other skip means a required
# check did not run.
unexpected_skips=$(grep -E 'SKIP' "$log" 2>/dev/null \
    | grep -Fv 'TCP verifier: SKIP' \
    | grep -v '^$' || true)
if [ -n "$unexpected_skips" ]; then
    problems="$problems unexpected-skip"
fi

forbid '^smoke matrix: FAILED' "matrix-failed"
forbid 'verifier: FAIL' "verifier-failed"
forbid 'collection: FAIL' "collection-failed"
forbid '^diagnose scenario .*: FAIL' "scenario-failed"
forbid '^diagnose scenarios: FAIL' "scenario-run-failed"
forbid '^ranking accuracy: FAIL' "ranking-failed"

passed_scenarios=$(grep -c '^diagnose scenario .*: pass' "$log" 2>/dev/null || true)
case "$scenarios" in
    ''|*[!0-9]*) ;;
    *) [ "${passed_scenarios:-0}" -lt "$scenarios" ] && problems="$problems scenarios=${passed_scenarios:-0}/$scenarios" ;;
esac

result=pass
if [ -n "$problems" ]; then
    result=fail
fi

if [ -n "$output" ]; then
    printf '{"schema":"rand-fast/qemu-cell/v1","kernel":"%s","accelerator":"%s","psi":"%s","scenario_count":%s,"scenarios_passed":%s,"result":"%s","log":"%s","problems":"%s"}\n' \
        "$kernel" "${accelerator:-unknown}" "${psi:-unknown}" "${scenarios:-0}" "${passed_scenarios:-0}" \
        "$result" "$log" "${problems# }" >"$output"
fi

if [ "$result" = fail ]; then
    echo "check-qemu-results: FAIL ($kernel):${problems}" >&2
    if [ -n "$unexpected_skips" ]; then
        printf '%s\n' "$unexpected_skips" | sed 's/^/    /' >&2
    fi
    exit 1
fi

echo "check-qemu-results: PASS ($kernel, ${passed_scenarios} scenario(s), ${accelerator:-unknown})"
exit 0
