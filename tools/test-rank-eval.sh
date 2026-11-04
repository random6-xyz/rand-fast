#!/bin/sh
# Host-side regression tests for the ranking-evaluation gate.
#
# The real evaluation needs a kernel and eBPF; these tests replace the collector
# and fixtures with stubs so the scoring, artifact, and failure paths are
# exercised by the normal gate. They are deliberately about the gate: a missing
# document, a missing fixture report, a wrong top cause, or an excluded cause in
# the control must fail, while a lost-event observation is descriptive.
set -u

ROOT=$(cd "$(dirname "$0")/.." && pwd)
TMP=$(mktemp -d) || exit 1
FAILURES=0

cleanup() {
    rm -rf "$TMP"
}
trap cleanup EXIT

fail() {
    echo "test-rank-eval: FAIL: $*" >&2
    FAILURES=$((FAILURES + 1))
}

mkdir -p "$TMP/bin" "$TMP/out"

cat >"$TMP/bin/workload" <<'EOF'
#!/bin/sh
ready=""
report=""
while [ $# -gt 0 ]; do
    case "$1" in
        --ready-file) ready=$2; shift 2 ;;
        --report) report=$2; shift 2 ;;
        *) shift ;;
    esac
done
[ -n "$ready" ] && : >"$ready"
sleep 0.4
if [ "${STUB_REPORT:-1}" = "1" ] && [ -n "$report" ]; then
    printf '%s\n' '{"workload":"stub","pid":1,"duration_ms":400,"ops":10,"latency_us":{"p50":100,"p95":200,"p99":300}}' >"$report"
fi
EOF

cat >"$TMP/bin/fast" <<'EOF'
#!/bin/sh
[ "${STUB_EMPTY:-0}" = "1" ] && exit 0
n=0
if [ -f "${STUB_COUNTER:-/dev/null}" ]; then
    n=$(cat "$STUB_COUNTER")
fi
n=$((n + 1))
[ -n "${STUB_COUNTER:-}" ] && printf '%s\n' "$n" >"$STUB_COUNTER"
top=$(printf '%s\n' "${STUB_SEQUENCE:-CPU contention;Other waiting}" | cut -d ';' -f "$n")
cause=""
if [ -n "$top" ]; then
    cause=$(printf '{"cause":"%s","confidence_pct":99.0,"evidence":["stub"]}' "$top")
fi
lost=${STUB_LOST_JSON:-[]}
printf '{"schema":"rand-fast/v2","command":"diagnose","pid":1,"duration_s":1,"interrupted":false,"process_exited":false,"data":{"measured":{"cpu_percent":%s,"sched_samples":5,"sched_p95_us":2000},"lost_events":%s,"causes":[%s]}}\n' \
    "${STUB_CPU:-90}" "$lost" "$cause"
EOF

chmod +x "$TMP/bin/workload" "$TMP/bin/fast"

US=$(printf '\037')
cat >"$TMP/scenarios.sh" <<EOF
SCENARIO_COUNT=2
scenario_tag_0='positive'
scenario_kind_0='positive'
scenario_duration_0='1'
scenario_prereqs_0=''
scenario_fixture_0='workload'
scenario_bg_0_count=0
scenario_measured_0='cpu_percent'
scenario_expected_0='CPU contention'
scenario_check_0() { measured_min cpu_percent 50; top1_any 'CPU contention'; report_ops_min 1; }
scenario_tag_1='control'
scenario_kind_1='control'
scenario_duration_1='1'
scenario_prereqs_1=''
scenario_fixture_1='workload'
scenario_bg_1_count=0
scenario_measured_1='cpu_percent'
scenario_expected_1=''
scenario_check_1() { measured_min cpu_percent 0; exclude_causes 'CPU contention'; report_ops_min 1; }
EOF

run_eval() {
    # run_eval <tag> [env assignments...]
    tag=$1
    shift
    rm -f "$TMP/counter-$tag"
    # shellcheck disable=SC2086
    env PATH="$TMP/bin:$PATH" \
        STUB_COUNTER="$TMP/counter-$tag" \
        FAST="$TMP/bin/fast" \
        SCHED_WORKLOAD="$TMP/bin/workload" \
        FAST_WORKLOAD="$TMP/bin/workload" \
        SCENARIOS_SH="$TMP/scenarios.sh" \
        OUT_DIR="$TMP/out/$tag" \
        RANK_OUT="$TMP/out/$tag/rank" \
        RANK_REPETITIONS="${RANK_REPETITIONS:-1}" \
        "$@" \
        "$ROOT/tools/rank-eval.sh" >"$TMP/$tag.log" 2>&1
}

# 1. A passing run produces a valid report and two passing rows.
if run_eval pass STUB_SEQUENCE="CPU contention;Other waiting"; then
    jq -e '.overall.runs == 2 and .overall.passed == 2' \
        "$TMP/out/pass/rank/rank-report.json" >/dev/null 2>&1 \
        || { fail "the passing report does not record two passing runs"; cat "$TMP/out/pass/rank/rank-report.json" >&2; }
    rows=$(awk -F '\t' 'NR > 1 && $4 == "yes"' "$TMP/out/pass/rank/runs.tsv" | wc -l)
    [ "$rows" -eq 2 ] || fail "the passing run did not write two passing rows (got $rows)"
else
    fail "a passing evaluation exited non-zero"
    sed 's/^/    /' "$TMP/pass.log" >&2
fi

# 2. A wrong top cause fails the deterministic gate.
if run_eval wrong_top STUB_SEQUENCE="Other waiting;Other waiting"; then
    fail "a wrong top cause was accepted"
else
    grep -q 'top1=Other waiting' "$TMP/wrong_top.log" || fail "the failure did not name the top cause"
fi

# 3. A control that reports an excluded cause fails.
if run_eval control_hit STUB_SEQUENCE="CPU contention;CPU contention"; then
    fail "a control reporting a bottleneck cause was accepted"
fi

# 4. A missing fixture report fails even when the ranking was right.
if run_eval no_report STUB_SEQUENCE="CPU contention;Other waiting" STUB_REPORT=0; then
    fail "a run without a fixture report was accepted"
else
    grep -q 'report-ops=' "$TMP/no_report.log" || fail "the missing report was not named"
fi

# 5. An empty diagnose document fails.
if run_eval empty STUB_EMPTY=1; then
    fail "an empty diagnose document was accepted"
fi

# 6. Zero repetitions is rejected instead of passing trivially.
if RANK_REPETITIONS=0 run_eval zero_reps STUB_SEQUENCE="CPU contention;Other waiting"; then
    fail "zero repetitions were accepted"
fi

# 7. Lost events are reported but do not fail the deterministic gate.
if run_eval lost STUB_SEQUENCE="CPU contention;Other waiting" STUB_LOST_JSON='[{"stream":"cpu","count":1}]'; then
    jq -e '.overall.runs == 2 and (.scenarios[0].lost_event_runs == 1)' \
        "$TMP/out/lost/rank/rank-report.json" >/dev/null 2>&1 \
        || fail "lost events were not recorded in the report"
else
    fail "a lost-event observation failed the gate"
    sed 's/^/    /' "$TMP/lost.log" >&2
fi

if [ "$FAILURES" -ne 0 ]; then
    echo "test-rank-eval: $FAILURES case(s) failed" >&2
    exit 1
fi
echo "test-rank-eval: pass, wrong-top, control-hit, missing-report, empty-document, zero-repetition and lost-event paths passed"
