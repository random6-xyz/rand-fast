#!/bin/sh
# Measures diagnosis ranking accuracy over repeated runs of the declared
# scenarios.
#
# This is deliberately separate from tools/qemu-smoke.sh: the smoke matrix
# asserts that a signal exists and that the ranked cause is the declared one in
# a single run. Accuracy work needs repetitions, aggregated rates, and the raw
# documents, so it lives here and is enabled explicitly with RANK_EVAL=1.
#
# Outputs under $RANK_OUT (default $OUT_DIR/rank):
#   raw/<scenario>-<run>.json            diagnose document
#   raw/<scenario>-<run>-report.json     the fixture's own measurement
#   runs.tsv                             one row per run
#   rank-report.json                     machine-readable aggregate
#   rank-summary.txt                     human-readable aggregate
#
# Exit status: 0 when every run satisfied its scenario's declared checks,
# 1 otherwise. Descriptive rates are reported but do not fail the run by
# themselves; the manifest checks are the deterministic gate.
set -u

DIR=$(dirname "$0")
FAST=${FAST:-./fast}
SCHED_WORKLOAD=${SCHED_WORKLOAD:-./sched-workload}
FAST_WORKLOAD=${FAST_WORKLOAD:-./fast-workload}
OUT_DIR=${OUT_DIR:-/fast-smoke}
IO_HOG_PATH=${IO_HOG_PATH:-/tmp/fast-workload-io}
REPETITIONS=${RANK_REPETITIONS:-3}
OUT=${RANK_OUT:-$OUT_DIR/rank}

# shellcheck source=tools/scenarios-lib.sh
. "$DIR/scenarios-lib.sh"

[ -r "$SCENARIOS_SH" ] || {
    echo "rank-eval: missing $SCENARIOS_SH; run tools/scenarios-generate.sh" >&2
    exit 1
}
# shellcheck source=tools/scenarios.sh
. "$SCENARIOS_SH"

for binary in "$FAST" "$SCHED_WORKLOAD" "$FAST_WORKLOAD"; do
    [ -x "$binary" ] || {
        echo "rank-eval: missing executable: $binary" >&2
        exit 1
    }
done

rm -rf "$OUT/raw" || exit 1
mkdir -p "$OUT/raw" || exit 1
rm -f "$OUT/runs.tsv" "$OUT/rank-report.json" "$OUT/rank-summary.txt"
printf 'scenario\tkind\trun\tpass\ttop1\texpected_top1\tconfidence\tops\tmissing_evidence\tlost_events\tproblems\n' \
    >"$OUT/runs.tsv"

total_runs=0
total_pass=0
total_top1_ok=0
total_top1_scored=0
total_top3_ok=0
total_top3_scored=0
gate_failures=0
scenario_json="$OUT/scenario-metrics.jsonl"
: >"$scenario_json"

in_expected() { # in_expected <cause>
    [ -n "$1" ] || return 1
    printf '%s\n' "$expected" | grep -Fqx "$1"
}

i=0
while [ "$i" -lt "${SCENARIO_COUNT:-0}" ]; do
    eval "name=\$scenario_tag_$i"
    eval "kind=\$scenario_kind_$i"
    eval "duration=\$scenario_duration_$i"
    eval "prereqs=\$scenario_prereqs_$i"
    eval "fixture=\$scenario_fixture_$i"
    eval "bg_count=\$scenario_bg_${i}_count"
    eval "measured_keys=\$scenario_measured_$i"
    eval "expected_packed=\$scenario_expected_$i"

    # The generator packs expected cause names with US; one per line keeps
    # names that contain spaces intact.
    expected=$(printf '%s' "$expected_packed" | tr '\037' '\n')

    missing=""
    for prereq in $prereqs; do
        prereq_ok "$prereq" || missing="$missing $prereq"
    done
    if [ -n "$missing" ]; then
        echo "rank-eval: $name FAIL (required prerequisite missing:$missing)"
        gate_failures=$((gate_failures + 1))
        printf '{"scenario":"%s","runs":0,"gate":"prerequisite-failure","missing_prerequisites":"%s"}\n' \
            "$name" "${missing# }" >>"$scenario_json"
        i=$((i + 1))
        continue
    fi

    [ "${REPETITIONS:-0}" -ge 1 ] || {
        echo "rank-eval: RANK_REPETITIONS must be at least 1" >&2
        exit 1
    }

    runs=0
    passed=0
    top1_ok=0
    top1_scored=0
    top3_ok=0
    top3_scored=0
    control_hits=0
    missing_evidence_runs=0
    lost_runs=0

    run=1
    while [ "$run" -le "$REPETITIONS" ]; do
        runs=$((runs + 1))
        total_runs=$((total_runs + 1))
        json="$OUT/raw/$name-$run.json"
        report="$OUT/raw/$name-$run-report.json"
        ready="$OUT/raw/$name-$run.ready"
        err="$OUT/raw/$name-$run.err"
        rm -f "$json" "$report" "$ready" "$err"

        start_workload "$fixture" "$OUT/raw/$name-$run-fixture.log" "$ready" "$report"
        fixture_pid=$!
        bg_pids=""
        j=0
        while [ "$j" -lt "$bg_count" ]; do
            eval "bg=\$scenario_bg_${i}_${j}"
            start_workload "$bg" "$OUT/raw/$name-$run-bg-$j.log" \
                "$OUT/raw/$name-$run-bg-$j.ready" "$OUT/raw/$name-$run-bg-$j.json"
            bg_pids="$bg_pids $!"
            j=$((j + 1))
        done

        problems=""
        wait_for_ready "$fixture_pid" "$ready" || problems="$problems fixture-not-ready"
        j=0
        for bg_pid in $bg_pids; do
            wait_for_ready "$bg_pid" "$OUT/raw/$name-$run-bg-$j.ready" \
                || problems="$problems bg-$j-not-ready"
            j=$((j + 1))
        done
        if [ -z "$problems" ]; then
            "$FAST" diagnose --pid "$fixture_pid" --duration "${duration}s" --format json \
                >"$json" 2>"$err" || problems="$problems diagnose-exit"
        fi
        wait_for_exit "$fixture_pid" 70
        kill "$fixture_pid" $bg_pids 2>/dev/null
        wait "$fixture_pid" 2>/dev/null
        for bg_pid in $bg_pids; do
            wait "$bg_pid" 2>/dev/null
        done

        # The deterministic checks are the same ones the smoke matrix applies.
        SCENARIO_JSON="$json"
        SCENARIO_REPORT="$report"
        scenario_problems="$problems"
        if [ ! -s "$json" ] && ! printf '%s' "$problems" | grep -q 'diagnose-exit'; then
            scenario_problems="$scenario_problems no-document"
        elif [ -s "$json" ] && ! printf '%s' "$problems" | grep -q 'diagnose-exit'; then
            "scenario_check_$i"
        fi

        top1=$(top_cause "$json" 2>/dev/null)
        top3=$(json_causes "$json" 2>/dev/null | head -3)
        top1_expected=no
        top3_expected=no
        if [ -n "$expected" ]; then
            if in_expected "$top1"; then
                top1_expected=yes
                top1_ok=$((top1_ok + 1))
            fi
            top1_scored=$((top1_scored + 1))
            # Cause names contain spaces, so the causes are compared line by
            # line rather than through word splitting.
            while IFS= read -r cause; do
                [ -n "$cause" ] || continue
                if printf '%s\n' "$expected" | grep -Fqx "$cause"; then
                    top3_expected=yes
                    break
                fi
            done <<EOF
$top3
EOF
            [ "$top3_expected" = yes ] && top3_ok=$((top3_ok + 1))
            top3_scored=$((top3_scored + 1))
        fi

        # A healthy control is scored by what it must not report.
        if [ "$kind" = control ]; then
            if printf '%s' "$scenario_problems" | grep -q 'unexpected='; then
                control_hits=$((control_hits + 1))
            fi
        fi

        evidence_missing=no
        for key in $measured_keys; do
            [ -n "$(json_number "$json" "$key")" ] || evidence_missing=yes
        done
        [ "$evidence_missing" = yes ] && missing_evidence_runs=$((missing_evidence_runs + 1))

        # A run with no document has no loss observation; counting it as a
        # loss would report a parsing failure as a kernel drop.
        if [ -s "$json" ]; then
            if grep -q '"lost_events":\[\]' "$json" 2>/dev/null; then
                lost=no
            else
                lost=yes
                lost_runs=$((lost_runs + 1))
            fi
        else
            lost=na
        fi

        confidence=""
        if [ -s "$json" ]; then
            confidence=$(sed -n 's/.*"causes":\[{"cause":"[^"]*","confidence_pct":\([0-9.]*\).*/\1/p' "$json" | head -1)
        fi
        ops=$(json_number "$report" ops)
        [ -n "$ops" ] || scenario_problems="$scenario_problems report-missing"

        if [ -n "$scenario_problems" ]; then
            pass=no
            gate_failures=$((gate_failures + 1))
        else
            pass=yes
            passed=$((passed + 1))
            total_pass=$((total_pass + 1))
        fi

        printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
            "$name" "$kind" "$run" "$pass" "${top1:--}" \
            "$top1_expected" "${confidence:--}" "${ops:--}" \
            "$evidence_missing" "$lost" "${scenario_problems# }" >>"$OUT/runs.tsv"

        run=$((run + 1))
    done

    total_top1_ok=$((total_top1_ok + top1_ok))
    total_top1_scored=$((total_top1_scored + top1_scored))
    total_top3_ok=$((total_top3_ok + top3_ok))
    total_top3_scored=$((total_top3_scored + top3_scored))

    expected_json=$(printf '%s\n' "$expected" | awk 'NF { printf "%s\"%s\"", sep, $0; sep = "," }')
    printf '{"scenario":"%s","kind":"%s","expected":[%s],"runs":%s,"passed":%s,"top1_rate":%s,"top3_rate":%s,"control_false_positives":%s,"missing_evidence_runs":%s,"lost_event_runs":%s}\n' \
        "$name" "$kind" "$expected_json" "$runs" "$passed" \
        "$(awk -v a="$top1_ok" -v b="$top1_scored" 'BEGIN { printf "%.3f", (b > 0) ? a / b : 0 }')" \
        "$(awk -v a="$top3_ok" -v b="$top3_scored" 'BEGIN { printf "%.3f", (b > 0) ? a / b : 0 }')" \
        "$control_hits" "$missing_evidence_runs" "$lost_runs" >>"$scenario_json"

    echo "rank-eval: $name $passed/$runs runs passed; top1 ${top1_ok}/${top1_scored}, top3 ${top3_ok}/${top3_scored}, control false positives ${control_hits}, lost-event runs ${lost_runs}"
    i=$((i + 1))
done

top1_rate=$(awk -v a="$total_top1_ok" -v b="$total_top1_scored" 'BEGIN { printf "%.3f", (b > 0) ? a / b : 0 }')
top3_rate=$(awk -v a="$total_top3_ok" -v b="$total_top3_scored" 'BEGIN { printf "%.3f", (b > 0) ? a / b : 0 }')
printf '"overall":{"runs":%s,"passed":%s,"top1_rate":%s,"top3_rate":%s,"gate_failures":%s}' \
    "$total_runs" "$total_pass" "$top1_rate" "$top3_rate" "$gate_failures" >"$OUT/overall.json"

{
    printf '{"schema":"rand-fast/rank-eval/v1","kernel":"%s","accelerator":"%s","cpus":%s,"repetitions":%s,' \
        "$(uname -r)" "${FAST_ACCEL:-unknown}" \
        "$(grep -c '^processor' /proc/cpuinfo)" "$REPETITIONS"
    cat "$OUT/overall.json"
    printf ',"scenarios":[\n'
    awk 'NR > 1 { printf ",\n" } { printf "%s", $0 }' "$scenario_json"
    printf '\n]}\n'
} >"$OUT/rank-report.json"

{
    echo "rank evaluation: $total_pass/$total_runs runs passed; top1 $top1_rate, top3 $top3_rate; gate failures $gate_failures"
    echo "kernel: $(uname -r), accelerator: ${FAST_ACCEL:-unknown}, cpus: $(grep -c '^processor' /proc/cpuinfo), repetitions: $REPETITIONS"
    echo
    column -t -s "$(printf '\t')" "$OUT/runs.tsv" 2>/dev/null || cat "$OUT/runs.tsv"
} >"$OUT/rank-summary.txt"

cat "$OUT/rank-summary.txt"

if [ "$total_runs" -eq 0 ]; then
    echo "rank-eval: FAILED (no scenario run was executed)" >&2
    exit 1
fi

if [ "$gate_failures" -ne 0 ]; then
    echo "rank-eval: FAILED ($gate_failures run(s) violated their scenario checks)" >&2
    exit 1
fi
echo "rank-eval: every run satisfied its scenario checks"
exit 0
