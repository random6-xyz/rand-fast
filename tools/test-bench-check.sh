#!/bin/sh
# Synthetic calibration/gate checks for tools/bench-check.sh.
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
CHECK="$ROOT/tools/bench-check.sh"
POLICY="$ROOT/tools/bench/policy.json"
fail() {
    echo "test-bench-check: $*" >&2
    exit 1
}

make_report() {
    # make_report <path> <ops> <cpu> <p95> <lost> <valid> <runs>
    python3 - "$@" <<'PY'
import json, sys
path, ops, cpu, p95, lost, valid, runs = sys.argv[1:]
report = {
    "schema": "rand-fast/bench/v1",
    "metadata": {"kernel": "6.12.115", "accelerator": "tcg", "cpus": 4},
    "duration_ms": 3000,
    "repetitions": 2,
    "warmup": 0,
    "runs": [],
    "summary": [],
}
for mode in ("cpu", "io", "lock", "net"):
    report["summary"].append({
        "mode": mode,
        "runs": int(runs),
        "valid_runs": int(valid),
        "ops_ratio_median": float(ops),
        "p95_ratio_median": float(p95),
        "collector_cpu_pct_median": float(cpu),
        "collector_rss_bytes_max": 40 * 1024 * 1024,
        "lost_events_max": int(lost),
    })
with open(path, "w") as handle:
    json.dump(report, handle)
PY
}

make_report "$TMP/base.json" 0.98 10 1.2 0 2 2
python3 - "$TMP/base.json" <<'PY_FIXTURE'
import json, sys
path = sys.argv[1]
report = json.load(open(path))
report["duration_ms"] = 3000
report["repetitions"] = 2
report["warmup"] = 0
json.dump(report, open(path, "w"))
PY_FIXTURE
make_report "$TMP/stable.json" 0.96 12 1.4 0 2 2
"$CHECK" --baseline "$TMP/base.json" --candidate "$TMP/stable.json" \
    --policy "$POLICY" >/dev/null || fail "a stable candidate was rejected"

make_report "$TMP/cpu-regression.json" 0.97 30 1.3 0 2 2
if ! "$CHECK" --baseline "$TMP/base.json" --candidate "$TMP/cpu-regression.json" \
    --policy "$POLICY" --output "$TMP/cpu-report.json" >/dev/null 2>&1; then
    fail "the report-only collector CPU metric failed the gate"
fi
python3 - "$TMP/cpu-report.json" <<'PY2' || fail "collector CPU is not marked report-only"
import json, sys
doc = json.load(open(sys.argv[1]))
cpu = [c for c in doc["checks"] if c["metric"] == "collector_cpu_pct"]
assert cpu and all(c["status"] == "report-only" for c in cpu), cpu
PY2

make_report "$TMP/ops-regression.json" 0.50 11 1.2 0 2 2
if "$CHECK" --baseline "$TMP/base.json" --candidate "$TMP/ops-regression.json" \
    --policy "$POLICY" --output "$TMP/fail.json" >/dev/null 2>&1; then
    fail "a 50% throughput drop was accepted"
fi
python3 - "$TMP/fail.json" <<'PY2' || fail "a failing check has no JSON record"
import json, sys
doc = json.load(open(sys.argv[1]))
assert doc["ok"] is False, doc
assert any(c["status"] == "fail" for c in doc["checks"]), doc
PY2

make_report "$TMP/p95-regression.json" 0.97 11 6.0 0 2 2
"$CHECK" --baseline "$TMP/base.json" --candidate "$TMP/p95-regression.json" \
    --policy "$POLICY" >/dev/null || fail "an unenforced p95 change failed the gate"

make_report "$TMP/lost.json" 0.98 11 1.2 200 2 2
if "$CHECK" --baseline "$TMP/base.json" --candidate "$TMP/lost.json" \
    --policy "$POLICY" >/dev/null 2>&1; then
    fail "excess event loss was accepted"
fi

make_report "$TMP/invalid.json" 0.97 11 1.2 0 1 2
if "$CHECK" --baseline "$TMP/base.json" --candidate "$TMP/invalid.json" \
    --policy "$POLICY" >/dev/null 2>&1; then
    fail "a report with an invalid run was accepted"
fi

python3 - "$TMP/base.json" "$TMP/mismatch.json" <<'PY_FIXTURE'
import json, sys
report = json.load(open(sys.argv[1]))
report["metadata"]["accelerator"] = "kvm"
json.dump(report, open(sys.argv[2], "w"))
PY_FIXTURE
python3 - "$TMP/base.json" "$TMP/duration-mismatch.json" <<'PY_FIXTURE'
import json, sys
report = json.load(open(sys.argv[1]))
report["duration_ms"] = 1500
json.dump(report, open(sys.argv[2], "w"))
PY_FIXTURE
if "$CHECK" --baseline "$TMP/base.json" --candidate "$TMP/duration-mismatch.json" \
    --policy "$POLICY" >/dev/null 2>&1; then
    fail "a duration mismatch was accepted"
fi
if "$CHECK" --baseline "$TMP/base.json" --candidate "$TMP/mismatch.json" \
    --policy "$POLICY" >/dev/null 2>&1; then
    fail "an accelerator mismatch was accepted"
fi

python3 - "$TMP/base.json" "$TMP/missing.json" <<'PY'
import json, sys
report = json.load(open(sys.argv[1]))
report["summary"] = [s for s in report["summary"] if s["mode"] != "net"]
json.dump(report, open(sys.argv[2], "w"))
PY
if "$CHECK" --baseline "$TMP/base.json" --candidate "$TMP/missing.json" \
    --policy "$POLICY" >/dev/null 2>&1; then
    fail "a missing mode was accepted"
fi


make_report "$TMP/base-loss.json" 0.98 10 1.2 120 2 2
make_report "$TMP/same-loss.json" 0.98 10 1.2 120 2 2
if "$CHECK" --baseline "$TMP/base-loss.json" --candidate "$TMP/same-loss.json" \
    --policy "$POLICY" >/dev/null 2>&1; then
    fail "a baseline outside its own loss cap was accepted"
fi

make_report "$TMP/base-invalid.json" 0.98 10 1.2 0 1 2
if "$CHECK" --baseline "$TMP/base-invalid.json" --candidate "$TMP/base-invalid.json" \
    --policy "$POLICY" >/dev/null 2>&1; then
    fail "an invalid baseline was accepted"
fi

python3 - "$TMP/base.json" "$TMP/kernel-mismatch.json" <<'PY2'
import json, sys
report = json.load(open(sys.argv[1]))
report["metadata"]["kernel"] = "7.2.15"
json.dump(report, open(sys.argv[2], "w"))
PY2
if "$CHECK" --baseline "$TMP/base.json" --candidate "$TMP/kernel-mismatch.json" \
    --policy "$POLICY" >/dev/null 2>&1; then
    fail "a kernel mismatch was accepted"
fi

python3 - "$TMP/base.json" "$TMP/missing-enforced.json" <<'PY2'
import json, sys
report = json.load(open(sys.argv[1]))
for item in report["summary"]:
    item["ops_ratio_median"] = None
json.dump(report, open(sys.argv[2], "w"))
PY2
if "$CHECK" --baseline "$TMP/base.json" --candidate "$TMP/missing-enforced.json" \
    --policy "$POLICY" >/dev/null 2>&1; then
    fail "a missing enforced metric was accepted"
fi

python3 - "$TMP/base.json" "$TMP/missing-p95.json" <<'PY2'
import json, sys
report = json.load(open(sys.argv[1]))
for item in report["summary"]:
    item["p95_ratio_median"] = None
json.dump(report, open(sys.argv[2], "w"))
PY2
"$CHECK" --baseline "$TMP/base.json" --candidate "$TMP/missing-p95.json" \
    --policy "$POLICY" >/dev/null || fail "a missing report-only metric failed the gate"

"$CHECK" --baseline "$TMP/base.json" --candidate "$TMP/stable.json" \
    --policy "$POLICY" --output "$TMP/check.json" >/dev/null
python3 - "$TMP/check.json" <<'PY' || fail "the check document is malformed"
import json, sys
doc = json.load(open(sys.argv[1]))
assert doc["ok"] is True, doc
assert len(doc["checks"]) == 16, doc
assert all(c["status"] in ("pass", "report-only") for c in doc["checks"]), doc
PY

echo "test-bench-check: stable, deliberate regressions, loss, missing and mismatch cases passed"
