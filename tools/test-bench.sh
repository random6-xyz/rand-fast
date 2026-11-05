#!/bin/sh
# Host-side checks for the fast-bench harness. The fake fast/workload binaries
# keep this independent of eBPF and QEMU; the guest run is exercised by CI.
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
mkdir -p "$TMP/bin"
fail() {
    echo "test-bench: $*" >&2
    exit 1
}

cat >"$TMP/bin/fake-fast" <<'EOF'
#!/bin/sh
# Arguments: diagnose --pid N --duration D --format json
while [ "$#" -gt 0 ]; do
    case "$1" in
    --duration) shift 2 ;;
    *) shift ;;
    esac
done
sleep 1
printf '%s\n' '{"data":{"lost_events":[{"stream":"sched","count":0}]}}'
EOF
cat >"$TMP/bin/fake-workload" <<'EOF'
#!/bin/sh
report=""
duration="1s"
while [ "$#" -gt 0 ]; do
    case "$1" in
    --report) report=$2; shift 2 ;;
    --duration) duration=$2; shift 2 ;;
    *) shift ;;
    esac
done
# Sleep most of the requested duration, then write a valid report.
sleep 1
if [ -n "$report" ]; then
    printf '%s\n' '{"workload":"fake","ops":100,"latency_us":{"p50":100,"p95":200,"p99":300}}' >"$report"
fi
EOF
cat >"$TMP/bin/zero-workload" <<'EOF'
#!/bin/sh
report=""
while [ "$#" -gt 0 ]; do
    case "$1" in
    --report) report=$2; shift 2 ;;
    *) shift ;;
    esac
done
sleep 1
[ -n "$report" ] && printf '%s\n' '{"workload":"fake","ops":0}' >"$report"
EOF
chmod +x "$TMP/bin/"*

BENCH="$ROOT/target/release/fast-bench"
[ -x "$BENCH" ] || fail "build fast-bench first"

"$BENCH" --fast "$TMP/bin/fake-fast" --workload "$TMP/bin/fake-workload" \
    --duration 1s --repetitions 1 --warmup 0 --modes cpu --out "$TMP/ok" >/dev/null \
    || fail "a valid fake run failed"
python3 - "$TMP/ok/report.json" <<'PY' || fail "valid report is malformed"
import json, sys
report = json.load(open(sys.argv[1]))
assert report["schema"] == "rand-fast/bench/v1"
assert len(report["runs"]) == 1, report
run = report["runs"][0]
assert run["error"] is None, run
assert run["baseline"]["ops"] == 100 and run["instrumented"]["ops"] == 100, run
assert run["collector"]["lost_events"] == 0, run
assert run["collector"]["peak_rss_bytes"] > 0, run
assert report["summary"][0]["valid_runs"] == 1, report["summary"]
PY

if "$BENCH" --fast "$TMP/bin/fake-fast" --workload "$TMP/bin/zero-workload" \
    --duration 1s --repetitions 1 --warmup 0 --modes cpu --out "$TMP/zero" >/dev/null 2>&1; then
    fail "a zero-work run was accepted"
fi
python3 - "$TMP/zero/report.json" <<'PY' || fail "invalid report does not record the error"
import json, sys
report = json.load(open(sys.argv[1]))
assert report["summary"][0]["valid_runs"] == 0, report
assert report["runs"][0]["error"], report["runs"][0]
PY

echo "test-bench: valid and invalid fake runs handled"
