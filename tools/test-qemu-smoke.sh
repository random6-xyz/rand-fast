#!/bin/sh
# Host-side regression tests for qemu-smoke.sh failure propagation and cleanup.
set -u

ROOT=$(cd "$(dirname "$0")/.." && pwd)
SMOKE="$ROOT/tools/qemu-smoke.sh"
TMP=$(mktemp -d) || exit 1
FAILURES=0

cleanup() {
    rm -rf "$TMP"
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

mkdir -p "$TMP/bin"
cat >"$TMP/bin/fast" <<'EOF'
#!/bin/sh
calls=0
if [ -f "$FAST_CALLS" ]; then
    calls=$(cat "$FAST_CALLS")
fi
calls=$((calls + 1))
printf '%s\n' "$calls" >"$FAST_CALLS"
if [ "$FAST_FAIL_AT" -eq "$calls" ]; then
    echo "stub fast: forced failure at call $calls" >&2
    exit 1
fi
exit 0
EOF
cat >"$TMP/bin/workload" <<'EOF'
#!/bin/sh
printf '%s\n' "$$" >>"$CHILD_PIDS"
while :; do
    printf 'alive\n' >>"$CHILD_HEARTBEAT"
    sleep 0.05
done
EOF
chmod +x "$TMP/bin/fast" "$TMP/bin/workload"

run_case_test() {
    name=$1
    fail_at=$2
    expected_status=$3
    expected_output=$4
    state="$TMP/$name"
    mkdir -p "$state/out"
    : >"$state/calls"
    : >"$state/pids"
    : >"$state/heartbeat"

    if timeout 10s env \
        FAST="$TMP/bin/fast" \
        SCHED_WORKLOAD="$TMP/bin/workload" \
        FAST_WORKLOAD="$TMP/bin/workload" \
        FAST_FAIL_AT="$fail_at" \
        FAST_CALLS="$state/calls" \
        CHILD_PIDS="$state/pids" \
        CHILD_HEARTBEAT="$state/heartbeat" \
        OUT_DIR="$state/out" \
        DURATION=1s \
        QEMU_SMOKE_TEST_CASE=single-io \
        setsid sh "$SMOKE" >"$state/log" 2>&1; then
        status=0
    else
        status=$?
    fi

    if [ "$status" -ne "$expected_status" ]; then
        echo "test-qemu-smoke: FAIL $name exited $status, expected $expected_status"
        cat "$state/log"
        FAILURES=$((FAILURES + 1))
    elif ! grep -Fq "$expected_output" "$state/log"; then
        echo "test-qemu-smoke: FAIL $name did not report '$expected_output'"
        cat "$state/log"
        FAILURES=$((FAILURES + 1))
    else
        echo "test-qemu-smoke: $name reported the expected result"
    fi

    child_count=$(wc -l <"$state/pids" | tr -d ' ')
    if [ "$child_count" -eq 0 ]; then
        echo "test-qemu-smoke: FAIL $name started no background workload"
        FAILURES=$((FAILURES + 1))
    fi
    before=$(wc -l <"$state/heartbeat" | tr -d ' ')
    sleep 0.2
    after=$(wc -l <"$state/heartbeat" | tr -d ' ')
    if [ "$after" -ne "$before" ]; then
        echo "test-qemu-smoke: FAIL $name left a background workload running"
        FAILURES=$((FAILURES + 1))
    fi
}

# Fail the verifier command, then the load command, and finally verify the
# successful path. The workload stub's heartbeat proves that each path reaps
# the background fixtures instead of leaving them behind.
run_case_test verifier-failure 1 1 "io verifier: FAIL"
run_case_test load-failure 2 1 "io load collection: FAIL"
run_case_test success 0 0 "smoke matrix: all cases passed"

if [ "$FAILURES" -ne 0 ]; then
    echo "test-qemu-smoke: $FAILURES failure(s)" >&2
    exit 1
fi
echo "test-qemu-smoke: all failure-propagation and cleanup cases passed"
