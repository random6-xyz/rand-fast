#!/bin/sh
# Host-side regression tests for the CI guest-log auditor.
#
# The real gate only runs in GitHub Actions with a kernel build, so the
# decision logic is exercised here against synthetic logs: a complete pass, a
# non-zero run, an unexpected skip, a missing verifier check, the wrong kernel,
# and a failed scenario must each be classified correctly.
set -u

ROOT=$(cd "$(dirname "$0")/.." && pwd)
CHECK="$ROOT/tools/check-qemu-results.sh"
TMP=$(mktemp -d) || exit 1
FAILURES=0

cleanup() {
    rm -rf "$TMP"
}
trap cleanup EXIT

fail() {
    echo "test-qemu-ci: FAIL: $*" >&2
    FAILURES=$((FAILURES + 1))
}

make_good_log() {
    cat >"$1" <<'EOF'
guest: kernel 6.12.115
guest: accelerator tcg
guest: BTF present
guest: tracefs mounted
sched verifier: pass (program loaded and attached)
cpu verifier: pass (program loaded and attached)
io verifier: pass (program loaded and attached)
off-cpu verifier: pass (program loaded and attached)
memory verifier: pass (program loaded and attached)
diagnose verifier: pass (program loaded and attached)
net collection: pass (TCP programs not attached; no TCP verifier check)
TCP unavailable contract: pass (net, diagnose, daemon and incident; retransmission trigger disabled)
TCP verifier: SKIP (programs intentionally not attached)
diagnose scenario cpu-saturation: pass (positive, 4s, fixture report checked)
diagnose scenario sched-contention: pass (positive, 4s, fixture report checked)
diagnose scenario block-io: pass (positive, 4s, fixture report checked)
diagnose scenario lock-contention: pass (positive, 4s, fixture report checked)
diagnose scenario memory-pressure: pass (positive, 4s, fixture report checked)
diagnose scenario slow-socket-peer: pass (positive, 4s, fixture report checked)
diagnose scenario mixed-lock-io: pass (mixed, 4s, fixture report checked)
diagnose scenario slow-peer-delay: pass (positive, 4s, fixture report checked)
diagnose scenario idle-control: pass (control, 4s, fixture report checked)
smoke matrix: all cases passed
=== smoke run finished with rc=0 ===
EOF
}

run_check() {
    # run_check <name> <expected-status> [mutator]
    name=$1
    expected=$2
    make_good_log "$TMP/good.log"
    if [ $# -ge 3 ]; then
        "$3" "$TMP/good.log"
    fi
    "$CHECK" --log "$TMP/good.log" --kernel 6.12.115 --accelerator tcg \
        --scenarios 9 --output "$TMP/$name.json" >"$TMP/$name.out" 2>&1
    status=$?
    if [ "$status" -ne "$expected" ]; then
        fail "$name exited $status, expected $expected"
        sed 's/^/    /' "$TMP/$name.out" >&2
    fi
}

mutate_rc() { sed -i 's/rc=0/rc=1/' "$1"; }
mutate_skip() { printf 'memory fault counter: SKIP (no memory report from the matrix)\n' >>"$1"; }
mutate_missing_verifier() { sed -i '/memory verifier: pass/d' "$1"; }
mutate_kernel() { sed -i 's/6\.12\.115/6.12.114/' "$1"; }
mutate_scenario() { sed -i 's/diagnose scenario block-io: pass/diagnose scenario block-io: FAIL (no signal)/' "$1"; }
mutate_accel() { sed -i 's/guest: accelerator tcg/guest: accelerator kvm/' "$1"; }
mutate_bootfail() { printf 'Booting the kernel...\nNo working init found.\n' >"$1"; }
mutate_btf() { sed -i '/guest: BTF present/d' "$1"; }
mutate_tracefs() { sed -i '/guest: tracefs mounted/d' "$1"; }

run_check good 0
run_check rc 1 mutate_rc
run_check skip 1 mutate_skip
run_check missing_verifier 1 mutate_missing_verifier
run_check kernel 1 mutate_kernel
run_check scenario 1 mutate_scenario
run_check accelerator 1 mutate_accel
run_check bootfail 1 mutate_bootfail
run_check btf 1 mutate_btf
run_check tracefs 1 mutate_tracefs

# The cell record is written on both outcomes so a failed job still has one.
if [ ! -s "$TMP/rc.json" ]; then
    fail "a failing run did not write a cell record"
fi
if ! grep -q '"result":"pass"' "$TMP/good.json"; then
    fail "a passing run did not write result=pass"
fi
if ! grep -q '"result":"fail"' "$TMP/rc.json"; then
    fail "a failing run did not write result=fail"
fi

if [ "$FAILURES" -ne 0 ]; then
    echo "test-qemu-ci: $FAILURES case(s) failed" >&2
    exit 1
fi
echo "test-qemu-ci: pass, rc, skip, missing-verifier, kernel, scenario, accelerator, boot, BTF and tracefs cases passed"
