#!/bin/sh
# Host-side checks for the pinned-kernel build contract.
#
# A full kernel build belongs in CI, not the host gate. These checks cover the
# failure paths that would otherwise turn into a confusing CI error: an
# unpinned version, a malformed pin table, and a build script that is not
# executable.
set -u

ROOT=$(cd "$(dirname "$0")/.." && pwd)
BUILD="$ROOT/tools/kernel/build.sh"
TSV="$ROOT/tools/kernel/kernels.tsv"
FAILURES=0
TMP=$(mktemp -d) || exit 1

cleanup() {
    rm -rf "$TMP"
}
trap cleanup EXIT

fail() {
    echo "test-kernel-build: FAIL: $*" >&2
    FAILURES=$((FAILURES + 1))
}

[ -x "$BUILD" ] || fail "tools/kernel/build.sh is not executable"

if "$BUILD" 9.9.9 >/dev/null 2>&1; then
    fail "an unpinned version was accepted"
else
    status=$?
    [ "$status" -eq 1 ] || fail "an unpinned version exited $status, expected 1"
fi

if "$BUILD" >/dev/null 2>&1; then
    fail "a missing version was accepted"
else
    status=$?
    [ "$status" -eq 2 ] || fail "a missing version exited $status, expected 2"
fi

rows=$(awk -F '\t' '!/^#/ && NF { n++ } END { print n + 0 }' "$TSV")
[ "$rows" -ge 1 ] || fail "the pin table has no rows"
awk -F '\t' '!/^#/ && NF {
        if ($1 == "" || $2 == "" || $3 == "" || $4 !~ /^https:\/\// || $5 !~ /^[0-9a-f]{64}$/ || $6 != "gcc") bad = 1
    } END { exit bad ? 1 : 0 }' "$TSV" \
    || fail "a pin row has a missing field, a non-https source, or a malformed sha256"
# Every declared profile needs a fragment, otherwise the failure only appears
# inside a long CI build.
awk -F '\t' '!/^#/ && NF { print $3 }' "$TSV" | sort -u | while read -r profile; do
    if [ "$profile" = default ]; then
        fragment="$ROOT/tools/kernel/config.fragment"
    else
        fragment="$ROOT/tools/kernel/config.$profile.fragment"
    fi
    if [ ! -r "$fragment" ]; then
        echo "missing profile fragment: $profile"
        continue
    fi
    for symbol in CONFIG_BPF_SYSCALL CONFIG_BPF_EVENTS CONFIG_DEBUG_INFO_BTF CONFIG_IKCONFIG_PROC; do
        grep -q "^$symbol=y" "$fragment" || echo "profile $profile lacks $symbol"
    done
    if [ "$profile" = nopsi ] && ! grep -q '^# CONFIG_PSI is not set' "$fragment"; then
        echo "profile nopsi does not disable PSI"
    fi
done >"$TMP/profiles.txt"
if [ -s "$TMP/profiles.txt" ]; then
    fail "$(cat "$TMP/profiles.txt")"
fi

if [ "$FAILURES" -ne 0 ]; then
    echo "test-kernel-build: $FAILURES case(s) failed" >&2
    exit 1
fi
echo "test-kernel-build: pin table and build failure paths passed"
