#!/bin/sh
# Host-side regression tests for the scenario manifest and its generator.
#
# The guest has no JSON parser, so tools/scenarios.sh is generated on the host
# and committed. These tests prove it is current, syntactically valid, and
# that fixture arguments survive the generator without shell evaluation.
set -u

ROOT=$(cd "$(dirname "$0")/.." && pwd)
TMP=$(mktemp -d) || exit 1
FAILURES=0

cleanup() {
    rm -rf "$TMP"
}
trap cleanup EXIT

fail() {
    echo "test-scenarios: FAIL: $*" >&2
    FAILURES=$((FAILURES + 1))
}

command -v jq >/dev/null 2>&1 || {
    echo "test-scenarios: jq is required" >&2
    exit 1
}

# 1. The committed table must match the manifest.
if ! "$ROOT/tools/scenarios-generate.sh" >"$TMP/scenarios.sh"; then
    fail "the generator exited non-zero"
else
    if ! diff -u "$ROOT/tools/scenarios.sh" "$TMP/scenarios.sh" >"$TMP/diff.txt"; then
        fail "tools/scenarios.sh is stale; rerun tools/scenarios-generate.sh"
        sed 's/^/    /' "$TMP/diff.txt" >&2
    fi
fi

# 2. The guest sources it with a POSIX shell.
if ! sh -n "$ROOT/tools/scenarios.sh"; then
    fail "tools/scenarios.sh has a syntax error"
fi

# 3. Every declared scenario made it into the table.
expected=$(jq '.scenarios | length' "$ROOT/tools/scenarios.json") || fail "manifest is not valid JSON"
counted=$(sed -n 's/^SCENARIO_COUNT=\([0-9]*\)$/\1/p' "$ROOT/tools/scenarios.sh")
if [ "${expected:-x}" != "${counted:-y}" ]; then
    fail "manifest has ${expected:-?} scenarios but the table declares ${counted:-?}"
fi

# 4. Fixture argv is packed, not evaluated: spaces, quotes and shell syntax in
# an argument must survive as one word.
cat >"$TMP/adversarial.json" <<'JSON'
{
  "schema": "rand-fast/scenarios/v1",
  "scenarios": [
    {
      "name": "quoting",
      "kind": "positive",
      "fixture": ["prog with space", "a'b", "--flag=$HOME", "semi;colon", "glob*"],
      "background": [],
      "prerequisites": [],
      "duration_s": 1,
      "repetitions": 1,
      "expect": { "top1": ["Nothing"] }
    }
  ]
}
JSON
if "$ROOT/tools/scenarios-generate.sh" "$TMP/adversarial.json" >"$TMP/adversarial.sh"; then
    # shellcheck disable=SC1090
    . "$TMP/adversarial.sh"
    old_ifs=$IFS
    IFS=$(printf '\037')
    # shellcheck disable=SC2086
    set -- $scenario_fixture_0
    IFS=$old_ifs
    [ "${1:-}" = "prog with space" ] || fail "an argument with spaces was split: '${1:-}'"
    [ "${2:-}" = "a'b" ] || fail "a quote was consumed: '${2:-}'"
    [ "${3:-}" = '--flag=$HOME' ] || fail "shell expansion reached an argument: '${3:-}'"
    [ "${4:-}" = "semi;colon" ] || fail "a command separator survived: '${4:-}'"
    [ "${5:-}" = "glob*" ] || fail "a glob was expanded: '${5:-}'"
else
    fail "the generator rejected a valid adversarial manifest"
fi

# 5. An unsupported schema is rejected before anything is emitted.
cat >"$TMP/bad.json" <<'JSON'
{ "schema": "rand-fast/scenarios/v0", "scenarios": [] }
JSON
if "$ROOT/tools/scenarios-generate.sh" "$TMP/bad.json" >"$TMP/bad.sh" 2>/dev/null; then
    fail "the generator accepted an unsupported schema"
fi
[ -s "$TMP/bad.sh" ] && fail "the generator wrote output for an unsupported schema"

if [ "$FAILURES" -ne 0 ]; then
    echo "test-scenarios: $FAILURES case(s) failed" >&2
    exit 1
fi
echo "test-scenarios: manifest, generated table, quoting and schema rejection passed"
