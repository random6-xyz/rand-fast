#!/bin/sh
# Check that every workspace package and the repository license files agree.
set -eu

ROOT=$(cd "$(dirname "$0")/.." && pwd)
cd "$ROOT"

for license in LICENSE-APACHE LICENSE-MIT; do
    if [ ! -s "$license" ]; then
        echo "license check: missing $license" >&2
        exit 1
    fi
done

metadata=$(cargo metadata --no-deps --format-version 1)
printf '%s\n' "$metadata" | python3 -c '
import json
import sys

packages = json.load(sys.stdin)["packages"]
expected = "MIT OR Apache-2.0"
incorrect = [(package["name"], package["license"]) for package in packages if package["license"] != expected]
if not packages:
    print("license check: no workspace packages found", file=sys.stderr)
    raise SystemExit(1)
if incorrect:
    for name, license in incorrect:
        print(f"license check: {name} declares {license!r}; expected {expected!r}", file=sys.stderr)
    raise SystemExit(1)
print(f"license check: {len(packages)} workspace packages declare {expected}")
'
