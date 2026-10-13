#!/usr/bin/env bash
# Build and package the versioned Linux x86_64 GitHub Release assets.
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/.." && pwd)
TAG=${1:?Usage: tools/package-release.sh vMAJOR.MINOR.PATCH}

if [[ ! "$TAG" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    echo "release package: expected vMAJOR.MINOR.PATCH, got: $TAG" >&2
    exit 2
fi

cd "$ROOT"
CARGO_VERSION=$(cargo metadata --no-deps --format-version 1 | python3 -c '
import json
import sys
packages = json.load(sys.stdin)["packages"]
print(next(package["version"] for package in packages if package["name"] == "fast"))
')
TAG_VERSION=${TAG#v}
if [ "$TAG_VERSION" != "$CARGO_VERSION" ]; then
    echo "release package: tag version $TAG_VERSION does not match fast package version $CARGO_VERSION" >&2
    exit 1
fi

if ! command -v cargo-about >/dev/null 2>&1; then
    echo "release package: cargo-about is required (install version 0.9.2)" >&2
    exit 1
fi

TARGET=x86_64-unknown-linux-gnu
ASSET_DIR="$ROOT/target/release-assets"
PACKAGE_NAME="rand-fast-${TAG}"
PACKAGE_DIR="$ASSET_DIR/$PACKAGE_NAME"
ARCHIVE_NAME="${PACKAGE_NAME}-linux-x86_64.tar.gz"

cargo build --locked --release --package fast --target "$TARGET"
mkdir -p "$ASSET_DIR"
cargo about generate about.hbs > "$ASSET_DIR/THIRD-PARTY-LICENSES.md"
rm -rf "$PACKAGE_DIR"
mkdir -p "$PACKAGE_DIR"
install -m 0755 "$ROOT/target/$TARGET/release/fast" "$PACKAGE_DIR/fast"
install -m 0644 "$ROOT/README.md" "$ROOT/LICENSE-APACHE" "$ROOT/LICENSE-MIT" \
    "$ASSET_DIR/THIRD-PARTY-LICENSES.md" "$PACKAGE_DIR/"
"$PACKAGE_DIR/fast" --help >/dev/null

tar -C "$ASSET_DIR" -czf "$ASSET_DIR/$ARCHIVE_NAME" "$PACKAGE_NAME"
(
    cd "$ASSET_DIR"
    sha256sum "$ARCHIVE_NAME" > SHA256SUMS
    sha256sum --check SHA256SUMS
)
tar -tzf "$ASSET_DIR/$ARCHIVE_NAME"
printf 'release package: %s\n' "$ASSET_DIR/$ARCHIVE_NAME"
