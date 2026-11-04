#!/bin/sh
# Builds a pinned kernel image for the real-kernel QEMU gate.
#
# The tarball and its checksum come from tools/kernel/kernels.tsv. The image is
# built from that source with the pinned defconfig plus
# tools/kernel/config.fragment, and the result is cached by version + fragment
# hash so repeated CI runs do not rebuild it. Nothing here needs host root.
#
# Usage: tools/kernel/build.sh <id> [--force]
# Prints the absolute bzImage path on stdout. Diagnostics go to stderr.
set -eu

ROOT=$(cd "$(dirname "$0")/../.." && pwd)
TSV="$ROOT/tools/kernel/kernels.tsv"
CACHE=${KERNEL_CACHE:-"$HOME/.cache/rand-fast-kernels"}
JOBS=${KERNEL_JOBS:-$( (getconf _NPROCESSORS_ONLN || nproc) 2>/dev/null || echo 4 )}

usage() {
    echo "usage: tools/kernel/build.sh <id> [--force]" >&2
    exit 2
}

[ $# -ge 1 ] || usage
ID=$1
FORCE=0
[ "${2:-}" = "--force" ] && FORCE=1

row=$(awk -F '\t' -v v="$ID" '$1 == v { print; exit }' "$TSV")
[ -n "$row" ] || {
    echo "kernel-build: $ID is not pinned in $TSV" >&2
    exit 1
}
VERSION=$(printf '%s\n' "$row" | cut -f2)
PROFILE=$(printf '%s\n' "$row" | cut -f3)
URL=$(printf '%s\n' "$row" | cut -f4)
SHA256=$(printf '%s\n' "$row" | cut -f5)
TOOLCHAIN=$(printf '%s\n' "$row" | cut -f6)
if [ "$PROFILE" = default ]; then
    FRAGMENT="$ROOT/tools/kernel/config.fragment"
else
    FRAGMENT="$ROOT/tools/kernel/config.$PROFILE.fragment"
fi
[ -r "$FRAGMENT" ] || {
    echo "kernel-build: no config fragment for profile $PROFILE" >&2
    exit 1
}
[ "$TOOLCHAIN" = gcc ] || {
    echo "kernel-build: unsupported toolchain: $TOOLCHAIN" >&2
    exit 1
}

config_sha=$(sha256sum "$FRAGMENT" | awk '{print $1}')
out="$CACHE/$ID"
meta="$out/meta.txt"
expected_meta="id=$ID
version=$VERSION
profile=$PROFILE
toolchain=$TOOLCHAIN
config_sha256=$config_sha
tarball_sha256=$SHA256"

if [ "$FORCE" -eq 0 ] && [ -s "$out/bzImage" ] && [ -f "$meta" ] \
    && [ "$(cat "$meta")" = "$expected_meta" ]; then
    echo "kernel-build: reusing cached $ID" >&2
    printf '%s\n' "$out/bzImage"
    exit 0
fi

mkdir -p "$CACHE/downloads" "$out"
tarball="$CACHE/downloads/linux-$VERSION.tar.xz"
if [ ! -f "$tarball" ] || [ "$(sha256sum "$tarball" | awk '{print $1}')" != "$SHA256" ]; then
    echo "kernel-build: downloading $URL" >&2
    rm -f "$tarball"
    curl --fail --silent --show-error --location --retry 3 \
        --output "$tarball" "$URL" || {
        echo "kernel-build: download failed" >&2
        exit 1
    }
fi
actual=$(sha256sum "$tarball" | awk '{print $1}')
[ "$actual" = "$SHA256" ] || {
    echo "kernel-build: checksum mismatch for $tarball (got $actual)" >&2
    exit 1
}

work="$CACHE/build/$ID"
rm -rf "$work"
mkdir -p "$work/obj"
# A failed build must not leave a multi-GiB tree in the cache.
trap 'rm -rf "$work"' EXIT HUP INT TERM
echo "kernel-build: extracting $VERSION" >&2
tar -xf "$tarball" -C "$work"
src="$work/linux-$VERSION"
[ -d "$src" ] || {
    echo "kernel-build: extracted tree not found: $src" >&2
    exit 1
}

echo "kernel-build: defconfig + required facilities for $ID ($PROFILE)" >&2
make -C "$src" O="$work/obj" ARCH=x86_64 defconfig >/dev/null
"$src/scripts/kconfig/merge_config.sh" -m -O "$work/obj" \
    "$work/obj/.config" "$FRAGMENT" >/dev/null
make -C "$src" O="$work/obj" ARCH=x86_64 olddefconfig >/dev/null

echo "kernel-build: building bzImage with $JOBS jobs" >&2
make -C "$src" O="$work/obj" ARCH=x86_64 -j"$JOBS" bzImage >/dev/null

# A bootable image with the wrong facilities would fail later with a confusing
# guest error, so the required symbols are checked here, at build time.
missing=""
for symbol in CONFIG_BPF CONFIG_BPF_SYSCALL CONFIG_BPF_EVENTS CONFIG_DEBUG_INFO_BTF \
    CONFIG_FTRACE CONFIG_TRACEPOINTS CONFIG_KPROBES CONFIG_PERF_EVENTS \
    CONFIG_VIRTIO_BLK CONFIG_EXT4_FS CONFIG_SERIAL_8250_CONSOLE \
    CONFIG_IKCONFIG_PROC; do
    if ! grep -q "^$symbol=y" "$work/obj/.config"; then
        missing="$missing $symbol"
    fi
done
if [ "$PROFILE" = nopsi ]; then
    grep -q '^# CONFIG_PSI is not set' "$work/obj/.config" || missing="$missing CONFIG_PSI-disabled"
else
    grep -q '^CONFIG_PSI=y' "$work/obj/.config" || missing="$missing CONFIG_PSI=y"
fi
if [ -n "$missing" ]; then
    echo "kernel-build: required configuration missing:$missing" >&2
    echo "kernel-build: see $work/obj/.config" >&2
    exit 1
fi

cp "$work/obj/arch/x86/boot/bzImage" "$out/bzImage"
cp "$work/obj/.config" "$out/config"
cat "$src/include/config/kernel.release" >"$out/kernel.release" 2>/dev/null \
    || cat "$work/obj/include/config/kernel.release" >"$out/kernel.release"
release=$(cat "$out/kernel.release")
[ "$release" = "$VERSION" ] || {
    echo "kernel-build: built release '$release' does not match pinned version '$VERSION'" >&2
    exit 1
}
printf '%s\n' "$expected_meta" >"$meta"
{
    echo "id=$ID"
    echo "version=$VERSION"
    echo "profile=$PROFILE"
    echo "source=$URL"
    echo "sha256=$SHA256"
    echo "config_sha256=$config_sha"
    echo "kernel_release=$(cat "$out/kernel.release")"
    echo "toolchain=$TOOLCHAIN"
    echo "gcc=$(gcc --version 2>/dev/null | head -1)"
    echo "pahole=$(pahole --version 2>/dev/null | head -1)"
    echo "qemu=$(qemu-system-x86_64 --version 2>/dev/null | head -1)"
    echo "jobs=$JOBS"
    echo "built_at=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
} >"$out/build-info.txt"

printf '%s\n' "$out/bzImage"
