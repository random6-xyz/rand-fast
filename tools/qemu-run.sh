#!/bin/sh
# Boot a QEMU guest and run the rand-fast smoke matrix inside it.
#
# The privileged eBPF checks need a real kernel and root, which the developer
# host does not provide. This script builds a self-contained initramfs-only
# guest around tools/qemu-guest-init.sh, boots it under KVM, and prints the
# recorded results, so the eBPF verifier and every collector are exercised
# end to end without host sudo.
#
# Usage:
#   tools/qemu-run.sh                 # build, boot, print results
#   tools/qemu-run.sh --keep          # keep the generated initramfs and image
#   tools/qemu-run.sh --duration 10s  # longer per-run collection window
#   DURATION=10s tools/qemu-run.sh    # same, via the environment
#
# Environment overrides:
#   KERNEL     bzImage to boot (default: the kernel-server bpf-next build)
#   CPUS       guest vCPU count (default 8)
#   MEM_MB     guest memory in MiB (default 2048)
#   OUT_DIR    where the guest log is written (default /tmp/fast-qemu)
#   DURATION   per-run collection length passed to the matrix (default 5s)
#
# Exit status: 0 when the guest smoke run succeeded, 1 otherwise.
set -u

ROOT=$(cd "$(dirname "$0")/.." && pwd)
KERNEL=${KERNEL:-/home/rand/kernel-server/build/bpf-next/arch/x86_64/boot/bzImage}
CPUS=${CPUS:-8}
MEM_MB=${MEM_MB:-2048}
OUT_DIR=${OUT_DIR:-/tmp/fast-qemu}
DURATION=${DURATION:-5s}
KEEP=0

for arg in "$@"; do
    case "$arg" in
    --keep) KEEP=1 ;;
    --duration) shift; DURATION=$1 ;;
    --duration=*) DURATION=${arg#--duration=} ;;
    -h|--help)
        sed -n '2,25p' "$0" | sed 's/^# \{0,1\}//'
        exit 0
        ;;
    *) echo "qemu-run: unknown argument: $arg" >&2; exit 2 ;;
    esac
    [ "$#" -gt 0 ] && shift || true
done

log() { printf 'qemu-run: %s\n' "$*"; }
die() { printf 'qemu-run: %s\n' "$*" >&2; exit 1; }

[ -r "$KERNEL" ] || die "kernel not readable: $KERNEL (set KERNEL=<bzImage>)"
command -v qemu-system-x86_64 >/dev/null 2>&1 || die "qemu-system-x86_64 not found"
command -v cpio >/dev/null 2>&1 || die "cpio not found"
BUSYBOX=$(command -v busybox 2>/dev/null) || die "busybox not found"

mkdir -p "$OUT_DIR" || die "cannot create $OUT_DIR"

STAGE="$OUT_DIR/initramfs"
IO_IMG="$OUT_DIR/fast-io.img"
INITRAMFS="$OUT_DIR/initramfs.img.gz"
LOG="$OUT_DIR/guest.log"

# --- release binaries -------------------------------------------------------
log "building release binaries"
( cd "$ROOT" && cargo build --release ) >/dev/null 2>&1 || die "cargo build --release failed"
for binary in fast sched-workload fast-workload; do
    [ -x "$ROOT/target/release/$binary" ] || die "missing target/release/$binary"
done

# The tiny mount(2) wrapper: busybox mount in this init is not present, and
# the init script needs to mount proc/sysfs/tracefs without a helper.
log "building the static mount helper"
gcc -static -O2 -o "$OUT_DIR/mount2" "$ROOT/tools/qemu-guest-mount.c" \
    || die "failed to build the mount helper"

# --- ext4 scratch disk for the io-hog fixture --------------------------------
# Reads served from tmpfs never reach the block_rq_* tracepoints, so the io
# fixture needs a real block device.
if [ ! -f "$IO_IMG" ]; then
    log "creating the 256M ext4 scratch image"
    truncate -s 256M "$IO_IMG" || die "truncate failed"
    mkfs.ext4 -q -F "$IO_IMG" || die "mkfs.ext4 failed"
fi

# --- initramfs staging ------------------------------------------------------
log "staging the initramfs"
rm -rf "$STAGE"
# Brace expansion is not portable to POSIX sh, so the directories are listed.
mkdir -p "$STAGE/bin" "$STAGE/lib" "$STAGE/lib64" "$STAGE/tools" \
    "$STAGE/dev" "$STAGE/proc" "$STAGE/sys" "$STAGE/tmp" "$STAGE/mnt/io" \
    || die "staging failed"

cp "$BUSYBOX" "$STAGE/bin/busybox"
cp "$OUT_DIR/mount2" "$STAGE/bin/mount2"
# The init script starts with `busybox --install -s /bin`, but that runs too
# late: the kernel needs /bin/sh to satisfy the shebang of /init itself.
# Without this symlink the guest panics with "Failed to execute /init (-2)".
ln -s busybox "$STAGE/bin/sh"
for binary in fast sched-workload fast-workload; do
    cp "$ROOT/target/release/$binary" "$STAGE/bin/$binary"
done

# The release binaries are dynamically linked against glibc; the guest has no
# package manager, so the runtime loader and the needed libraries are staged.
FAST_BIN="$ROOT/target/release/fast"
ldd "$FAST_BIN" > "$OUT_DIR/ldd.txt" 2>/dev/null || die "ldd failed on $FAST_BIN"
LOADER=$(awk '/ld-linux/{print $1; exit}' "$OUT_DIR/ldd.txt")
[ -n "$LOADER" ] || die "could not locate the dynamic loader for $FAST_BIN"
cp "$LOADER" "$STAGE/lib64/ld-linux-x86-64.so.2"
# Every "lib*.so* => /path" entry is a shared library the binaries need.
awk '/=> \//{print $3}' "$OUT_DIR/ldd.txt" | while read -r lib; do
    [ -f "$lib" ] || continue
    mkdir -p "$STAGE/lib"
    cp "$lib" "$STAGE/lib/" 2>/dev/null || true
done
log "staged loader $(basename "$LOADER") and $(awk '/=> \//{print $3}' "$OUT_DIR/ldd.txt" | wc -l) libraries"

cp "$ROOT/tools/qemu-smoke.sh" "$STAGE/tools/qemu-smoke.sh"
cp "$ROOT/tools/qemu-guest-init.sh" "$STAGE/init"

log "packing the initramfs"
( cd "$STAGE" && find . | cpio -o -H newc 2>/dev/null | gzip -1 ) > "$INITRAMFS" \
    || die "failed to pack the initramfs"

# --- boot -------------------------------------------------------------------
KVM=off
if [ -r /dev/kvm ] && [ -w /dev/kvm ]; then
    KVM=on
    log "KVM available"
else
    log "KVM unavailable, falling back to TCG emulation (slow)"
fi

log "booting the guest (${CPUS} vCPU, ${MEM_MB} MiB, duration $DURATION)"
rm -f "$LOG"
# The guest powers itself off at the end of the run, so a bounded timeout
# only guards against a hang.
if [ "$KVM" = on ]; then
    ACCEL="-enable-kvm"
else
    ACCEL=""
fi

# shellcheck disable=SC2086
timeout 1800 qemu-system-x86_64 $ACCEL \
    -m "$MEM_MB" -smp "$CPUS" \
    -kernel "$KERNEL" -initrd "$INITRAMFS" \
    -append "console=ttyS0 rdinit=/init loglevel=3 panic=-1 fast.duration=$DURATION" \
    -nographic -no-reboot -monitor none \
    -drive "file=$IO_IMG,format=raw,if=virtio" \
    < /dev/null > "$LOG" 2>&1
QEMU_RC=$?

log "guest log: $LOG"
if [ "$QEMU_RC" -ne 0 ]; then
    printf 'qemu-run: qemu exited with %s (124 means the 1800s timeout hit)\n' "$QEMU_RC" >&2
fi

# --- report -----------------------------------------------------------------
if grep -q 'smoke run finished with rc=0' "$LOG" 2>/dev/null; then
    RESULT=0
elif grep -q 'smoke run finished with rc=' "$LOG" 2>/dev/null; then
    RESULT=1
else
    RESULT=1
    printf 'qemu-run: the guest did not report a smoke result; it likely failed to boot\n' >&2
fi

printf '\n===== guest summary =====\n'
grep -E '^guest:|^=== .* (format|MISSING|present|available)' "$LOG" 2>/dev/null \
    | sed 's/^/  /'
grep -E 'smoke run finished with rc=' "$LOG" 2>/dev/null | sed 's/^/  /'

printf '\n===== smoke reports =====\n'
sed -n '/^=== reports ===/,$p' "$LOG" 2>/dev/null \
    | sed -n '/^----- .*\.txt -----/,$p' | tail -n +2

if [ "$KEEP" -eq 0 ]; then
    rm -rf "$STAGE"
    log "removed the staging tree (pass --keep to retain it)"
else
    log "kept $STAGE and $INITRAMFS"
fi

exit "$RESULT"
