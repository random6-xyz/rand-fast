#!/bin/sh
# Guest init for the rand-fast QEMU smoke matrix.
#
# Builds an initramfs-only guest around this script (no root filesystem
# image needed) and runs tools/qemu-smoke.sh inside the guest as root:
#
#   gcc -static -O2 -o /bin/mount2 tools/qemu-guest-mount.c
#   (stage: /bin/busybox + applets, /bin/{fast,sched-workload,fast-workload},
#    /lib/{libc.so.6,libgcc_s.so.1,libcrypt.so.2}, /lib64/ld-linux-x86-64.so.2,
#    /tools/qemu-smoke.sh, this script as /init)
#   find . | cpio -o -H newc | gzip -1 > initramfs.img.gz
#   qemu-system-x86_64 -enable-kvm -m 2048 -smp 8 \
#       -kernel vmlinuz -initrd initramfs.img.gz \
#       -append "console=ttyS0 rdinit=/init loglevel=3 panic=-1" \
#       -nographic -no-reboot -monitor none \
#       -drive file=/tmp/fast-io.img,format=raw,if=virtio
#
# Optional virtio disk: an ext4 scratch device for the io-hog fixture
# (tmpfs reads never reach the block_rq_* tracepoints).
/bin/busybox --install -s /bin 2>/dev/null

# Mount-point directories must exist before the mounts below; fresh staging
# trees do not carry them.
mkdir -p /proc /sys /dev /tmp /mnt/io

/bin/mount2 none proc /proc
/bin/mount2 none sysfs /sys
/bin/mount2 none devtmpfs /dev 2>/dev/null
mkdir -p /sys/kernel/tracing /sys/kernel/debug
/bin/mount2 none tracefs /sys/kernel/tracing
/bin/mount2 none debugfs /sys/kernel/debug

# Networking: bring loopback up so the net-hog fixture can run.
ip link set lo up

# Real block device for the io-hog fixture, when one is attached. Only use
# /mnt/io when the mount actually succeeded; otherwise fall back to the
# default tmpfs path (which collects no block_rq_* samples).
IO_HOG_PATH=/tmp/fast-workload-io
if [ -e /dev/vda ]; then
    mkdir -p /mnt/io
    if /bin/mount2 /dev/vda ext4 /mnt/io; then
        IO_HOG_PATH=/mnt/io/fast-workload-io
        echo "guest: block device /dev/vda mounted at /mnt/io"
    else
        echo "guest: block device mount FAILED; io-hog falls back to tmpfs"
    fi
else
    echo "guest: block device MISSING; io-hog falls back to tmpfs"
fi

echo "guest: kernel $(uname -r)"
if [ -e /sys/kernel/btf/vmlinux ]; then
    echo "guest: BTF present"
else
    echo "guest: BTF MISSING"
fi
if [ -e /sys/kernel/tracing/events/sched/sched_wakeup ]; then
    echo "guest: tracefs mounted"
else
    echo "guest: tracefs NOT available"
fi

# Record the block tracepoint payload layout the eBPF I/O programs rely on
# (7.2.x layout: dev=8, sector=16, nr_sector=24, bytes/error=28, rwbs=34).
for event in block_rq_issue block_rq_complete; do
    if [ -e /sys/kernel/tracing/events/block/$event/format ]; then
        echo "=== $event format ==="
        cat /sys/kernel/tracing/events/block/$event/format
    else
        echo "=== $event format MISSING ==="
    fi
done

# Record the TCP tracepoint payload layouts the eBPF network programs rely
# on. Both events carry the socket 5-tuple in the payload, so the programs
# need no BTF and no struct offsets: tcp_probe also carries srtt, and
# tcp_retransmit_skb carries the IPv4 and IPv6 addresses.
for event in tcp_probe tcp_retransmit_skb; do
    if [ -e /sys/kernel/tracing/events/tcp/$event/format ]; then
        echo "=== $event format ==="
        cat /sys/kernel/tracing/events/tcp/$event/format
    else
        echo "=== $event format MISSING ==="
    fi
done

# Record the memory tracepoint payload layouts the eBPF memory programs rely
# on: user page faults, and direct reclaim, which is where a task stalls when
# memory runs short.
for spec in exceptions/page_fault_user vmscan/mm_vmscan_direct_reclaim_begin; do
    event=$(basename "$spec")
    category=$(dirname "$spec")
    if [ -e "/sys/kernel/tracing/events/$category/$event/format" ]; then
        echo "=== $event format ==="
        cat "/sys/kernel/tracing/events/$category/$event/format"
    else
        echo "=== $event format MISSING ==="
    fi
done

# PSI is the other half of the memory picture. The verified kernel is built
# without it, which the memory report has to say out loud rather than quietly
# reporting zeroes.
if [ -r /proc/pressure/memory ]; then
    echo "=== pressure/memory ==="
    cat /proc/pressure/memory
else
    echo "=== pressure/memory MISSING (kernel built without CONFIG_PSI) ==="
fi

export FAST=/bin/fast
export SCHED_WORKLOAD=/bin/sched-workload
export FAST_WORKLOAD=/bin/fast-workload
export OUT_DIR=/tmp/fast-smoke
export IO_HOG_PATH

# The per-run collection window is passed on the kernel command line as
# fast.duration=<value> so the host helper can change it without rebuilding
# the initramfs. tools/qemu-run.sh sets it; a hand-built guest keeps 5s.
export DURATION=5s
if [ -r /proc/cmdline ]; then
    for arg in $(cat /proc/cmdline); do
        case "$arg" in
        fast.duration=*) DURATION=${arg#fast.duration=} ;;
        esac
    done
fi
echo "guest: collection duration $DURATION"

sh /tools/qemu-smoke.sh
rc=$?
echo "=== smoke run finished with rc=$rc ==="
echo "=== fixture logs ==="
for f in /tmp/fast-smoke/*-fixture.log; do
    [ -f "$f" ] || continue
    echo "----- $f -----"
    cat "$f"
done
echo "=== reports ==="
for f in /tmp/fast-smoke/*.txt; do
    echo "----- $f -----"
    cat "$f"
done
# The diagnose scenario documents are single-line JSON, so they are dumped
# wrapped rather than raw, to keep the console log readable.
for f in /tmp/fast-smoke/scenario-*.json; do
    [ -f "$f" ] || continue
    echo "----- $f -----"
    tr ',' '\n' <"$f"
done
sync
poweroff -f
# Fallback if poweroff is not honored
sleep 5
echo o > /proc/sysrq-trigger
while true; do sleep 1; done
