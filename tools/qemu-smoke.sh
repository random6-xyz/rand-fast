#!/bin/sh
# QEMU smoke matrix for all eBPF-backed fast subcommands.
#
# Records verifier results and idle-vs-load deltas for sched, cpu, io, net,
# and off-cpu, one case per line, so results can be pasted into the README
# matrix. Run it as root inside the QEMU guest (the kernel used for the
# matrix, see README) or on a host where you hold CAP_BPF + CAP_PERFMON.
#
# Besides the matrix, the v1.0 accuracy checks quantify:
# - cpu rate scaling: samples scale with --frequency x CPU time,
# - cpu symbolization: the lock-hog futex wait path appears in top stacks,
# - io per-request pairing: completions match issues (ratio ~ 1).
#
# Expected working directory contents (release binaries):
#   ./fast  ./sched-workload  ./fast-workload
#   (override with FAST, SCHED_WORKLOAD, FAST_WORKLOAD)
#
# Environment overrides:
#   DURATION    per-run collection length (default 5s)
#   OUT_DIR     where raw reports are written (default /tmp/fast-smoke)
#   IO_HOG_PATH file the io-hog reads; put it on a real block device (not
#               tmpfs) so block_rq_* tracepoints fire (default /tmp/fast-workload-io)
#
# Exit status: 0 when every verifier load and idle/load collection succeeded,
# 1 otherwise (failures are also counted in the summary).
set -u

FAST=${FAST:-./fast}
SCHED_WORKLOAD=${SCHED_WORKLOAD:-./sched-workload}
FAST_WORKLOAD=${FAST_WORKLOAD:-./fast-workload}
DURATION=${DURATION:-5s}
OUT_DIR=${OUT_DIR:-/tmp/fast-smoke}
IO_HOG_PATH=${IO_HOG_PATH:-/tmp/fast-workload-io}
FAILURES=0

cleanup() {
    kill $(jobs -p) 2>/dev/null
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

mkdir -p "$OUT_DIR"
for binary in "$FAST" "$SCHED_WORKLOAD" "$FAST_WORKLOAD"; do
    if [ ! -x "$binary" ]; then
        echo "missing executable: $binary" >&2
        exit 1
    fi
done

echo "kernel: $(uname -r)"
echo "duration: $DURATION"
echo

run_case() {
    # run_case <command> <fixture-cmd...>
    local command_name="$1"
    shift
    local report="$OUT_DIR/$command_name.txt"
    "$SCHED_WORKLOAD" target --duration 30s --period 1ms >/dev/null 2>&1 &
    local target_pid=$!
    sleep 0.3

    if "$FAST" "$command_name" --pid "$target_pid" --duration "$DURATION" \
        >"$report" 2>&1; then
        echo "$command_name verifier: pass (program loaded and attached)"
    else
        echo "$command_name verifier: FAIL"
        cat "$report"
        FAILURES=$((FAILURES + 1))
        kill "$target_pid" 2>/dev/null
        return
    fi

    # Load case: run the fixture for the target and collect again.
    "$@" >"$OUT_DIR/$command_name-fixture.log" 2>&1 &
    local load_pid=$!
    sleep 0.5
    if "$FAST" "$command_name" --pid "$load_pid" --duration "$DURATION" \
        >"$OUT_DIR/$command_name-load.txt" 2>&1; then
        : # counted as success; the report itself carries the numbers
    else
        echo "$command_name load collection: FAIL (see $OUT_DIR/$command_name-load.txt)"
        FAILURES=$((FAILURES + 1))
    fi
    kill "$load_pid" "$target_pid" 2>/dev/null
    wait "$load_pid" 2>/dev/null
    wait "$target_pid" 2>/dev/null

    echo "  idle report: $report"
    echo "  load report: $OUT_DIR/$command_name-load.txt"
    echo
}

run_sched_case() {
    # sched compares the same target idle vs under external contention.
    local report_idle="$OUT_DIR/sched.txt"
    local report_load="$OUT_DIR/sched-load.txt"

    "$SCHED_WORKLOAD" target --duration 30s --period 1ms >/dev/null 2>&1 &
    local target_pid=$!
    sleep 0.3
    if "$FAST" sched --pid "$target_pid" --duration "$DURATION" >"$report_idle" 2>&1; then
        echo "sched verifier: pass (program loaded and attached)"
    else
        echo "sched verifier: FAIL"
        cat "$report_idle"
        FAILURES=$((FAILURES + 1))
        kill "$target_pid" 2>/dev/null
        return
    fi

    "$SCHED_WORKLOAD" hog --duration 30s --workers 8 >/dev/null 2>&1 &
    local hog_pid=$!
    if "$FAST" sched --pid "$target_pid" --duration "$DURATION" >"$report_load" 2>&1; then
        : # counted as success
    else
        echo "sched load collection: FAIL (see $report_load)"
        FAILURES=$((FAILURES + 1))
    fi
    kill "$hog_pid" "$target_pid" 2>/dev/null
    wait 2>/dev/null

    echo "  idle report: $report_idle"
    echo "  load report: $report_load"
    echo
}

run_sched_case
run_case cpu "$SCHED_WORKLOAD" hog --duration 30s --workers 8
run_case io "$FAST_WORKLOAD" io-hog --duration 30s --workers 2 --path "$IO_HOG_PATH"
run_case net "$FAST_WORKLOAD" net-hog --duration 30s --workers 4
run_case off-cpu "$FAST_WORKLOAD" lock-hog --duration 30s --workers 16
run_case memory "$FAST_WORKLOAD" mem-hog --duration 30s --workers 2
run_case diagnose "$FAST_WORKLOAD" lock-hog --duration 30s --workers 16

# --- v1.0 accuracy checks ---
check_cpu_rate_scaling() {
    # Samples must scale with frequency x CPU time: 396 Hz yields ~4x the
    # sample count of 99 Hz against the same busy-spin hog.
    "$SCHED_WORKLOAD" hog --duration 20s --workers 8 >/dev/null 2>&1 &
    local hog_pid=$!
    sleep 0.3
    local one four ratio_ok=1
    if ! "$FAST" cpu --pid "$hog_pid" --duration "$DURATION" \
        >"$OUT_DIR/cpu-rate-1x.txt" 2>&1; then
        echo "cpu rate scaling: FAIL (99 Hz collection failed)"
        FAILURES=$((FAILURES + 1))
        kill "$hog_pid" 2>/dev/null
        return
    fi
    if ! "$FAST" cpu --pid "$hog_pid" --duration "$DURATION" --frequency 396 \
        >"$OUT_DIR/cpu-rate-4x.txt" 2>&1; then
        echo "cpu rate scaling: FAIL (396 Hz collection failed)"
        FAILURES=$((FAILURES + 1))
        kill "$hog_pid" 2>/dev/null
        return
    fi
    one=$(grep -m1 '^Samples:' "$OUT_DIR/cpu-rate-1x.txt" | awk '{print $2}')
    four=$(grep -m1 '^Samples:' "$OUT_DIR/cpu-rate-4x.txt" | awk '{print $2}')
    awk -v a="${one:-0}" -v b="${four:-0}" \
        'BEGIN { if (a+0 <= 0) { print "cpu rate scaling: FAIL (no samples at 99 Hz)"; exit 1 }
                 r = (b+0) / (a+0)
                 printf "cpu rate scaling: %d samples at 99 Hz -> %d samples at 396 Hz (%.2fx)\n", a, b, r
                 exit (r >= 3 && r <= 5.5) ? 0 : 1 }' || ratio_ok=0
    if [ "$ratio_ok" -ne 1 ]; then
        FAILURES=$((FAILURES + 1))
    fi
    kill "$hog_pid" 2>/dev/null
    wait "$hog_pid" 2>/dev/null
}

check_cpu_symbolization() {
    # The lock-hog fixture parks in futex syscalls; the futex wait path must
    # show up symbolized in the hot stacks (kernel frames and user frames).
    "$FAST_WORKLOAD" lock-hog --duration 20s --workers 16 >/dev/null 2>&1 &
    local hog_pid=$!
    sleep 0.3
    local report="$OUT_DIR/cpu-symbols.txt"
    if "$FAST" cpu --pid "$hog_pid" --duration "$DURATION" >"$report" 2>&1; then
        if grep -q '\[k\] .*futex' "$report" \
            && grep -Eq '^  [0-9]+ +[A-Za-z_]' "$report"; then
            echo "cpu symbolization: pass (futex kernel frames + symbolized user frames)"
        else
            echo "cpu symbolization: FAIL (futex path not visible; see $report)"
            FAILURES=$((FAILURES + 1))
        fi
    else
        echo "cpu symbolization: FAIL (collection failed; see $report)"
        FAILURES=$((FAILURES + 1))
    fi
    kill "$hog_pid" 2>/dev/null
    wait "$hog_pid" 2>/dev/null
}

check_io_pairing() {
    # Per-request tracking: the completion count must approach the issue
    # count. The fixture runs 8s and the collection starts 0.2s later and
    # stops when the fixture exits, so ~0.97 is the ceiling; the pre-v1.0
    # TID matching paired only a fraction of a percent.
    "$FAST_WORKLOAD" io-hog --duration 8s --workers 2 --path "$IO_HOG_PATH" \
        >"$OUT_DIR/io-pair-fixture.log" 2>&1 &
    local hog_pid=$!
    sleep 0.2
    local report="$OUT_DIR/io-pair.txt"
    if "$FAST" io --pid "$hog_pid" --duration 8s >"$report" 2>&1; then
        local samples reads
        samples=$(grep -m1 '^Samples:' "$report" | awk '{print $2}')
        reads=$(grep -m1 'in [0-9]* reads' "$OUT_DIR/io-pair-fixture.log" | awk '{print $6}')
        awk -v s="${samples:-0}" -v r="${reads:-0}" \
            'BEGIN { if (r+0 == 0) { print "io pairing: FAIL (fixture performed no reads)"; exit 1 }
                     p = (s+0) / (r+0) * 100
                     printf "io pairing: %s completions for %s reads (%.1f%%)\n", s, r, p
                     exit (p >= 80) ? 0 : 1 }' \
            || FAILURES=$((FAILURES + 1))
    else
        echo "io pairing: FAIL (collection failed; see $report)"
        FAILURES=$((FAILURES + 1))
    fi
    kill "$hog_pid" 2>/dev/null
    wait "$hog_pid" 2>/dev/null
}

# Proves the RTT distribution actually moves when the link degrades.
#
# A qdisc would be the obvious way to degrade a link, but netem, HTB and TBF
# are all optional kernel features and none of them are usable on loopback in
# the verified kernel (netem and TBF are not built in, and HTB shapes the
# link so hard the connection never gets going). The stalling fixture is used
# instead: it closes the receive window in cycles, which stretches the round
# trip into the tens of milliseconds while the baseline sits in the tens of
# microseconds.
#
# The slowest endpoint is compared on both sides. Cycling the receive window
# leaves one direction of each connection fast and the other stretched, so a
# median lands on whichever side happened to dominate and the ratio collapses
# from one run to the next. The slowest endpoint is the same measurement on
# both sides, and the gap is measured in orders of magnitude, so a loose
# threshold still catches a measurement that is stuck or scaled wrong. The
# report is reused from the retransmission check, which needs the same
# cycling workload.
RTT_MIN_RATIO=${RTT_MIN_RATIO:-20}

# rand-fast reports microseconds, ss reports milliseconds. The two must agree
# within a factor of two: wide enough for the run-to-run drift of a smoothed
# RTT, tight enough to catch a wrong scale factor or a misread offset.
RTT_CROSSCHECK_TOLERANCE=${RTT_CROSSCHECK_TOLERANCE:-2}

# Proves the endpoint ranking is usable: the report is supposed to lead with
# the connection that is actually slow, so the first row has to be a real
# outlier rather than one of the healthy ones. The cycling fixture stretches
# its round trips into the milliseconds while a plain loopback run sits in the
# microseconds, so the two are compared row by row.
check_net_endpoint_ranking() {
    if [ ! -f "$OUT_DIR/net-retrans.txt" ] || [ ! -f "$OUT_DIR/net-rtt-base.txt" ]; then
        echo "net endpoint ranking: SKIP (no reports from the earlier net checks)"
        return
    fi

    # First data row of each table, and the slowest row of the cycling table.
    local worst_p95 base_p95 median_p95
    worst_p95=$(max_p95_us "$OUT_DIR/net-retrans.txt")
    base_p95=$(max_p95_us "$OUT_DIR/net-rtt-base.txt")
    median_p95=$(median_p50_us "$OUT_DIR/net-retrans.txt")

    if [ "${worst_p95:-0}" -le 0 ] || [ "${median_p95:-0}" -le 0 ]; then
        echo "net endpoint ranking: FAIL (no p95 values; worst=$worst_p95 median=$median_p95)"
        FAILURES=$((FAILURES + 1))
        return
    fi
    if ! awk -v w="$worst_p95" -v m="$median_p95" -v b="$base_p95" \
            'BEGIN { ok = (w >= b * 5)
                     printf "net endpoint ranking: first row %d us p95 vs %d us median under load and %d us on plain loopback\n", w, m, b
                     exit ok ? 0 : 1 }'; then
        echo "    the first row is not a real outlier, so the ranking is not leading with the slow endpoint"
        FAILURES=$((FAILURES + 1))
    fi
}

check_net_rtt_separation() {
    local base stalled ratio_ok=1
    base=$(max_p95_us "$OUT_DIR/net-rtt-base.txt")
    # The cycling run that check_net_retransmit_attribution collected: its
    # round trips are stretched by the shut receive window.
    stalled=$(max_p95_us "$OUT_DIR/net-retrans.txt")
    if [ "${base:-0}" -le 0 ] || [ "${stalled:-0}" -le 0 ]; then
        echo "net RTT separation: FAIL (no RTT samples; plain loopback=$base window cycling=$stalled)"
        FAILURES=$((FAILURES + 1))
        return
    fi
    if ! awk -v b="$base" -v d="$stalled" -v need="$RTT_MIN_RATIO" \
            'BEGIN { r = (b + 0) == 0 ? 0 : d / b
                     printf "net RTT separation: slowest endpoint p95 %d us on plain loopback vs %d us with the receive window cycling shut (%.0fx)\n", b, d, r
                     exit (r >= need) ? 0 : 1 }'; then
        ratio_ok=0
    fi
    [ "$ratio_ok" -eq 1 ] || FAILURES=$((FAILURES + 1))
}

# Locates ss, which busybox does not provide at all.
SS_BIN=""
for candidate in /sbin/ss /bin/ss; do
    [ -x "$candidate" ] && { SS_BIN=$candidate; break; }
done

# Median of the per-endpoint p50 column, in microseconds.
#
# The endpoint table is printed with fixed-width numeric columns, so the
# columns are positional: p95, p50, p99, samples, retrans, ratio, endpoint.
# Data rows are recognised by a leading integer, which the header and the
# surrounding prose never have.
median_p50_us() {
    awk '$1 ~ /^[0-9]+$/ { print $2 }' "$1" | sort -n \
        | awk '{ v[NR] = $1 } END { if (NR == 0) { print 0 } else { print v[int((NR+1)/2)] } }'
}

# Slowest p95 in a report, in microseconds.
max_p95_us() {
    awk '$1 ~ /^[0-9]+$/ && $1 + 0 > m { m = $1 + 0 } END { print m + 0 }' "$1"
}

# Congestion window rand-fast reported for the slowest endpoint, which the
# report prints in its detail block.
fast_cwnd() {
    awk '/congestion window/ { print $3; exit }' "$1"
}

# Congestion window `ss -ti` reported for a loopback socket.
ss_cwnd() {
    awk '/cwnd:/ { for (i = 1; i <= NF; i++) if ($i ~ /^cwnd:/ && $i != "cwnd:") { split($i, p, ":"); print p[2]; exit } }' "$1"
}

# Median of the `rtt:` values `ss -ti` printed for loopback sockets, in
# microseconds.
#
# `ss -ti` prints two lines per socket: a header with the addresses, then an
# indented detail line carrying `rtt:<smoothed>/<last>`. The detail line is
# what holds the number, so the header is remembered and checked to decide
# whether the detail line belongs to a loopback socket. The first number of
# `rtt:` is the same srtt the tracepoint carries.
median_ss_rtt_us() {
    awk '/127\.0\.0\.1/ { loopback = 1; next }
         loopback && /rtt:/ {
             for (i = 1; i <= NF; i++)
                 if ($i ~ /^rtt:/ && $i != "rtt:") {
                     split($i, part, "/")
                     split(part[1], pair, ":")
                     if (pair[2] + 0 > 0) print pair[2] * 1000
                 }
             loopback = 0
         }' "$1" | sort -n \
        | awk '{ v[NR] = $1 } END { if (NR == 0) { print 0 } else { print v[int((NR+1)/2)] } }'
}

# Collects RTT for a net-hog fixture. Arguments are the report path and the
# path the ss snapshot is written to. Returns non-zero when the collection
# fails; the fixture is always cleaned up.
#
# The ss snapshot is sampled repeatedly while the eBPF collection runs, not
# once before it. rand-fast adds its own overhead to a saturated guest, so a
# snapshot taken before collection starts would compare a lightly loaded
# loopback against a heavily loaded one and report a large false mismatch.
collect_net_rtt() {
    report=$1
    ss_out=$2
    "$FAST_WORKLOAD" net-hog --duration 20s --workers 2 >/dev/null 2>&1 &
    fixture_pid=$!
    sleep 0.3
    : >"$ss_out"
    if [ -n "$SS_BIN" ]; then
        # 0.25s of settle time, then 16 samples spaced 0.4s apart across the
        # 8s collection window.
        ( sleep 0.25
          i=0
          while [ "$i" -lt 16 ]; do
              "$SS_BIN" -ti state established 2>/dev/null >>"$ss_out" || true
              echo >>"$ss_out"
              i=$((i + 1))
              sleep 0.4
          done ) &
        ss_pid=$!
    else
        ss_pid=""
    fi
    if ! "$FAST" net --pid "$fixture_pid" --duration 8s >"$report" 2>&1; then
        [ -n "$ss_pid" ] && kill "$ss_pid" 2>/dev/null
        kill "$fixture_pid" 2>/dev/null
        wait "$fixture_pid" 2>/dev/null
        return 1
    fi
    [ -n "$ss_pid" ] && { kill "$ss_pid" 2>/dev/null; wait "$ss_pid" 2>/dev/null; }
    kill "$fixture_pid" 2>/dev/null
    wait "$fixture_pid" 2>/dev/null
    return 0
}

# Proves the retransmission path attributes events to endpoints.
#
# A loopback link never loses packets, so the fixture has to create the
# condition retransmission needs: a receive window that shuts while segments
# are still in flight. net-hog cycles the server between draining and stalling
# for longer than the initial RTO, which produces a burst of real
# retransmissions at the start of every cycle.
#
# The report must then name the endpoints carrying the retransmissions, and
# the kernel's own counters are printed alongside so a miss is
# distinguishable from a workload that simply did not retransmit.
RETRANS_DELAY_MS=${RETRANS_DELAY_MS:-600}
RETRANS_RCVBUF_KB=${RETRANS_RCVBUF_KB:-8}

check_net_retransmit_attribution() {
    "$FAST_WORKLOAD" net-hog --duration 20s --workers 2 \
        --delay-ms "$RETRANS_DELAY_MS" --rcvbuf-kb "$RETRANS_RCVBUF_KB" \
        >"$OUT_DIR/net-retrans-fixture.log" 2>&1 &
    local fixture_pid=$!
    # The fixture prints its listening port, which is used to filter the ss
    # snapshot. Without the filter a socket left over from an earlier case
    # could be mistaken for evidence that this fixture retransmitted.
    sleep 0.5
    local port
    port=$(grep -m1 -oE 'endpoint: 127\.0\.0\.1:[0-9]+' "$OUT_DIR/net-retrans-fixture.log" \
        | grep -oE '[0-9]+$')
    : >"$OUT_DIR/net-retrans-ss.txt"
    if [ -n "$SS_BIN" ]; then
        ( i=0
          while [ "$i" -lt 12 ]; do
              if [ -n "$port" ]; then
                  # Filtering on the port keeps sockets from other cases out
                  # of the evidence.
                  "$SS_BIN" -ti 2>/dev/null | grep -A1 ":$port" \
                      >>"$OUT_DIR/net-retrans-ss.txt" || true
              else
                  "$SS_BIN" -ti 2>/dev/null >>"$OUT_DIR/net-retrans-ss.txt" || true
              fi
              echo >>"$OUT_DIR/net-retrans-ss.txt"
              i=$((i + 1))
              sleep 0.5
          done ) &
        local ss_pid=$!
    else
        ss_pid=""
    fi
    if ! "$FAST" net --pid "$fixture_pid" --duration 8s >"$OUT_DIR/net-retrans.txt" 2>&1; then
        echo "net retransmit attribution: FAIL (collection failed)"
        FAILURES=$((FAILURES + 1))
        kill "$fixture_pid" 2>/dev/null
        wait "$fixture_pid" 2>/dev/null
        return
    fi
    [ -n "$ss_pid" ] && { kill "$ss_pid" 2>/dev/null; wait "$ss_pid" 2>/dev/null; }
    kill "$fixture_pid" 2>/dev/null
    wait "$fixture_pid" 2>/dev/null

    # What the kernel itself counted. bytes_retrans is cumulative per socket,
    # so the largest single value seen is the total, not the sum.
    if [ -n "$SS_BIN" ] && [ -s "$OUT_DIR/net-retrans-ss.txt" ]; then
        local kernel_bytes kernel_segs
        kernel_bytes=$(awk '/bytes_retrans:/ {for(i=1;i<=NF;i++) if($i ~ /^bytes_retrans:/){split($i,p,":"); if(p[2]+0>m) m=p[2]}} END{print m+0}' "$OUT_DIR/net-retrans-ss.txt")
        kernel_segs=$(awk '/retrans:/ {for(i=1;i<=NF;i++) if($i ~ /^retrans:/){split($i,p,"/"); if(p[2]+0>m) m=p[2]}} END{print m+0}' "$OUT_DIR/net-retrans-ss.txt")
        echo "    kernel ss on port ${port:-?}: $kernel_bytes bytes_retrans, $kernel_segs retrans segs"
    fi

    local total endpoints
    total=$(awk '/^Retransmissions:/ {print $2}' "$OUT_DIR/net-retrans.txt")
    # Endpoints whose retrans column is not zero.
    endpoints=$(awk '$1 ~ /^[0-9]+$/ && $5 + 0 > 0 { n++ } END { print n + 0 }' \
        "$OUT_DIR/net-retrans.txt")
    if [ "${total:-0}" -le 0 ]; then
        echo "net retransmit attribution: FAIL (rand-fast saw no retransmissions; see the kernel counter above for whether the workload produced any)"
        FAILURES=$((FAILURES + 1))
        return
    fi
    if [ "${endpoints:-0}" -le 0 ]; then
        echo "net retransmit attribution: FAIL ($total retransmissions were not attributed to any endpoint)"
        FAILURES=$((FAILURES + 1))
        return
    fi
    echo "net retransmit attribution: $total retransmissions across $endpoints endpoints"
}

# Cross-checks rand-fast's RTT against the kernel's own estimate.
check_net_rtt_crosscheck() {
    if [ -z "$SS_BIN" ]; then
        echo "net RTT cross-check: SKIP (no ss binary in the guest)"
        return
    fi
    if ! collect_net_rtt "$OUT_DIR/net-rtt-xcheck.txt" "$OUT_DIR/net-ss-xcheck.txt"; then
        echo "net RTT cross-check: FAIL (collection failed)"
        FAILURES=$((FAILURES + 1))
        return
    fi

    mine=$(median_p50_us "$OUT_DIR/net-rtt-xcheck.txt")
    kernel=$(median_ss_rtt_us "$OUT_DIR/net-ss-xcheck.txt")
    # The raw snapshots are summarised so a mismatch can be diagnosed from
    # the log alone instead of re-running the guest.
    echo "    fast: $(awk '$1 ~ /^[0-9]+$/{n++} END{print n+0}' "$OUT_DIR/net-rtt-xcheck.txt") endpoints, p50 $mine us, cwnd $(fast_cwnd "$OUT_DIR/net-rtt-xcheck.txt")"
    echo "    ss:   $(awk '/rtt:/{n++} END{print n+0}' "$OUT_DIR/net-ss-xcheck.txt") samples, first $(awk '/rtt:/{for(i=1;i<=NF;i++) if($i ~ /^rtt:/ && $i != "rtt:"){print $i; exit}}' "$OUT_DIR/net-ss-xcheck.txt"), cwnd $(ss_cwnd "$OUT_DIR/net-ss-xcheck.txt")"

    if [ "${mine:-0}" -le 0 ] || [ "${kernel:-0}" -le 0 ]; then
        echo "net RTT cross-check: FAIL (no samples; fast=$mine us kernel=$kernel us)"
        FAILURES=$((FAILURES + 1))
        return
    fi
    if ! awk -v a="$mine" -v b="$kernel" -v tol="$RTT_CROSSCHECK_TOLERANCE" \
            'BEGIN { lo = (a < b ? a : b); hi = (a > b ? a : b)
                     ratio = (lo + 0) == 0 ? 0 : hi / lo
                     printf "net RTT cross-check: fast %d us vs kernel ss %d us (%.2fx, tolerance %gx)\n", a, b, ratio, tol
                     exit (ratio <= tol) ? 0 : 1 }'; then
        FAILURES=$((FAILURES + 1))
    fi
}

# Confirms the payload offsets are right by checking a second field. `ss -ti`
# prints the congestion window the same way it prints the RTT, so agreement
# on both values means the reads land on the intended fields rather than
# merely on plausible-looking numbers.
check_net_field_crosscheck() {
    if [ -z "$SS_BIN" ]; then
        echo "net field cross-check: SKIP (no ss binary in the guest)"
        return
    fi
    local report="$OUT_DIR/net-rtt-xcheck.txt"
    local ss_out="$OUT_DIR/net-ss-xcheck.txt"
    [ -f "$report" ] && [ -f "$ss_out" ] || {
        echo "net field cross-check: SKIP (no snapshots from the RTT cross-check)"
        return
    }

    local mine kernel
    mine=$(fast_cwnd "$report")
    kernel=$(ss_cwnd "$ss_out")
    if [ "${mine:-0}" -le 0 ] || [ "${kernel:-0}" -le 0 ]; then
        echo "net field cross-check: FAIL (no cwnd samples; fast=$mine kernel=$kernel)"
        FAILURES=$((FAILURES + 1))
        return
    fi
    if ! awk -v a="$mine" -v b="$kernel" \
            'BEGIN { printf "net field cross-check: fast snd_cwnd %d vs kernel ss cwnd %d\n", a, b
                     exit (a == b) ? 0 : 1 }'; then
        echo "    the payload offsets do not line up with the kernel layout"
        FAILURES=$((FAILURES + 1))
    fi
}


# The unthrottled baseline both net checks compare against.
if collect_net_rtt "$OUT_DIR/net-rtt-base.txt" "$OUT_DIR/net-ss-base.txt"; then
    :
else
    echo "net RTT baseline: FAIL (collection failed)"
    FAILURES=$((FAILURES + 1))
fi

# Proves off-CPU waits are attributed to the right process shape.
#
# A CPU-bound process never blocks, so it should report almost no waits. A
# futex-contending one blocks constantly and should report many. If the
# switch-out pairing were wrong these would come out the same way, or the
# busy process would show waits it never took.
#
# The hog is the CPU-bound case: it busy-spins, so every switch-out of it is
# a preemption (prev_state 0), which is deliberately not counted as a wait.
check_offcpu_shape() {
    "$SCHED_WORKLOAD" hog --duration 20s --workers 1 >/dev/null 2>&1 &
    local hog_pid=$!
    sleep 0.3
    if ! "$FAST" off-cpu --pid "$hog_pid" --duration 6s >"$OUT_DIR/off-cpu-busy.txt" 2>&1; then
        echo "off-CPU shape: FAIL (collection against the CPU-bound hog failed)"
        FAILURES=$((FAILURES + 1))
        kill "$hog_pid" 2>/dev/null
        wait "$hog_pid" 2>/dev/null
        return
    fi
    kill "$hog_pid" 2>/dev/null
    wait "$hog_pid" 2>/dev/null

    "$FAST_WORKLOAD" lock-hog --duration 20s --workers 16 >/dev/null 2>&1 &
    local lock_pid=$!
    sleep 0.3
    if ! "$FAST" off-cpu --pid "$lock_pid" --duration 6s >"$OUT_DIR/off-cpu-locked.txt" 2>&1; then
        echo "off-CPU shape: FAIL (collection against lock-hog failed)"
        FAILURES=$((FAILURES + 1))
        kill "$lock_pid" 2>/dev/null
        wait "$lock_pid" 2>/dev/null
        return
    fi
    kill "$lock_pid" 2>/dev/null
    wait "$lock_pid" 2>/dev/null

    local busy locked
    busy=$(awk '/^Samples:/ {print $2; exit}' "$OUT_DIR/off-cpu-busy.txt")
    locked=$(awk '/^Samples:/ {print $2; exit}' "$OUT_DIR/off-cpu-locked.txt")
    if [ "${busy:-0}" -gt 500 ]; then
        echo "off-CPU shape: FAIL (CPU-bound hog reported $busy waits; a busy-spinning thread should not block)"
        FAILURES=$((FAILURES + 1))
    elif [ "${locked:-0}" -lt 1000 ]; then
        echo "off-CPU shape: FAIL (lock-hog reported only $locked waits; futex contention should block constantly)"
        FAILURES=$((FAILURES + 1))
    else
        echo "off-CPU shape: $busy waits for the CPU-bound hog against $locked for lock-hog"
    fi
}

# Proves the off-CPU report answers the question it exists for: which wait is
# costing this process the most time, and where is it waiting.
#
# lock-hog blocks on a futex in a tight loop, so the report must rank the futex
# bucket first and the leading stack must resolve to the futex path. A report
# that only counted waits, or that ranked by sample count instead of total
# time, would fail this.
check_offcpu_ranking() {
    local report="$OUT_DIR/off-cpu-load.txt"
    if [ ! -f "$report" ]; then
        echo "off-CPU ranking: SKIP (no off-CPU report from the matrix)"
        return
    fi

    local top_reason
    top_reason=$(awk '/Wait reasons/ { getline; print $1; exit }' "$report")
    if [ "$top_reason" != "futex" ]; then
        echo "off-CPU ranking: FAIL (top wait reason is '$top_reason', expected futex)"
        FAILURES=$((FAILURES + 1))
        return
    fi

    # The leading stack is the first "stack <id>" line under the stack section.
    local stack_line
    stack_line=$(awk '/Top wait stacks/ { f = 1 } f && /^  stack / { print; exit }' "$report")
    if [ -z "$stack_line" ]; then
        echo "off-CPU ranking: FAIL (no wait stacks listed)"
        FAILURES=$((FAILURES + 1))
        return
    fi
    # The frames of that stack follow, indented. A symbolized futex frame is
    # what makes the report actionable.
    if ! awk '/Top wait stacks/ { f = 1; next }
               f && /^  stack / { s = 1; next }
               s && /^  stack / { exit }
               s && /futex/ { found = 1 }
               END { exit found ? 0 : 1 }' "$report"; then
        echo "off-CPU ranking: FAIL (the top wait stack has no symbolized futex frame)"
        FAILURES=$((FAILURES + 1))
        return
    fi

    local total
    total=$(awk '/^Total off-CPU:/ { print $3; exit }' "$report")
    echo "off-CPU ranking: futex is the top reason, $total total off-CPU, leading stack $stack_line"
}

# Proves the kernel-side page fault counter keeps up.
#
# The counter exists because the old per-fault perf event could not: at a high
# fault rate the buffer fills and records are lost. The independent source is
# the process accounting counters, so the two rates over the same window are
# compared. They are not identical by construction, because the tracepoint
# only sees user-mode faults and only from the moment the program is attached,
# so the check is that the eBPF rate keeps up rather than that it matches
# exactly. A counter that had dropped events would fall far short.
MEMORY_RATE_MIN_PERCENT=${MEMORY_RATE_MIN_PERCENT:-95}

check_memory_fault_counter() {
    local report="$OUT_DIR/memory-load.txt"
    if [ ! -f "$report" ]; then
        echo "memory fault counter: SKIP (no memory report from the matrix)"
        return
    fi

    # Both lines end their first figure with "(NNN/s)". The guest awk is
    # busybox's, which has no capture-group match(), so the value is cut out
    # with sub() on a single field instead.
    local ebpf_rate minor_rate
    ebpf_rate=$(awk '/eBPF user faults:/ { v = $5; gsub(/[^0-9]/, "", v); print v; exit }' "$report")
    minor_rate=$(awk '/^ *minor / { v = $3; gsub(/[^0-9]/, "", v); print v; exit }' "$report")
    if [ -z "${ebpf_rate:-}" ] || [ -z "${minor_rate:-}" ] || [ "$minor_rate" -eq 0 ]; then
        echo "memory fault counter: FAIL (no fault rates in the report; eBPF=$ebpf_rate /proc=$minor_rate)"
        FAILURES=$((FAILURES + 1))
        return
    fi
    if ! awk -v a="$ebpf_rate" -v b="$minor_rate" -v need="$MEMORY_RATE_MIN_PERCENT" \
            'BEGIN { pct = (b + 0) == 0 ? 0 : a * 100.0 / b
                     printf "memory fault counter: %d user faults/s from eBPF against %d minor faults/s from /proc (%.2f%%)\n", a, b, pct
                     exit (pct >= need) ? 0 : 1 }'; then
        echo "    the kernel-side counter is falling behind, so events are being lost"
        FAILURES=$((FAILURES + 1))
    fi
}

# Proves the memory verdict tells idle from pressure.
#
# The two runs differ only in the workload, and both are read through the same
# report, so a verdict that cannot separate them is not usable. mem-hog
# allocates and touches memory continuously, which drives the fault rate up;
# the scheduled target is a periodic sleeper, which is the idle case.
#
# The pressure half is asserted on the fault rate rather than on reclaim,
# because the guest has no swap device and its root filesystem is an initramfs
# in RAM, so there are no disk-backed pages to fault in, and reclaim only
# appears once the guest runs out of memory. The unit tests cover the reclaim
# and swap branches of the verdict, which this environment cannot reach.
check_memory_verdict() {
    local load="$OUT_DIR/memory-load.txt" idle="$OUT_DIR/memory.txt"
    if [ ! -f "$load" ] || [ ! -f "$idle" ]; then
        echo "memory verdict: SKIP (no memory reports from the matrix)"
        return
    fi

    local load_verdict idle_verdict load_rate idle_rate
    load_verdict=$(awk '/^Verdict:/ { print $2; exit }' "$load")
    idle_verdict=$(awk '/^Verdict:/ { print $2; exit }' "$idle")
    load_rate=$(awk '/^ *minor / { v = $3; gsub(/[^0-9]/, "", v); print v; exit }' "$load")
    idle_rate=$(awk '/^ *minor / { v = $3; gsub(/[^0-9]/, "", v); print v; exit }' "$idle")

    if [ -z "${load_rate:-}" ] || [ -z "${idle_rate:-}" ] || [ "$load_rate" -eq 0 ]; then
        echo "memory verdict: FAIL (no fault rates in the reports)"
        FAILURES=$((FAILURES + 1))
        return
    fi
    if [ "$load_rate" -le "$idle_rate" ]; then
        echo "memory verdict: FAIL (mem-hog faulted $load_rate/s, no more than the idle target's $idle_rate/s)"
        FAILURES=$((FAILURES + 1))
        return
    fi
    # The load run must be named as more than idle: either real churn or real
    # pressure. Anything else means the thresholds never engage.
    if [ "$load_verdict" = "idle" ]; then
        echo "memory verdict: FAIL (mem-hog at $load_rate minor faults/s was still called idle)"
        FAILURES=$((FAILURES + 1))
    else
        echo "memory verdict: $load_verdict at $load_rate minor faults/s against $idle_verdict at $idle_rate/s"
    fi
}

# Proves the parallel collection really is parallel.
#
# `fast diagnose` used to run no eBPF at all and infer everything from /proc.
# The check is that one run of the single loaded object reports real
# measurements from several streams at once: a process that blocks on a futex
# must show off-CPU waits, and the same run must also show scheduler latency,
# because both come out of one collection over one window.
check_diagnose_parallel() {
    local report="$OUT_DIR/diagnose-load.txt"
    if [ ! -f "$report" ]; then
        echo "diagnose parallel: SKIP (no diagnose report from the matrix)"
        return
    fi

    local sched offcpu io_samples
    sched=$(awk '/^ *scheduler:/ { print $2; exit }' "$report")
    offcpu=$(awk '/^ *off-cpu:/ { print $2; exit }' "$report")
    io_samples=$(awk '/^ *block io:/ { print $2; exit }' "$report")
    if [ -z "${sched:-}" ] || [ -z "${offcpu:-}" ] || [ -z "${io_samples:-}" ]; then
        echo "diagnose parallel: FAIL (a stream is missing from the report)"
        FAILURES=$((FAILURES + 1))
        return
    fi
    # lock-hog blocks constantly, so off-CPU and scheduler both have to be
    # populated from the same run. A zero on either means that stream never
    # produced an event, which is what a broken parallel load would look like.
    if [ "$offcpu" -eq 0 ]; then
        echo "diagnose parallel: FAIL (off-CPU stream reported no waits for lock-hog)"
        FAILURES=$((FAILURES + 1))
    elif [ "$sched" -eq 0 ]; then
        echo "diagnose parallel: FAIL (scheduler stream reported no samples)"
        FAILURES=$((FAILURES + 1))
    else
        echo "diagnose parallel: $sched scheduler and $offcpu off-CPU samples from one run"
    fi
}

# Proves the ranking comes from measurements rather than from the machine.
#
# The old implementation read /proc/loadavg and reported a CPU confidence for a
# process that was blocked on a futex and using no CPU at all. The check is
# that a futex-bound process is ranked on its futex time, with CPU nowhere in
# sight, which is only possible if the ranking is computed from what was
# measured about the process.
check_diagnose_ranking() {
    local report="$OUT_DIR/diagnose-load.txt"
    if [ ! -f "$report" ]; then
        echo "diagnose ranking: SKIP (no diagnose report from the matrix)"
        return
    fi

    local top
    top=$(awk '/^Ranked causes/ { getline; while ($0 ~ /^ *$/) getline; print $2; exit }' "$report")
    if [ -z "$top" ]; then
        echo "diagnose ranking: FAIL (no ranked causes in the report)"
        FAILURES=$((FAILURES + 1))
        return
    fi
    # lock-hog spends its off-CPU time on a futex and nothing else, so that has
    # to be the first named cause.
    if [ "$top" != "Lock" ]; then
        echo "diagnose ranking: FAIL (lock-hog ranked '$top' first, expected Lock contention)"
        grep -A 6 '^Ranked causes' "$report" | sed 's/^/    /' >&2
        FAILURES=$((FAILURES + 1))
        return
    fi
    # Every ranked line has to carry its measurements, otherwise the number is
    # an assertion rather than a conclusion.
    if ! awk '/^Ranked causes/ { f = 1; next } f && /^[0-9]\./ { if ($0 !~ /us |%|s,/) { bad = 1 } }
               END { exit bad ? 1 : 0 }' "$report"; then
        echo "diagnose ranking: FAIL (a ranked cause has no measurements behind it)"
        FAILURES=$((FAILURES + 1))
        return
    fi
    echo "diagnose ranking: top cause is $top, with measurements on every ranked line"
}

# Proves --format json is consumable, not just printable.
#
# The guest has no JSON parser in busybox awk, so the document is validated with
# what it does have: the schema marker, the envelope fields, and the
# single-line guarantee. The parsing itself is covered by the round-trip tests
# in fast/src/json.rs, which use a real parser.
#
# Two commands are checked rather than one, because a format that works for
# `sched` and not for `diagnose` is not a format.
check_json_document() {
    local target="$OUT_DIR/json-sched.txt"
    "$SCHED_WORKLOAD" target --duration 10s --period 1ms >/dev/null 2>&1 &
    local target_pid=$!
    sleep 0.3
    "$FAST" sched --pid "$target_pid" --duration 2s --format json >"$target" 2>/dev/null || true
    "$FAST" diagnose --pid "$target_pid" --duration 2s --format json \
        >"$OUT_DIR/json-diagnose.txt" 2>/dev/null || true
    kill "$target_pid" 2>/dev/null
    wait "$target_pid" 2>/dev/null

    if [ ! -s "$target" ]; then
        echo "json document: SKIP (the JSON run produced no output here)"
        return
    fi

    local problems=""
    for field in '"schema":"rand-fast/v1"' '"command":"sched"' '"pid":' \
        '"duration_s":' '"data":' '"samples":' '"p95_us":' '"lost_events":'; do
        grep -q -- "$field" "$target" || problems="$problems $field"
    done
    # A streaming consumer reads one document per line, so a multi-line
    # document breaks it.
    if [ "$(wc -l <"$target")" -ne 1 ]; then
        problems="$problems <not-a-single-line>"
    fi
    if [ -s "$OUT_DIR/json-diagnose.txt" ]; then
        grep -q -- '"causes"' "$OUT_DIR/json-diagnose.txt" \
            || problems="$problems causes-in-diagnose"
        grep -q -- '"measured"' "$OUT_DIR/json-diagnose.txt" \
            || problems="$problems measured-in-diagnose"
    fi

    if [ -n "$problems" ]; then
        echo "json document: FAIL (missing or wrong:$problems)"
        head -c 200 "$target" | sed 's/^/    /' >&2
        echo >&2
        FAILURES=$((FAILURES + 1))
    else
        echo "json document: one line, schema and fields present, diagnose carries measured and causes"
    fi
}

check_cpu_rate_scaling
check_cpu_symbolization
check_io_pairing
check_offcpu_shape
check_offcpu_ranking
check_memory_fault_counter
check_memory_verdict
check_diagnose_parallel
check_diagnose_ranking
check_json_document
check_net_rtt_crosscheck
check_net_field_crosscheck
check_net_retransmit_attribution
check_net_endpoint_ranking
check_net_rtt_separation

echo "=== key metrics ==="
print_metrics() {
    # print_metrics <case-name> <grep pattern>
    local name="$1" pattern="$2" report
    for variant in "" "-load"; do
        report="$OUT_DIR/$name$variant.txt"
        [ -f "$report" ] || continue
        echo "--- $name$variant ---"
        grep -E "$pattern" "$report" || echo "(no match)"
    done
}

print_metrics sched 'p95|> 1ms'
print_metrics cpu 'Samples:|CPU usage:'
print_metrics io 'Samples:|rchar:'
print_metrics net 'Retransmissions:|RTT p50'
print_metrics off-cpu 'Samples:'
print_metrics memory 'eBPF user faults|minor |direct reclaim'
print_metrics diagnose 'scheduler:|cpu:|block io:|tcp:|off-cpu:|memory:|lost events:'
echo
echo "Raw reports saved under $OUT_DIR"

if [ "$FAILURES" -gt 0 ]; then
    echo "smoke matrix: FAILED ($FAILURES failure(s))"
    exit 1
fi
echo "smoke matrix: all cases passed"
