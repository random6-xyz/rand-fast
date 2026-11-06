#![cfg_attr(target_arch = "bpf", no_std)]
#![cfg_attr(target_arch = "bpf", no_main)]

#[cfg(target_arch = "bpf")]
use core::panic::PanicInfo;

use aya_ebpf::{
    EbpfContext,
    bindings::{BPF_ANY, BPF_F_REUSE_STACKID, BPF_NOEXIST},
    helpers::{
        bpf_get_current_pid_tgid, bpf_get_smp_processor_id, bpf_get_stackid, bpf_ktime_get_ns,
        bpf_probe_read_kernel,
    },
    macros::{map, perf_event, raw_tracepoint, tracepoint},
    maps::{Array, HashMap, LruHashMap, PerCpuArray, PerfEventArray, StackTrace},
    programs::{PerfEventContext, RawTracePointContext, TracePointContext},
};
use fast_common::{
    AF_INET, AF_INET6, COLLECT_CPU_SAMPLE, COLLECT_MEMORY, COLLECT_NET, COLLECT_OFFCPU,
    COLLECT_SCHEDULER_LATENCY, ConnEvent, CpuSampleEvent, IO_OP_UNMATCHED, IoEvent, IoRequestId,
    IoRequestLayout, ListenKey, ListenOwner, MAX_MEMORY_THREADS, MAX_PENDING_IO, MAX_STACKS,
    MAX_TARGET_TIDS, MAX_TCP_LISTENERS, MAX_TCP_OWNERS, MAX_TCP_PENDING_CONNECTS, MemoryCounters,
    OFFCPU_REASON_IO, OFFCPU_REASON_UNKNOWN, OFFCPU_REASON_WAIT, OffCpuEvent, OffCpuPending,
    PendingIo, PendingWakeup, SchedulerLatencyEvent, TCP_AWAITING_CONNECT, TCP_CONNECT_ESTABLISHED,
    TCP_CONNECT_FAILED, TCP_LISTENER_AMBIGUOUS, TCP_ORIGIN_CREATED, TCP_ORIGIN_SEEDED,
    TCP_ROLE_CLIENT, TCP_ROLE_SERVER, TCP_RTT_SAMPLE_INTERVAL_NS, TCP_STAT_AMBIGUOUS_LISTENER,
    TCP_STAT_COUNT, TCP_STAT_MATCHED_RETRANS, TCP_STAT_MATCHED_RTT, TCP_STAT_OWNER_DROPS,
    TCP_STAT_OWNER_INSERTED, TCP_STAT_OWNER_REMOVED, TCP_STAT_PENDING_ESTABLISHED,
    TCP_STAT_PENDING_FAILED, TCP_STAT_PENDING_INSERTED, TCP_STAT_RATE_LIMITED,
    TCP_STAT_UNMATCHED_RETRANS, TCP_STAT_UNMATCHED_RTT, TcpEvent, TcpKey, TcpOwner,
    TcpPendingConnect, io_op_from_request_flags, scheduler_state_is_exiting,
};

// Payload offsets for the supported scheduler tracepoint layouts. The user-space
// runtime validates the active tracefs formats against these expected fields
// before attaching a program, and rejects a mismatch instead of misreading data.
const SCHED_WAKEUP_PID_OFFSET: usize = 24;
const SCHED_SWITCH_PREV_PID_OFFSET: usize = 24;
const SCHED_SWITCH_PREV_STATE_OFFSET: usize = 32;
const SCHED_SWITCH_NEXT_PID_OFFSET: usize = 56;

// Payload offsets of the memory tracepoints, verified against the format
// files that tools/qemu-guest-init.sh dumps on the target kernel
// (7.2.0-rc6):
//   page_fault_user:                address=8 ip=16 error_code=24
//   mm_vmscan_direct_reclaim_begin: gfp_flags=8 memcg_id=16 order=24
//
// Neither payload is read. A fault's address says nothing about whether it
// was minor or major, and the reclaim order says nothing a user acts on, so
// the programs only need the fact that the event happened. The offsets are
// recorded here so the layout stays documented if a future report needs one.

#[cfg(not(target_arch = "bpf"))]
fn main() {}

#[map]
static TARGET_TIDS: HashMap<u32, u8> = HashMap::with_max_entries(MAX_TARGET_TIDS, 0);

/// Collector selector written by the userspace command before collection
/// starts; tracepoint programs skip the paths their command does not consume.
#[map]
static MODE: HashMap<u32, u32> = HashMap::with_max_entries(1, 0);

#[map]
static PENDING_WAKEUPS: LruHashMap<u32, PendingWakeup> =
    LruHashMap::with_max_entries(MAX_TARGET_TIDS, 0);

#[map]
static EVENTS: PerfEventArray<SchedulerLatencyEvent> = PerfEventArray::new(0);

#[map]
static CPU_EVENTS: PerfEventArray<CpuSampleEvent> = PerfEventArray::new(0);

#[map]
static STACK_TRACES: StackTrace = StackTrace::with_max_entries(MAX_STACKS, 0);

/// User-space stacks live in their own map: `bpf_get_stackid` chains entries
/// with equal ids (the id is a hash index, not a unique key), so sharing one
/// map between kernel and user captures would make lookups return whichever
/// stack was captured last for that id.
#[map]
static STACK_TRACES_USER: StackTrace = StackTrace::with_max_entries(MAX_STACKS, 0);

#[map]
static IO_EVENTS: PerfEventArray<IoEvent> = PerfEventArray::new(0);

#[map]
static IO_REQUEST_LAYOUT: HashMap<u32, IoRequestLayout> = HashMap::with_max_entries(1, 0);

#[map]
static PENDING_IO: HashMap<IoRequestId, PendingIo> = HashMap::with_max_entries(MAX_PENDING_IO, 0);

#[map]
static NET_EVENTS: PerfEventArray<TcpEvent> = PerfEventArray::new(0);

/// Connection-establishment latency events, one per client handshake the
/// target started. Kept in its own perf array so the RTT stream keeps its
/// fixed event size and the per-connection rate limit applies only to RTT.
#[map]
static CONN_EVENTS: PerfEventArray<ConnEvent> = PerfEventArray::new(0);

/// Thread group observed by the current run. TCP ownership is recorded only
/// when the current thread group matches, so a socket created by another
/// process is never written into the ownership map.
#[map]
static TARGET_TGID: Array<u32> = Array::with_max_entries(1, 0);

/// Verified socket owners, keyed by connection 5-tuple.
///
/// The key is never a kernel pointer: pointers are reused across socket
/// lifetimes, and a remembered pointer is not evidence of ownership. A tuple
/// identifies one live connection and is invalidated when the socket closes.
#[map]
static TCP_OWNERS: HashMap<TcpKey, TcpOwner> = HashMap::with_max_entries(MAX_TCP_OWNERS, 0);

/// Listening sockets the target owns, keyed by the address they listen on.
#[map]
static TCP_LISTENERS: HashMap<ListenKey, ListenOwner> =
    HashMap::with_max_entries(MAX_TCP_LISTENERS, 0);

/// Client handshakes in flight, keyed by socket address.
///
/// The entry pairs the target's `TCP_SYN_SENT` with the same socket's
/// `TCP_ESTABLISHED` so the handshake duration can be measured; it is bound to
/// the socket lifetime by the `TCP_CLOSE` removal and bounded by LRU.
#[map]
static TCP_PENDING_CONNECTS: LruHashMap<u64, TcpPendingConnect> =
    LruHashMap::with_max_entries(MAX_TCP_PENDING_CONNECTS, 0);

/// Per-CPU counters describing how attribution went. Userspace sums them, so
/// a run reports unattributed events and dropped records instead of silently
/// showing fewer measurements.
#[map]
static TCP_OWNER_STATS: PerCpuArray<u64> = PerCpuArray::with_max_entries(TCP_STAT_COUNT, 0);

#[map]
static OFFCPU_EVENTS: PerfEventArray<OffCpuEvent> = PerfEventArray::new(0);

/// Pending off-CPU waits, keyed by TID.
///
/// The value carries the blocking stack and the wait reason alongside the
/// timestamp, because all three have to be read at switch-out: by the time
/// the thread is woken, the frame that blocked it is gone.
#[map]
static OFFCPU_START: LruHashMap<u32, OffCpuPending> =
    LruHashMap::with_max_entries(MAX_TARGET_TIDS, 0);

/// TIDs whose exit hook ran but final sched_switch has not been observed yet.
#[map]
static EXITING_TIDS: LruHashMap<u32, u8> = LruHashMap::with_max_entries(MAX_TARGET_TIDS, 0);

#[map]
static MEMORY_COUNTERS: LruHashMap<u32, MemoryCounters> =
    LruHashMap::with_max_entries(MAX_MEMORY_THREADS, 0);

#[tracepoint(name = "sched_wakeup", category = "sched")]
pub fn sched_wakeup(ctx: TracePointContext) -> u32 {
    match try_sched_wakeup(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_sched_wakeup(ctx: TracePointContext) -> Result<u32, u32> {
    let tid = unsafe { ctx.read_at::<u32>(SCHED_WAKEUP_PID_OFFSET) }.map_err(|_| 0u32)?;

    if unsafe { TARGET_TIDS.get(tid) }.is_none() {
        return Ok(0);
    }
    if unsafe { EXITING_TIDS.get(tid) }.is_some() {
        let _ = EXITING_TIDS.remove(tid);
    }

    let mode = unsafe { MODE.get(0) }.copied().unwrap_or(0);

    // A runnable task should retain the timestamp of its first observed wakeup.
    // BPF_NOEXIST also avoids replacing it if multiple wakeup notifications race.
    if mode & COLLECT_SCHEDULER_LATENCY != 0 && unsafe { PENDING_WAKEUPS.get(tid) }.is_none() {
        let pending = PendingWakeup {
            wake_ns: unsafe { bpf_ktime_get_ns() },
            wake_cpu: unsafe { bpf_get_smp_processor_id() },
            reserved: 0,
        };
        let _ = PENDING_WAKEUPS.insert(tid, pending, BPF_NOEXIST as u64);
    }

    // Off-CPU: the task was switched out in a sleepable state and just became
    // runnable again, so the pending switch-out record measures its wait.
    if mode & COLLECT_OFFCPU != 0
        && let Some(pending) = unsafe { OFFCPU_START.get(tid) }
    {
        // Copy the record before removing the entry; the LRU entry memory is
        // freed by remove and must not be read afterwards.
        let pending = *pending;
        let _ = OFFCPU_START.remove(tid);
        let now = unsafe { bpf_ktime_get_ns() };
        if now >= pending.start_ns {
            let event = OffCpuEvent {
                wait_ns: now - pending.start_ns,
                stack_id: pending.stack_id,
                tid,
                reason: pending.reason,
                _pad: 0,
                _pad2: 0,
            };
            OFFCPU_EVENTS.output(&ctx, event, BPF_ANY);
        }
    }

    Ok(0)
}

/// Classifies a wait from the task state the scheduler recorded.
///
/// `sched_switch` reports `prev_state` as a bitmask, and the two bits that
/// matter are TASK_INTERRUPTIBLE (1) and TASK_UNINTERRUPTIBLE (2). Sleeping
/// in an interruptible wait is what futexes, condition variables and timed
/// sleeps use; an uninterruptible wait is what disk and network I/O use for
/// the duration of a request.
///
/// This is deliberately coarse. It separates "waiting on a lock or a timer"
/// from "waiting on a device", which is the split a user acts on, and the
/// finer classification comes from symbolizing the captured stack. A state
/// with neither bit set is reported as unknown rather than guessed at.
fn offcpu_reason_from_state(prev_state: u64) -> u32 {
    const TASK_INTERRUPTIBLE: u64 = 1;
    const TASK_UNINTERRUPTIBLE: u64 = 2;
    if prev_state & TASK_UNINTERRUPTIBLE != 0 {
        OFFCPU_REASON_IO
    } else if prev_state & TASK_INTERRUPTIBLE != 0 {
        OFFCPU_REASON_WAIT
    } else {
        OFFCPU_REASON_UNKNOWN
    }
}

#[tracepoint(name = "sched_switch", category = "sched")]
pub fn sched_switch(ctx: TracePointContext) -> u32 {
    match try_sched_switch(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_sched_switch(ctx: TracePointContext) -> Result<u32, u32> {
    let tid = unsafe { ctx.read_at::<u32>(SCHED_SWITCH_NEXT_PID_OFFSET) }.map_err(|_| 0u32)?;
    let mode = unsafe { MODE.get(0) }.copied().unwrap_or(0);

    // Off-CPU: a target task that switched out in a non-runnable state starts
    // waiting. The stack and the reason are captured here rather than at
    // wakeup, because the frame that blocked the thread is only on the stack
    // at this point.
    //
    // prev_state is 0 when the task was merely preempted, which is not a wait
    // and must not be recorded: preemption is what the scheduler collector
    // measures.
    if mode & COLLECT_OFFCPU != 0
        && let Ok(prev_pid) = unsafe { ctx.read_at::<u32>(SCHED_SWITCH_PREV_PID_OFFSET) }
        && unsafe { TARGET_TIDS.get(prev_pid) }.is_some()
        && let Ok(prev_state) = unsafe { ctx.read_at::<u64>(SCHED_SWITCH_PREV_STATE_OFFSET) }
    {
        if unsafe { EXITING_TIDS.get(prev_pid) }.is_some() || scheduler_state_is_exiting(prev_state)
        {
            // sched_switch reports EXIT_DEAD/EXIT_ZOMBIE for an exiting task.
            // It is not a wait, and the marker also covers kernel state encoding.
            let _ = OFFCPU_START.remove(prev_pid);
            let _ = EXITING_TIDS.remove(prev_pid);
        } else if prev_state != 0 {
            let stack = unsafe {
                bpf_get_stackid(
                    ctx.as_ptr(),
                    &STACK_TRACES as *const _ as *mut core::ffi::c_void,
                    // BPF_F_REUSE_STACKID lets a recurring blocking path share one
                    // entry. Without it every distinct stack takes a slot, and a
                    // thread that blocks in a tight loop evicts everything else.
                    BPF_F_REUSE_STACKID as u64,
                )
            };
            let pending = OffCpuPending {
                start_ns: unsafe { bpf_ktime_get_ns() },
                stack_id: stack as i64,
                reason: offcpu_reason_from_state(prev_state),
                _pad: 0,
            };
            let _ = OFFCPU_START.insert(prev_pid, pending, BPF_ANY as u64);
        }
    }

    if unsafe { TARGET_TIDS.get(tid) }.is_none() {
        return Ok(0);
    }

    if mode & COLLECT_SCHEDULER_LATENCY != 0 {
        let pending = match unsafe { PENDING_WAKEUPS.get(tid) } {
            Some(pending) => *pending,
            None => return Ok(0),
        };
        let _ = PENDING_WAKEUPS.remove(tid);

        let run_ns = unsafe { bpf_ktime_get_ns() };
        if run_ns < pending.wake_ns {
            return Ok(0);
        }

        let run_cpu = unsafe { bpf_get_smp_processor_id() };
        let event = SchedulerLatencyEvent {
            latency_ns: run_ns - pending.wake_ns,
            wake_ns: pending.wake_ns,
            run_ns,
            tid,
            wake_cpu: pending.wake_cpu,
            run_cpu,
            reserved: 0,
        };
        EVENTS.output(&ctx, event, BPF_ANY);
    }

    Ok(0)
}

#[tracepoint(name = "sched_process_exit", category = "sched")]
pub fn sched_process_exit(ctx: TracePointContext) -> u32 {
    match try_sched_process_exit(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_sched_process_exit(_ctx: TracePointContext) -> Result<u32, u32> {
    let tid = bpf_get_current_pid_tgid() as u32;
    let mode = unsafe { MODE.get(0) }.copied().unwrap_or(0);
    if mode & (COLLECT_SCHEDULER_LATENCY | COLLECT_OFFCPU) == 0 {
        return Ok(0);
    }
    if unsafe { TARGET_TIDS.get(tid) }.is_some() {
        let _ = EXITING_TIDS.insert(tid, 1, BPF_ANY as u64);
    }
    // Pending maps only contain target threads, but the userspace polling loop
    // can remove TARGET_TIDS immediately before this tracepoint runs. Delete by
    // TID regardless so that race cannot preserve state for a reused ID.
    if mode & COLLECT_SCHEDULER_LATENCY != 0 {
        let _ = PENDING_WAKEUPS.remove(tid);
    }
    if mode & COLLECT_OFFCPU != 0 {
        let _ = OFFCPU_START.remove(tid);
    }
    Ok(0)
}

// --- CPU: on-CPU sampling via perf cpu-clock events ---
/// Samples the stack of whichever target thread is running when the perf
/// event fires. `fast cpu` attaches this program per CPU with a fixed
/// frequency, so the sample count scales with sampling rate times CPU time —
/// unlike the old switch-in capture, which scaled with wakeup count and
/// never saw a busy thread that sleeps between wakeups.
#[perf_event]
pub fn cpu_sample(ctx: PerfEventContext) -> u32 {
    match try_cpu_sample(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_cpu_sample(ctx: PerfEventContext) -> Result<u32, u32> {
    if unsafe { MODE.get(0) }.copied().unwrap_or(0) & COLLECT_CPU_SAMPLE == 0 {
        return Ok(0);
    }

    // The event fires in the context of the interrupted task, so the current
    // TID identifies the thread that was on CPU. The idle task (TID 0) and
    // all non-target threads are filtered out here.
    let tid = bpf_get_current_pid_tgid() as u32;
    if unsafe { TARGET_TIDS.get(tid) }.is_none() {
        return Ok(0);
    }

    let cpu = unsafe { bpf_get_smp_processor_id() };
    let kstack = unsafe {
        bpf_get_stackid(
            ctx.as_ptr(),
            &STACK_TRACES as *const _ as *mut core::ffi::c_void,
            0,
        )
    };
    // BPF_F_USER_STACK (256) selects the user-space stack of the interrupted
    // task; BPF_F_REUSE_STACKID lets different samples share one entry.
    let ustack = unsafe {
        bpf_get_stackid(
            ctx.as_ptr(),
            &STACK_TRACES_USER as *const _ as *mut core::ffi::c_void,
            256 | BPF_F_REUSE_STACKID as u64,
        )
    };
    let cpu_sample = CpuSampleEvent {
        tid,
        cpu,
        kernel_stack_id: kstack as i64,
        user_stack_id: ustack as i64,
        _pad: 0,
        _pad2: 0,
    };
    CPU_EVENTS.output(&ctx, cpu_sample, BPF_ANY);
    Ok(0)
}

// --- I/O: correlate block requests by their unique struct request pointer ---
#[raw_tracepoint(tracepoint = "block_rq_issue")]
pub fn block_rq_issue(ctx: RawTracePointContext) -> u32 {
    match try_block_rq_issue(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_block_rq_issue(ctx: RawTracePointContext) -> Result<u32, u32> {
    let tid = bpf_get_current_pid_tgid() as u32;
    if unsafe { TARGET_TIDS.get(tid) }.is_none() {
        return Ok(0);
    }

    let request = ctx.arg::<*const u8>(0);
    if request.is_null() {
        emit_unmatched(&ctx, tid, 0);
        return Ok(0);
    }
    let layout = match unsafe { IO_REQUEST_LAYOUT.get(0) } {
        Some(layout) => *layout,
        None => {
            emit_unmatched(&ctx, tid, 0);
            return Ok(0);
        }
    };
    let (dev, _, _, op) = match request_fields(request, layout) {
        Ok(fields) => fields,
        Err(_) => {
            emit_unmatched(&ctx, tid, 0);
            return Ok(0);
        }
    };

    // Raw tracepoint arguments expose the actual request pointer. Different
    // requests may share a device and start sector, but a live request object
    // has a unique address until block_rq_complete releases it.
    let request_id = IoRequestId::from_address(request as u64);
    let pending = PendingIo {
        start_ns: unsafe { bpf_ktime_get_ns() },
        tid,
        op,
    };
    if PENDING_IO
        .insert(request_id, pending, BPF_NOEXIST as u64)
        .is_err()
        // A repeated issue for the same request is a requeue; retain its first
        // timestamp. If the key is absent, the bounded map is full and this
        // sample must be reported as unmatched rather than silently evicted.
        && unsafe { PENDING_IO.get(request_id) }.is_none()
    {
        emit_unmatched(&ctx, tid, dev);
    }
    Ok(0)
}

#[raw_tracepoint(tracepoint = "block_rq_complete")]
pub fn block_rq_complete(ctx: RawTracePointContext) -> u32 {
    match try_block_rq_complete(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_block_rq_complete(ctx: RawTracePointContext) -> Result<u32, u32> {
    let request = ctx.arg::<*const u8>(0);
    if request.is_null() {
        return Ok(0);
    }
    let request_id = IoRequestId::from_address(request as u64);
    let pending = match unsafe { PENDING_IO.get(request_id) } {
        Some(pending) => *pending,
        None => return Ok(0),
    };
    let _ = PENDING_IO.remove(request_id);

    let layout = match unsafe { IO_REQUEST_LAYOUT.get(0) } {
        Some(layout) => *layout,
        None => {
            emit_unmatched(&ctx, pending.tid, 0);
            return Ok(0);
        }
    };
    let (dev, sectors, _, _) = match request_fields(request, layout) {
        Ok(fields) => fields,
        Err(_) => {
            emit_unmatched(&ctx, pending.tid, 0);
            return Ok(0);
        }
    };

    let end = unsafe { bpf_ktime_get_ns() };
    if end < pending.start_ns {
        emit_unmatched(&ctx, pending.tid, dev);
        return Ok(0);
    }
    let event = IoEvent {
        latency_ns: end - pending.start_ns,
        tid: pending.tid,
        dev,
        sectors,
        op: pending.op,
    };
    IO_EVENTS.output(&ctx, event, BPF_ANY);
    Ok(0)
}

fn request_fields(
    request: *const u8,
    layout: IoRequestLayout,
) -> Result<(u32, u32, u64, u32), u32> {
    let queue = unsafe { read_request_field::<*const u8>(request, layout.request_q) }?;
    let disk = unsafe { read_request_field::<*const u8>(queue, layout.queue_disk) }?;
    let major = unsafe { read_request_field::<u32>(disk, layout.gendisk_major) }?;
    let first_minor = unsafe { read_request_field::<u32>(disk, layout.gendisk_first_minor) }?;
    let sector = unsafe { read_request_field::<u64>(request, layout.request_sector) }?;
    let bytes = unsafe { read_request_field::<u32>(request, layout.request_data_len) }?;
    let flags = unsafe { read_request_field::<u32>(request, layout.request_cmd_flags) }?;
    let dev = (major << 20) | (first_minor & 0x000f_ffff);
    let sectors = bytes >> 9;
    let op = io_op_from_request_flags(flags);
    Ok((dev, sectors, sector, op))
}

unsafe fn read_request_field<T: Copy>(base: *const u8, offset: u32) -> Result<T, u32> {
    if base.is_null() {
        return Err(0);
    }
    let address = base.wrapping_add(offset as usize).cast::<T>();
    unsafe { bpf_probe_read_kernel(address) }.map_err(|_| 0u32)
}

fn emit_unmatched(ctx: &impl EbpfContext, tid: u32, dev: u32) {
    IO_EVENTS.output(
        ctx,
        IoEvent {
            latency_ns: 0,
            tid,
            dev,
            sectors: 0,
            op: IO_OP_UNMATCHED,
        },
        BPF_ANY,
    );
}

// --- Network: socket ownership, TCP RTT and retransmissions ---
//
// Attribution rules, in one place:
//
//   * A connection belongs to the target when the target's own thread group
//     created it (TCP_SYN_SENT for a client, or a listener the target owns for
//     an accepted socket) or when the target holds its descriptor
//     (`/proc/<pid>/fd`, filled in by userspace).
//   * The ownership key is the connection 5-tuple, never a kernel pointer.
//     Two live sockets cannot share a tuple, and `TCP_CLOSE` invalidates the
//     record, so a reused address cannot inherit an old owner.
//   * Tracepoint payloads already carry the tuple, so no `struct sock` field
//     is read and no BTF offset is guessed.
//
// Payload offsets of `sock:inet_sock_set_state`, verified against the format
// files captured from the pinned kernels:
//   skaddr=8 oldstate=16 newstate=20 sport=24 dport=26 family=28 protocol=30
//   saddr=32(4) daddr=36(4) saddr_v6=40(16) daddr_v6=56(16)
const STATE_SKADDR_OFFSET: usize = 8;
const STATE_OLD_OFFSET: usize = 16;
const STATE_NEW_OFFSET: usize = 20;
const STATE_SPORT_OFFSET: usize = 24;
const STATE_DPORT_OFFSET: usize = 26;
const STATE_FAMILY_OFFSET: usize = 28;
const STATE_SADDR_OFFSET: usize = 32;
const STATE_DADDR_OFFSET: usize = 36;
const STATE_SADDR_V6_OFFSET: usize = 40;
const STATE_DADDR_V6_OFFSET: usize = 56;

/// `include/net/tcp_states.h` values, which the kernel freezes in the
/// tracepoint ABI (`BPF_TCP_*`).
const TCP_STATE_ESTABLISHED: i32 = 1;
const TCP_STATE_SYN_SENT: i32 = 2;
const TCP_STATE_CLOSE: i32 = 7;
const TCP_STATE_LISTEN: i32 = 10;

// Payload offsets of the TCP measurement tracepoints.
//   tcp_probe:          saddr=8(28) daddr=36(28) sport=64 dport=66 family=68
//                       snd_cwnd=88 srtt=100 rcv_wnd=104 skaddr=128
//   tcp_retransmit_skb: skbaddr=8 skaddr=16 state=24 sport=28 dport=30
//                       family=32 saddr=34(4) daddr=38(4) saddr_v6=42(16)
//                       daddr_v6=58(16)
const PROBE_SADDR_OFFSET: usize = 8;
const PROBE_DADDR_OFFSET: usize = 36;
const PROBE_SPORT_OFFSET: usize = 64;
const PROBE_DPORT_OFFSET: usize = 66;
const PROBE_FAMILY_OFFSET: usize = 68;
const PROBE_SND_CWND_OFFSET: usize = 88;
const PROBE_SRTT_OFFSET: usize = 100;
const PROBE_RCV_WND_OFFSET: usize = 104;

const RETRANS_SPORT_OFFSET: usize = 28;
const RETRANS_DPORT_OFFSET: usize = 30;
const RETRANS_FAMILY_OFFSET: usize = 32;
const RETRANS_SADDR_OFFSET: usize = 34;
const RETRANS_DADDR_OFFSET: usize = 38;
const RETRANS_SADDR_V6_OFFSET: usize = 42;
const RETRANS_DADDR_V6_OFFSET: usize = 58;

fn net_collection_enabled() -> bool {
    unsafe { MODE.get(0) }.copied().unwrap_or(0) & COLLECT_NET != 0
}

fn target_tgid() -> u32 {
    TARGET_TGID.get(0).copied().unwrap_or(0)
}

fn current_tgid() -> u32 {
    (bpf_get_current_pid_tgid() >> 32) as u32
}

fn bump_stat(index: u32) {
    if let Some(counter) = TCP_OWNER_STATS.get_ptr_mut(index) {
        // Each CPU owns its slot, so no atomic is needed.
        unsafe { *counter += 1 };
    }
}

/// Reads an IPv4 or IPv6 address pair from a payload that carries both.
fn read_address_pair(
    ctx: &TracePointContext,
    family: u16,
    saddr4: usize,
    daddr4: usize,
    saddr6: usize,
    daddr6: usize,
) -> Option<([u8; 16], [u8; 16])> {
    if family == AF_INET6 {
        let s: [u8; 16] = unsafe { ctx.read_at(saddr6) }.ok()?;
        let d: [u8; 16] = unsafe { ctx.read_at(daddr6) }.ok()?;
        return Some((s, d));
    }
    if family != AF_INET {
        return None;
    }
    let s: [u8; 4] = unsafe { ctx.read_at(saddr4) }.ok()?;
    let d: [u8; 4] = unsafe { ctx.read_at(daddr4) }.ok()?;
    let mut wide_s = [0u8; 16];
    let mut wide_d = [0u8; 16];
    wide_s[..4].copy_from_slice(&s);
    wide_d[..4].copy_from_slice(&d);
    Some((wide_s, wide_d))
}

/// Parses the source address blob `tcp_probe` stores.
///
/// The kernel writes a `struct sockaddr` family and port ahead of the address
/// through `TP_STORE_ADDR_PORTS`; the separate `sport`/`dport` fields are the
/// same ports in host byte order and are preferred, so only the address and
/// the family are taken from here.
fn read_probe_address(ctx: &TracePointContext, offset: usize) -> Option<(u16, [u8; 16])> {
    let raw: [u8; 28] = unsafe { ctx.read_at(offset) }.ok()?;
    let family = u16::from_ne_bytes([raw[0], raw[1]]);
    let mut address = [0u8; 16];
    if family == AF_INET {
        address[..4].copy_from_slice(&raw[4..8]);
    } else if family == AF_INET6 {
        address.copy_from_slice(&raw[8..24]);
    } else {
        return None;
    }
    Some((family, address))
}

fn insert_owner(key: &TcpKey, owner: &TcpOwner) {
    match TCP_OWNERS.insert(key, owner, BPF_ANY as u64) {
        Ok(()) => bump_stat(TCP_STAT_OWNER_INSERTED),
        // A full map drops the new record rather than evicting a verified
        // owner: an unattributed connection is honest, a stolen one is not.
        Err(_) => bump_stat(TCP_STAT_OWNER_DROPS),
    }
}

fn emit_conn(ctx: &TracePointContext, key: &TcpKey, start_ns: u64, now_ns: u64, result: u8) {
    let elapsed = now_ns.saturating_sub(start_ns);
    let latency_us = (elapsed / 1_000) as u32;
    let event = ConnEvent {
        family: key.family,
        sport: key.sport,
        dport: key.dport,
        result,
        _pad: 0,
        latency_us,
        saddr: key.saddr,
        daddr: key.daddr,
    };
    CONN_EVENTS.output(ctx, event, BPF_ANY);
}

/// Finds the owner of an accepted connection by the listener it arrived on.
fn listener_owner(key: &TcpKey) -> Option<TcpOwner> {
    let exact = ListenKey {
        family: key.family,
        port: key.dport,
        addr: key.saddr,
    };
    let wildcard = ListenKey {
        family: key.family,
        port: key.dport,
        addr: [0u8; 16],
    };
    for candidate in [&exact, &wildcard] {
        if let Some(listener) = unsafe { TCP_LISTENERS.get(candidate) }.copied() {
            if listener.ambiguous != 0 || listener.tgid == 0 {
                return None;
            }
            return Some(TcpOwner {
                tgid: listener.tgid,
                role: TCP_ROLE_SERVER,
                origin: TCP_ORIGIN_CREATED,
                awaiting: 0,
                _pad: 0,
                // An accepted socket has no observable handshake start: the
                // kernel sets a child's initial TCP_SYN_RECV state directly.
                start_ns: 0,
                last_sample_ns: 0,
                listener_port: key.dport,
                _pad2: [0u8; 6],
            });
        }
    }
    None
}

#[tracepoint(name = "inet_sock_set_state", category = "sock")]
pub fn inet_sock_set_state(ctx: TracePointContext) -> u32 {
    match try_inet_sock_set_state(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_inet_sock_set_state(ctx: TracePointContext) -> Result<u32, u32> {
    if !net_collection_enabled() {
        return Ok(0);
    }
    let target = target_tgid();
    if target == 0 {
        return Ok(0);
    }

    let old_state = unsafe { ctx.read_at::<i32>(STATE_OLD_OFFSET) }.map_err(|_| 1u32)?;
    let new_state = unsafe { ctx.read_at::<i32>(STATE_NEW_OFFSET) }.map_err(|_| 1u32)?;
    let family = unsafe { ctx.read_at::<u16>(STATE_FAMILY_OFFSET) }.map_err(|_| 1u32)?;
    let sport = unsafe { ctx.read_at::<u16>(STATE_SPORT_OFFSET) }.unwrap_or(0);
    let dport = unsafe { ctx.read_at::<u16>(STATE_DPORT_OFFSET) }.unwrap_or(0);
    let (saddr, daddr) = match read_address_pair(
        &ctx,
        family,
        STATE_SADDR_OFFSET,
        STATE_DADDR_OFFSET,
        STATE_SADDR_V6_OFFSET,
        STATE_DADDR_V6_OFFSET,
    ) {
        Some(value) => value,
        None => return Ok(0),
    };
    let key = TcpKey::new(family, saddr, sport, daddr, dport);
    let skaddr = unsafe { ctx.read_at::<u64>(STATE_SKADDR_OFFSET) }.unwrap_or(0);
    let now = unsafe { bpf_ktime_get_ns() };

    match new_state {
        TCP_STATE_CLOSE => {
            if let Some(owner) = unsafe { TCP_OWNERS.get(key) }.copied() {
                if owner.awaiting == TCP_AWAITING_CONNECT {
                    emit_conn(&ctx, &key, owner.start_ns, now, TCP_CONNECT_FAILED);
                }
                let _ = TCP_OWNERS.remove(key);
                bump_stat(TCP_STAT_OWNER_REMOVED);
            }
            if skaddr != 0 {
                // A connect that never established has no owner record; its
                // pending handshake is the only evidence, and closing before
                // `TCP_ESTABLISHED` is what a refused or timed-out connect
                // looks like. The result is reported, not guessed at.
                if let Some(started) = unsafe { TCP_PENDING_CONNECTS.get(skaddr) }.copied()
                    && started.matches(&key)
                {
                    bump_stat(TCP_STAT_PENDING_FAILED);
                    emit_conn(&ctx, &key, started.start_ns, now, TCP_CONNECT_FAILED);
                }
                let _ = TCP_PENDING_CONNECTS.remove(skaddr);
            }
            if old_state == TCP_STATE_LISTEN {
                let listener = ListenKey {
                    family,
                    port: sport,
                    addr: saddr,
                };
                let _ = TCP_LISTENERS.remove(listener);
            }
        }
        TCP_STATE_ESTABLISHED => {
            let pending = if skaddr == 0 {
                None
            } else {
                unsafe { TCP_PENDING_CONNECTS.get(skaddr) }.copied()
            };
            match unsafe { TCP_OWNERS.get(key) }.copied() {
                Some(owner) => {
                    // A record seeded from `/proc` while the handshake was in
                    // flight carries no creation evidence; promote it when the
                    // matching handshake completes so the latency is measured
                    // instead of lost.
                    if owner.origin == TCP_ORIGIN_SEEDED {
                        if let Some(started) = pending.filter(|entry| entry.matches(&key)) {
                            let promoted = TcpOwner {
                                tgid: target,
                                role: TCP_ROLE_CLIENT,
                                origin: TCP_ORIGIN_CREATED,
                                awaiting: 0,
                                _pad: 0,
                                start_ns: started.start_ns,
                                last_sample_ns: owner.last_sample_ns,
                                listener_port: 0,
                                _pad2: [0u8; 6],
                            };
                            insert_owner(&key, &promoted);
                            let _ = TCP_PENDING_CONNECTS.remove(skaddr);
                            bump_stat(TCP_STAT_PENDING_ESTABLISHED);
                            emit_conn(&ctx, &key, started.start_ns, now, TCP_CONNECT_ESTABLISHED);
                        }
                    } else if owner.awaiting == TCP_AWAITING_CONNECT {
                        let mut settled = owner;
                        settled.awaiting = 0;
                        insert_owner(&key, &settled);
                        if skaddr != 0 {
                            let _ = TCP_PENDING_CONNECTS.remove(skaddr);
                        }
                        emit_conn(&ctx, &key, owner.start_ns, now, TCP_CONNECT_ESTABLISHED);
                    }
                }
                None => {
                    if let Some(started) = pending.filter(|entry| entry.matches(&key)) {
                        let owner = TcpOwner {
                            tgid: target,
                            role: TCP_ROLE_CLIENT,
                            origin: TCP_ORIGIN_CREATED,
                            awaiting: 0,
                            _pad: 0,
                            start_ns: started.start_ns,
                            last_sample_ns: 0,
                            listener_port: 0,
                            _pad2: [0u8; 6],
                        };
                        insert_owner(&key, &owner);
                        let _ = TCP_PENDING_CONNECTS.remove(skaddr);
                        bump_stat(TCP_STAT_PENDING_ESTABLISHED);
                        emit_conn(&ctx, &key, started.start_ns, now, TCP_CONNECT_ESTABLISHED);
                    } else if let Some(owner) = listener_owner(&key) {
                        insert_owner(&key, &owner);
                    }
                }
            }
        }
        TCP_STATE_SYN_SENT => {
            // The local port is assigned after this state is set, so the
            // pending entry records the remote endpoint and pairs the two
            // events by socket address. Ownership is the current thread
            // group, which is the target's only when the target called
            // connect.
            if skaddr != 0 && current_tgid() == target {
                let pending = TcpPendingConnect {
                    start_ns: now,
                    family,
                    sport,
                    dport,
                    _pad: 0,
                    daddr,
                };
                let _ = TCP_PENDING_CONNECTS.insert(skaddr, pending, BPF_ANY as u64);
                bump_stat(TCP_STAT_PENDING_INSERTED);
            }
        }
        TCP_STATE_LISTEN => {
            let listener = ListenKey {
                family,
                port: sport,
                addr: saddr,
            };
            if current_tgid() == target {
                match unsafe { TCP_LISTENERS.get(listener) }.copied() {
                    Some(existing) if existing.tgid != target || existing.ambiguous != 0 => {
                        let ambiguous = ListenOwner {
                            tgid: 0,
                            ambiguous: TCP_LISTENER_AMBIGUOUS,
                            _pad: [0u8; 3],
                        };
                        let _ = TCP_LISTENERS.insert(listener, ambiguous, 0);
                        bump_stat(TCP_STAT_AMBIGUOUS_LISTENER);
                    }
                    _ => {
                        let owned = ListenOwner {
                            tgid: target,
                            ambiguous: 0,
                            _pad: [0u8; 3],
                        };
                        let _ = TCP_LISTENERS.insert(listener, owned, 0);
                    }
                }
            } else if let Some(existing) = unsafe { TCP_LISTENERS.get(listener) }.copied() {
                // Two processes listening on one address make every accepted
                // connection on it unattributable, so the key is poisoned
                // instead of keeping whichever owner was seen first.
                if existing.tgid == target {
                    let ambiguous = ListenOwner {
                        tgid: 0,
                        ambiguous: TCP_LISTENER_AMBIGUOUS,
                        _pad: [0u8; 3],
                    };
                    let _ = TCP_LISTENERS.insert(listener, ambiguous, 0);
                    bump_stat(TCP_STAT_AMBIGUOUS_LISTENER);
                }
            }
        }
        _ => {}
    }
    Ok(0)
}

#[tracepoint(name = "tcp_probe", category = "tcp")]
pub fn tcp_probe(ctx: TracePointContext) -> u32 {
    match try_tcp_probe(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_tcp_probe(ctx: TracePointContext) -> Result<u32, u32> {
    if !net_collection_enabled() {
        return Ok(0);
    }

    let sfamily = unsafe { ctx.read_at::<u16>(PROBE_FAMILY_OFFSET) }.map_err(|_| 1u32)?;
    let (sockaddr_family, saddr) = read_probe_address(&ctx, PROBE_SADDR_OFFSET).ok_or(1u32)?;
    let (dsockaddr_family, daddr) = read_probe_address(&ctx, PROBE_DADDR_OFFSET).ok_or(1u32)?;
    // The dedicated family field and the family embedded in each sockaddr are
    // written from the same socket; disagreement means the assumed layout is
    // wrong for this kernel, so the sample is dropped rather than misfiled.
    if sockaddr_family != sfamily || dsockaddr_family != sfamily {
        return Ok(0);
    }
    let sport = unsafe { ctx.read_at::<u16>(PROBE_SPORT_OFFSET) }.unwrap_or(0);
    let dport = unsafe { ctx.read_at::<u16>(PROBE_DPORT_OFFSET) }.unwrap_or(0);
    let key = TcpKey::new(sfamily, saddr, sport, daddr, dport);

    let now = unsafe { bpf_ktime_get_ns() };
    match TCP_OWNERS.get_ptr_mut(key) {
        Some(ptr) => {
            let owner = unsafe { &mut *ptr };
            // One sample per connection per interval keeps a busy socket from
            // flooding the perf buffer; the RTT distribution over a run is
            // still described by the samples that remain.
            if now.saturating_sub(owner.last_sample_ns) < TCP_RTT_SAMPLE_INTERVAL_NS {
                bump_stat(TCP_STAT_RATE_LIMITED);
                return Ok(0);
            }
            owner.last_sample_ns = now;
            bump_stat(TCP_STAT_MATCHED_RTT);
            let srtt = unsafe { ctx.read_at::<u32>(PROBE_SRTT_OFFSET) }.unwrap_or(0);
            let event = TcpEvent {
                // TCP events are attributed to a connection, not a thread.
                tid: 0,
                family: sfamily,
                retrans: 0,
                _pad: 0,
                sport,
                dport,
                rtt_us: srtt,
                snd_cwnd: unsafe { ctx.read_at::<u32>(PROBE_SND_CWND_OFFSET) }.unwrap_or(0),
                rcv_wnd: unsafe { ctx.read_at::<u32>(PROBE_RCV_WND_OFFSET) }.unwrap_or(0),
                saddr,
                daddr,
            };
            NET_EVENTS.output(&ctx, event, BPF_ANY);
            Ok(0)
        }
        None => {
            bump_stat(TCP_STAT_UNMATCHED_RTT);
            Ok(0)
        }
    }
}

#[tracepoint(name = "tcp_retransmit_skb", category = "tcp")]
pub fn tcp_retransmit_skb(ctx: TracePointContext) -> u32 {
    match try_tcp_retransmit_skb(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_tcp_retransmit_skb(ctx: TracePointContext) -> Result<u32, u32> {
    if !net_collection_enabled() {
        return Ok(0);
    }

    let family = unsafe { ctx.read_at::<u16>(RETRANS_FAMILY_OFFSET) }.map_err(|_| 1u32)?;
    let (saddr, daddr) = match read_address_pair(
        &ctx,
        family,
        RETRANS_SADDR_OFFSET,
        RETRANS_DADDR_OFFSET,
        RETRANS_SADDR_V6_OFFSET,
        RETRANS_DADDR_V6_OFFSET,
    ) {
        Some(value) => value,
        None => return Ok(0),
    };
    let sport = unsafe { ctx.read_at::<u16>(RETRANS_SPORT_OFFSET) }.unwrap_or(0);
    let dport = unsafe { ctx.read_at::<u16>(RETRANS_DPORT_OFFSET) }.unwrap_or(0);
    let key = TcpKey::new(family, saddr, sport, daddr, dport);

    // Retransmissions are raised from softirq context, so the current task is
    // never the owner; only the tuple lookup can attribute them.
    if unsafe { TCP_OWNERS.get(key) }.is_none() {
        bump_stat(TCP_STAT_UNMATCHED_RETRANS);
        return Ok(0);
    }
    bump_stat(TCP_STAT_MATCHED_RETRANS);
    let event = TcpEvent {
        tid: 0,
        family,
        retrans: 1,
        _pad: 0,
        sport,
        dport,
        rtt_us: 0,
        snd_cwnd: 0,
        rcv_wnd: 0,
        saddr,
        daddr,
    };
    NET_EVENTS.output(&ctx, event, BPF_ANY);
    Ok(0)
}

// --- Memory: page faults and direct reclaim, counted rather than streamed ---
/// Adds one to a per-thread counter, creating the entry on first use.
///
/// The increment goes through a raw pointer because the map has to be updated
/// in place. That is safe here even though the kernel does not make map writes
/// atomic: only the thread that owns a key ever writes it, and a thread runs
/// on one CPU at a time, so there is no second writer to race with.
fn bump_counter(tid: u32, bump: fn(&mut MemoryCounters)) {
    match MEMORY_COUNTERS.get_ptr_mut(tid) {
        Some(ptr) => {
            let counters = unsafe { &mut *ptr };
            bump(counters);
        }
        None => {
            // The thread set can grow past what the map already holds, so the
            // entry has to be created. The first event of that thread is
            // counted as the seed rather than dropped.
            let mut counters = MemoryCounters {
                faults: 0,
                reclaims: 0,
            };
            bump(&mut counters);
            let _ = MEMORY_COUNTERS.insert(tid, counters, BPF_ANY as u64);
        }
    }
}

fn count_fault(counters: &mut MemoryCounters) {
    counters.faults = counters.faults.saturating_add(1);
}

fn count_reclaim(counters: &mut MemoryCounters) {
    counters.reclaims = counters.reclaims.saturating_add(1);
}

#[tracepoint(name = "page_fault_user", category = "exceptions")]
pub fn page_fault_user(_ctx: TracePointContext) -> u32 {
    if unsafe { MODE.get(0) }.copied().unwrap_or(0) & COLLECT_MEMORY == 0 {
        return 0;
    }
    let tid = bpf_get_current_pid_tgid() as u32;
    if unsafe { TARGET_TIDS.get(tid) }.is_none() {
        return 0;
    }
    bump_counter(tid, count_fault);
    0
}

/// Counts the moments a thread had to reclaim memory itself, which is what
/// memory pressure looks like from inside a process: the task cannot proceed
/// until pages come back.
#[tracepoint(name = "mm_vmscan_direct_reclaim_begin", category = "vmscan")]
pub fn mm_vmscan_direct_reclaim_begin(_ctx: TracePointContext) -> u32 {
    if unsafe { MODE.get(0) }.copied().unwrap_or(0) & COLLECT_MEMORY == 0 {
        return 0;
    }
    let tid = bpf_get_current_pid_tgid() as u32;
    if unsafe { TARGET_TIDS.get(tid) }.is_none() {
        return 0;
    }
    bump_counter(tid, count_reclaim);
    0
}

#[cfg(target_arch = "bpf")]
#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    loop {}
}
