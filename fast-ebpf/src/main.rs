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
    maps::{HashMap, LruHashMap, PerfEventArray, StackTrace},
    programs::{PerfEventContext, RawTracePointContext, TracePointContext},
};
use fast_common::{
    COLLECT_CPU_SAMPLE, COLLECT_MEMORY, COLLECT_OFFCPU, COLLECT_SCHEDULER_LATENCY, CpuSampleEvent,
    IO_OP_UNMATCHED, IoEvent, IoRequestId, IoRequestLayout, MAX_MEMORY_THREADS, MAX_PENDING_IO,
    MAX_STACKS, MAX_TARGET_TIDS, MemoryCounters, OFFCPU_REASON_IO, OFFCPU_REASON_UNKNOWN,
    OFFCPU_REASON_WAIT, OffCpuEvent, OffCpuPending, PendingIo, PendingWakeup,
    SchedulerLatencyEvent, TcpEvent, io_op_from_request_flags, scheduler_state_is_exiting,
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

// These tracepoints cannot establish socket ownership. In particular, receive
// processing can run in softirq context and a raw socket address can be reused.
// Never emit an attributed event until a verified ownership path exists.
#[tracepoint(name = "tcp_probe", category = "tcp")]
pub fn tcp_probe(_ctx: TracePointContext) -> u32 {
    0
}

#[tracepoint(name = "tcp_retransmit_skb", category = "tcp")]
pub fn tcp_retransmit_skb(_ctx: TracePointContext) -> u32 {
    0
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
