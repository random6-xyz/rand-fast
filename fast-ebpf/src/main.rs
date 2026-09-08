#![cfg_attr(target_arch = "bpf", no_std)]
#![cfg_attr(target_arch = "bpf", no_main)]

#[cfg(target_arch = "bpf")]
use core::panic::PanicInfo;

use aya_ebpf::{
    EbpfContext,
    bindings::{BPF_ANY, BPF_F_REUSE_STACKID, BPF_NOEXIST},
    helpers::{
        bpf_get_current_pid_tgid, bpf_get_smp_processor_id, bpf_get_stackid, bpf_ktime_get_ns,
    },
    macros::{map, perf_event, tracepoint},
    maps::{HashMap, LruHashMap, PerfEventArray, StackTrace},
    programs::{PerfEventContext, TracePointContext},
};
use fast_common::{
    COLLECT_CPU_SAMPLE, COLLECT_OFFCPU, COLLECT_SCHEDULER_LATENCY, CpuSampleEvent, IoEvent,
    MAX_STACKS, MAX_TARGET_TIDS, MemoryEvent, OffCpuEvent, PendingIo, PendingWakeup,
    SchedulerLatencyEvent, TcpEvent,
};

// The offsets are the stable payload offsets of the Linux scheduler tracepoints:
// trace_entry is 8 bytes, followed by the fields declared in include/trace/events/sched.h.
const SCHED_WAKEUP_PID_OFFSET: usize = 24;
const SCHED_SWITCH_PREV_PID_OFFSET: usize = 24;
const SCHED_SWITCH_PREV_STATE_OFFSET: usize = 32;
const SCHED_SWITCH_NEXT_PID_OFFSET: usize = 56;

// Payload offsets of the block request tracepoints: trace_entry is 8 bytes,
// then dev (dev_t, 4 bytes), a 4-byte alignment hole, sector (u64), and
// nr_sector (u32). block_rq_issue carries cmd_flags at 28; block_rq_complete
// carries the completion error there instead. Verified against the tracepoint
// format files on the 6.x/7.x kernels used in the QEMU smoke matrix.
const BLOCK_RQ_DEV_OFFSET: usize = 8;
const BLOCK_RQ_SECTOR_OFFSET: usize = 16;
const BLOCK_RQ_NR_SECTOR_OFFSET: usize = 24;
const BLOCK_RQ_ISSUE_CMD_FLAGS_OFFSET: usize = 28;

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

#[map]
static IO_EVENTS: PerfEventArray<IoEvent> = PerfEventArray::new(0);

#[map]
static PENDING_IO: LruHashMap<u32, PendingIo> = LruHashMap::with_max_entries(MAX_TARGET_TIDS, 0);

#[map]
static NET_EVENTS: PerfEventArray<TcpEvent> = PerfEventArray::new(0);

#[map]
static OFFCPU_EVENTS: PerfEventArray<OffCpuEvent> = PerfEventArray::new(0);

#[map]
static OFFCPU_START: LruHashMap<u32, u64> = LruHashMap::with_max_entries(MAX_TARGET_TIDS, 0);

#[map]
static MEMORY_EVENTS: PerfEventArray<MemoryEvent> = PerfEventArray::new(0);

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
    // runnable again, so the pending switch-out timestamp measures its wait.
    if mode & COLLECT_OFFCPU != 0
        && let Some(start) = unsafe { OFFCPU_START.get(tid) }
    {
        // Copy the timestamp before removing the entry; the LRU entry memory
        // is freed by remove and must not be read afterwards.
        let start_ns = *start;
        let now = unsafe { bpf_ktime_get_ns() };
        let _ = OFFCPU_START.remove(tid);
        if now >= start_ns {
            let stack = unsafe {
                bpf_get_stackid(
                    ctx.as_ptr(),
                    &STACK_TRACES as *const _ as *mut core::ffi::c_void,
                    0,
                )
            };
            let event = OffCpuEvent {
                wait_ns: now - start_ns,
                stack_id: stack as i64,
                tid,
                reason: 0,
                _pad: 0,
                _pad2: 0,
            };
            OFFCPU_EVENTS.output(&ctx, event, BPF_ANY);
        }
    }

    Ok(0)
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

    // Off-CPU: a target task switched out in a sleepable state starts waiting.
    if mode & COLLECT_OFFCPU != 0
        && let Ok(prev_pid) = unsafe { ctx.read_at::<u32>(SCHED_SWITCH_PREV_PID_OFFSET) }
        && unsafe { TARGET_TIDS.get(prev_pid) }.is_some()
        && let Ok(prev_state) = unsafe { ctx.read_at::<u64>(SCHED_SWITCH_PREV_STATE_OFFSET) }
        && prev_state != 0
    {
        let _ = OFFCPU_START.insert(prev_pid, unsafe { bpf_ktime_get_ns() }, BPF_ANY as u64);
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
            &STACK_TRACES as *const _ as *mut core::ffi::c_void,
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

// --- I/O: block_rq_issue / block_rq_complete ---
#[tracepoint(name = "block_rq_issue", category = "block")]
pub fn block_rq_issue(ctx: TracePointContext) -> u32 {
    match try_block_rq_issue(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_block_rq_issue(ctx: TracePointContext) -> Result<u32, u32> {
    let tid = bpf_get_current_pid_tgid() as u32;
    if unsafe { TARGET_TIDS.get(tid) }.is_none() {
        return Ok(0);
    }

    let cmd_flags =
        unsafe { ctx.read_at::<u32>(BLOCK_RQ_ISSUE_CMD_FLAGS_OFFSET) }.map_err(|_| 0u32)?;
    let pending = PendingIo {
        start_ns: unsafe { bpf_ktime_get_ns() },
        tid,
        cmd_flags,
    };
    let _ = PENDING_IO.insert(tid, pending, BPF_ANY as u64);
    Ok(0)
}

#[tracepoint(name = "block_rq_complete", category = "block")]
pub fn block_rq_complete(ctx: TracePointContext) -> u32 {
    match try_block_rq_complete(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_block_rq_complete(ctx: TracePointContext) -> Result<u32, u32> {
    // The completion usually runs in IRQ/softirq context, so the current TID
    // says nothing about the issuer: only a pending entry can attribute the
    // completion to the issuing thread.
    let dev = unsafe { ctx.read_at::<u32>(BLOCK_RQ_DEV_OFFSET) }.map_err(|_| 0u32)?;
    let sector = unsafe { ctx.read_at::<u64>(BLOCK_RQ_SECTOR_OFFSET) }.map_err(|_| 0u32)?;
    let nr_sector = unsafe { ctx.read_at::<u32>(BLOCK_RQ_NR_SECTOR_OFFSET) }.map_err(|_| 0u32)?;

    let pending = match unsafe { PENDING_IO.get(&(bpf_get_current_pid_tgid() as u32)) } {
        Some(pending) => *pending,
        None => return Ok(0),
    };
    let _ = PENDING_IO.remove(&(bpf_get_current_pid_tgid() as u32));

    let end = unsafe { bpf_ktime_get_ns() };
    if end < pending.start_ns {
        return Ok(0);
    }
    let event = IoEvent {
        latency_ns: end - pending.start_ns,
        tid: pending.tid,
        dev,
        sectors: nr_sector,
        op: pending.cmd_flags >> 24,
    };
    IO_EVENTS.output(&ctx, event, BPF_ANY);
    Ok(0)
}

// --- Network: tcp_retransmit_skb ---
#[tracepoint(name = "tcp_retransmit_skb", category = "tcp")]
pub fn tcp_retransmit_skb(ctx: TracePointContext) -> u32 {
    let tid = bpf_get_current_pid_tgid() as u32;
    if unsafe { TARGET_TIDS.get(tid) }.is_none() {
        return 0;
    }
    let event = TcpEvent {
        tid,
        saddr: 0,
        daddr: 0,
        sport: 0,
        dport: 0,
        rtt_us: 0,
        retrans: 1,
        _pad: [0; 3],
    };
    NET_EVENTS.output(&ctx, event, BPF_ANY);
    0
}

// --- Memory: page_fault ---
#[tracepoint(name = "page_fault_user", category = "exceptions")]
pub fn page_fault_user(ctx: TracePointContext) -> u32 {
    let tid = bpf_get_current_pid_tgid() as u32;
    if unsafe { TARGET_TIDS.get(tid) }.is_none() {
        return 0;
    }
    let event = MemoryEvent {
        minflt: 1,
        majflt: 0,
        swap_kb: 0,
        tid,
        psi_some_pct: 0,
        psi_full_pct: 0,
        _pad: 0,
    };
    MEMORY_EVENTS.output(&ctx, event, BPF_ANY);
    0
}

#[cfg(target_arch = "bpf")]
#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    loop {}
}
