#![cfg_attr(target_arch = "bpf", no_std)]
#![cfg_attr(target_arch = "bpf", no_main)]

#[cfg(target_arch = "bpf")]
use core::panic::PanicInfo;

use aya_ebpf::{
    bindings::{BPF_ANY, BPF_F_REUSE_STACKID, BPF_NOEXIST},
    helpers::{bpf_get_stackid, bpf_get_smp_processor_id, bpf_ktime_get_ns},
    macros::{map, tracepoint},
    maps::{HashMap, LruHashMap, PerfEventArray, StackTrace},
    programs::TracePointContext,
    EbpfContext,
};
use fast_common::{CpuSampleEvent, MAX_STACKS, MAX_TARGET_TIDS, PendingWakeup, SchedulerLatencyEvent};

// The offsets are the stable payload offsets of the Linux scheduler tracepoints:
// trace_entry is 8 bytes, followed by the fields declared in include/trace/events/sched.h.
const SCHED_WAKEUP_PID_OFFSET: usize = 24;
const SCHED_SWITCH_NEXT_PID_OFFSET: usize = 56;

#[cfg(not(target_arch = "bpf"))]
fn main() {}

#[map]
static TARGET_TIDS: HashMap<u32, u8> = HashMap::with_max_entries(MAX_TARGET_TIDS, 0);

#[map]
static PENDING_WAKEUPS: LruHashMap<u32, PendingWakeup> =
    LruHashMap::with_max_entries(MAX_TARGET_TIDS, 0);

#[map]
static EVENTS: PerfEventArray<SchedulerLatencyEvent> = PerfEventArray::new(0);

#[map]
static CPU_EVENTS: PerfEventArray<CpuSampleEvent> = PerfEventArray::new(0);

#[map]
static STACK_TRACES: StackTrace = StackTrace::with_max_entries(MAX_STACKS, 0);

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

    // A runnable task should retain the timestamp of its first observed wakeup.
    // BPF_NOEXIST also avoids replacing it if multiple wakeup notifications race.
    if unsafe { PENDING_WAKEUPS.get(tid) }.is_none() {
        let pending = PendingWakeup {
            wake_ns: unsafe { bpf_ktime_get_ns() },
            wake_cpu: unsafe { bpf_get_smp_processor_id() },
            reserved: 0,
        };
        let _ = PENDING_WAKEUPS.insert(tid, pending, BPF_NOEXIST as u64);
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

    if unsafe { TARGET_TIDS.get(tid) }.is_none() {
        return Ok(0);
    }

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

    // Best-effort on-CPU sampling for hot-stack reporting.
    let kstack = unsafe {
        bpf_get_stackid(
            ctx.as_ptr() as *mut core::ffi::c_void,
            &STACK_TRACES as *const _ as *mut core::ffi::c_void,
            0,
        )
    };
    let ustack = unsafe {
        bpf_get_stackid(
            ctx.as_ptr() as *mut core::ffi::c_void,
            &STACK_TRACES as *const _ as *mut core::ffi::c_void,
            256 | BPF_F_REUSE_STACKID as u64,
        )
    };
    let cpu_sample = CpuSampleEvent {
        tid,
        cpu: run_cpu,
        kernel_stack_id: kstack as i64,
        user_stack_id: ustack as i64,
        _pad: 0,
        _pad2: 0,
    };
    CPU_EVENTS.output(&ctx, cpu_sample, BPF_ANY);

    Ok(0)
}

#[cfg(target_arch = "bpf")]
#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    loop {}
}
