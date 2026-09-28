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
    AF_INET, AF_INET6, COLLECT_CPU_SAMPLE, COLLECT_NET, COLLECT_OFFCPU, COLLECT_SCHEDULER_LATENCY,
    CpuSampleEvent, IoEvent, IoRequestKey, MAX_PENDING_IO, MAX_STACKS, MAX_TARGET_TIDS,
    MAX_TCP_SOCKETS, MemoryEvent, OFFCPU_REASON_IO, OFFCPU_REASON_UNKNOWN, OFFCPU_REASON_WAIT,
    OffCpuEvent, OffCpuPending, PendingIo, PendingWakeup, SchedulerLatencyEvent, TcpEvent,
};

// The offsets are the stable payload offsets of the Linux scheduler tracepoints:
// trace_entry is 8 bytes, followed by the fields declared in include/trace/events/sched.h.
const SCHED_WAKEUP_PID_OFFSET: usize = 24;
const SCHED_SWITCH_PREV_PID_OFFSET: usize = 24;
const SCHED_SWITCH_PREV_STATE_OFFSET: usize = 32;
const SCHED_SWITCH_NEXT_PID_OFFSET: usize = 56;

// Payload offsets of the block request tracepoints, verified against the
// format files that tools/qemu-guest-init.sh dumps on the target kernel
// (7.2.3-arch1-3):
//   issue:    dev=8(4) sector=16(8) nr_sector=24(4) bytes=28(4) ioprio=32(2)
//             rwbs[10]=34 comm[16]=44 cmd=60
//   complete: dev=8(4) sector=16(8) nr_sector=24(4) error=28(4) ioprio=32(2)
//             rwbs[10]=34 cmd=44
// The operation is the first character of the rwbs string, which is how the
// kernel renders req_op for the trace (R read, W write, D discard, ...).
const BLOCK_RQ_DEV_OFFSET: usize = 8;
const BLOCK_RQ_SECTOR_OFFSET: usize = 16;
const BLOCK_RQ_NR_SECTOR_OFFSET: usize = 24;
const BLOCK_RQ_RWBS_OFFSET: usize = 34;

// Payload offsets of the TCP tracepoints, verified against the format files
// that tools/qemu-guest-init.sh dumps on the target kernel (7.2.0-rc6).
//
//   tcp_probe:            saddr=8(28) daddr=36(28) sport=64 dport=66 family=68
//                         mark=72 data_len=76 snd_nxt=80 snd_una=84
//                         snd_cwnd=88 ssthresh=92 snd_wnd=96 srtt=100
//                         rcv_wnd=104 sock_cookie=112 skbaddr=120 skaddr=128
//   tcp_retransmit_skb:   skbaddr=8 skaddr=16 state=24 sport=28 dport=30
//                         family=32 saddr=34(4) daddr=38(4) saddr_v6=42(16)
//                         daddr_v6=58(16) err=76
//
// Both events carry the socket 5-tuple in the payload, so no BTF read and no
// struct offset is needed: the kernel already resolved the addresses and the
// ports. `saddr`/`daddr` are a `struct sockaddr_in6`, so they carry the
// family and port as well as the address; the separate `sport`/`dport`
// fields are the same ports in host byte order and are preferred.
//
// `saddr` and `daddr` are written by TP_STORE_ADDR_PORTS, which stores a
// `struct sockaddr_in` for IPv4 and a `struct sockaddr_in6` for IPv6. Both
// begin with the family in host byte order followed by the port in network
// byte order, so one parser handles either: IPv4 addresses follow directly
// and IPv6 addresses start after the 4-byte flowinfo field.
const TCP_PROBE_SADDR_OFFSET: usize = 8;
const TCP_PROBE_SADDR_LEN: usize = 28;
const TCP_PROBE_DADDR_OFFSET: usize = 36;
const TCP_PROBE_SPORT_OFFSET: usize = 64;
const TCP_PROBE_DPORT_OFFSET: usize = 66;
const TCP_PROBE_FAMILY_OFFSET: usize = 68;
const TCP_PROBE_SND_CWND_OFFSET: usize = 88;
const TCP_PROBE_SRTT_OFFSET: usize = 100;
const TCP_PROBE_RCV_WND_OFFSET: usize = 104;
const TCP_PROBE_SKADDR_OFFSET: usize = 128;

const TCP_RETRANS_SKADDR_OFFSET: usize = 16;
const TCP_RETRANS_SPORT_OFFSET: usize = 28;
const TCP_RETRANS_DPORT_OFFSET: usize = 30;
const TCP_RETRANS_FAMILY_OFFSET: usize = 32;
const TCP_RETRANS_SADDR_OFFSET: usize = 34;
const TCP_RETRANS_DADDR_OFFSET: usize = 38;
const TCP_RETRANS_SADDR_V6_OFFSET: usize = 42;
const TCP_RETRANS_DADDR_V6_OFFSET: usize = 58;

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
static PENDING_IO: LruHashMap<IoRequestKey, PendingIo> =
    LruHashMap::with_max_entries(MAX_PENDING_IO, 0);

#[map]
static NET_EVENTS: PerfEventArray<TcpEvent> = PerfEventArray::new(0);

/// Sockets a target thread was seen using, keyed by `struct sock *`.
///
/// `tcp_probe` usually runs in the context of the thread that owns the
/// socket, but TCP retransmissions are raised from softirq context where the
/// current TID says nothing about the owner. Remembering the socket pointer
/// when a target thread is seen on it lets those events be attributed to the
/// socket instead of to whatever task happened to be running.
#[map]
static TCP_SOCKETS: LruHashMap<u64, u32> = LruHashMap::with_max_entries(MAX_TCP_SOCKETS, 0);

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
        && prev_state != 0
    {
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

    let dev = unsafe { ctx.read_at::<u32>(BLOCK_RQ_DEV_OFFSET) }.map_err(|_| 0u32)?;
    let sector = unsafe { ctx.read_at::<u64>(BLOCK_RQ_SECTOR_OFFSET) }.map_err(|_| 0u32)?;
    let rwbs_op = unsafe { ctx.read_at::<u8>(BLOCK_RQ_RWBS_OFFSET) }.map_err(|_| 0u32)?;

    // Key the request by (device, start sector) so the completion can find it
    // from IRQ/softirq context. BPF_NOEXIST keeps the first outstanding
    // request on a colliding key instead of letting a second issue overwrite
    // and misattribute it.
    let key = IoRequestKey {
        dev,
        _pad: 0,
        sector,
    };
    let pending = PendingIo {
        start_ns: unsafe { bpf_ktime_get_ns() },
        tid,
        op: match rwbs_op {
            b'R' => 0,
            b'W' => 1,
            _ => 2,
        },
    };
    let _ = PENDING_IO.insert(key, pending, BPF_NOEXIST as u64);
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
    // says nothing about the issuer: the pending entry, found through the
    // request key, carries the issuing thread.
    let dev = unsafe { ctx.read_at::<u32>(BLOCK_RQ_DEV_OFFSET) }.map_err(|_| 0u32)?;
    let sector = unsafe { ctx.read_at::<u64>(BLOCK_RQ_SECTOR_OFFSET) }.map_err(|_| 0u32)?;
    let nr_sector = unsafe { ctx.read_at::<u32>(BLOCK_RQ_NR_SECTOR_OFFSET) }.map_err(|_| 0u32)?;
    let key = IoRequestKey {
        dev,
        _pad: 0,
        sector,
    };

    let pending = match unsafe { PENDING_IO.get(key) } {
        Some(pending) => *pending,
        None => return Ok(0),
    };
    let _ = PENDING_IO.remove(key);

    let end = unsafe { bpf_ktime_get_ns() };
    if end < pending.start_ns {
        return Ok(0);
    }
    let event = IoEvent {
        latency_ns: end - pending.start_ns,
        tid: pending.tid,
        dev,
        sectors: nr_sector,
        op: pending.op,
    };
    IO_EVENTS.output(&ctx, event, BPF_ANY);
    Ok(0)
}

// --- Network: TCP RTT via tcp_probe ---
/// Reads a `struct sockaddr_in6` from a tracepoint payload and splits it into
/// an address family, a port in host byte order, and the address bytes.
///
/// The kernel fills these in through `TP_STORE_ADDR_PORTS`, which writes a
/// `struct sockaddr_in` for IPv4 and a `struct sockaddr_in6` for IPv6. In
/// both cases the first two bytes are the family in host order and the next
/// two are the port in network order. IPv4 addresses follow directly; IPv6
/// addresses start after the 4-byte flowinfo field.
fn read_socket_addr(
    ctx: &TracePointContext,
    offset: usize,
    len: usize,
) -> Option<(u16, u16, [u8; 16])> {
    if len < 24 {
        return None;
    }
    let raw: [u8; 28] = unsafe { ctx.read_at(offset) }.ok()?;
    let family = u16::from_ne_bytes([raw[0], raw[1]]);
    // The port is kept in network byte order by the kernel, so it needs an
    // explicit swap to reach host order.
    let port = u16::from_be_bytes([raw[2], raw[3]]);

    let mut address = [0u8; 16];
    if family == AF_INET {
        address[..4].copy_from_slice(&raw[4..8]);
    } else {
        address.copy_from_slice(&raw[8..24]);
    }
    Some((family, port, address))
}

/// Resolves the thread a TCP event belongs to.
///
/// Returns `None` when the event cannot be attributed to a target thread,
/// which is the common case: these tracepoints fire for every TCP connection
/// on the host, not just for the observed process.
///
/// The `skaddr_offset` argument selects where the event keeps its
/// `struct sock *`. Both `tcp_probe` and `tcp_retransmit_skb` record the
/// same pointer, so a socket learned from one is recognised by the other.
fn attribute_tcp_socket(ctx: &TracePointContext, skaddr_offset: usize) -> Option<u32> {
    let skaddr = unsafe { ctx.read_at::<u64>(skaddr_offset) }.ok()?;
    if skaddr == 0 {
        return None;
    }
    let tid = bpf_get_current_pid_tgid() as u32;
    if unsafe { TARGET_TIDS.get(tid) }.is_some() {
        // A target thread is using this socket, so remember the association
        // for later events that arrive outside of its context.
        let _ = TCP_SOCKETS.insert(skaddr, tid, BPF_ANY as u64);
        return Some(tid);
    }
    // Not in a target thread: fall back to a socket a target was seen using.
    // This is the path retransmissions take, since the kernel raises them
    // from softirq context where the current TID is unrelated to the owner.
    let owner = unsafe { TCP_SOCKETS.get(skaddr) }?;
    Some(*owner)
}

#[tracepoint(name = "tcp_probe", category = "tcp")]
pub fn tcp_probe(ctx: TracePointContext) -> u32 {
    match try_tcp_probe(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_tcp_probe(ctx: TracePointContext) -> Result<u32, u32> {
    if unsafe { MODE.get(0) }.copied().unwrap_or(0) & COLLECT_NET == 0 {
        return Ok(0);
    }

    let tid = match attribute_tcp_socket(&ctx, TCP_PROBE_SKADDR_OFFSET) {
        Some(tid) => tid,
        None => return Ok(0),
    };

    let sfamily = match unsafe { ctx.read_at::<u16>(TCP_PROBE_FAMILY_OFFSET) }.ok() {
        Some(value) => value,
        None => return Ok(0),
    };
    let (parsed_sfamily, _, saddr) =
        match read_socket_addr(&ctx, TCP_PROBE_SADDR_OFFSET, TCP_PROBE_SADDR_LEN) {
            Some(value) => value,
            None => return Ok(0),
        };
    let (dfamily, _, daddr) =
        match read_socket_addr(&ctx, TCP_PROBE_DADDR_OFFSET, TCP_PROBE_SADDR_LEN) {
            Some(value) => value,
            None => return Ok(0),
        };
    // The dedicated `family` field and the family embedded in the sockaddr
    // are written by the same kernel code, so they always agree. When they do
    // not, the payload layout this program assumes is wrong for the running
    // kernel, and reporting the sample would poison the endpoint table with
    // misread addresses. Dropping it turns a silent corruption into an empty
    // report.
    if parsed_sfamily != sfamily || sfamily != dfamily {
        return Ok(0);
    }
    if sfamily != AF_INET && sfamily != AF_INET6 {
        return Ok(0);
    }

    let sport = unsafe { ctx.read_at::<u16>(TCP_PROBE_SPORT_OFFSET) }.unwrap_or(0);
    let dport = unsafe { ctx.read_at::<u16>(TCP_PROBE_DPORT_OFFSET) }.unwrap_or(0);
    // The kernel source for this tracepoint assigns `tp->srtt_us >> 3` to
    // the field, which would make the stored value one eighth of a
    // microsecond. On the verified kernel the stored value nevertheless
    // matches the RTT `ss -ti` reports for the same sockets (43 us against
    // 45 us in the recorded run), so the field is used unscaled. The
    // cross-check in tools/qemu-smoke.sh is what establishes the scale: a
    // wrong factor of eight shows up as an 8x disagreement with the kernel
    // rather than as a plausible-looking number.
    let srtt = unsafe { ctx.read_at::<u32>(TCP_PROBE_SRTT_OFFSET) }.unwrap_or(0);
    let snd_cwnd = unsafe { ctx.read_at::<u32>(TCP_PROBE_SND_CWND_OFFSET) }.unwrap_or(0);
    let rcv_wnd = unsafe { ctx.read_at::<u32>(TCP_PROBE_RCV_WND_OFFSET) }.unwrap_or(0);

    let event = TcpEvent {
        tid,
        family: sfamily,
        retrans: 0,
        _pad: 0,
        sport,
        dport,
        rtt_us: srtt,
        snd_cwnd,
        rcv_wnd,
        saddr,
        daddr,
    };
    NET_EVENTS.output(&ctx, event, BPF_ANY);
    Ok(0)
}

#[tracepoint(name = "tcp_retransmit_skb", category = "tcp")]
pub fn tcp_retransmit_skb(ctx: TracePointContext) -> u32 {
    match try_tcp_retransmit_skb(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_tcp_retransmit_skb(ctx: TracePointContext) -> Result<u32, u32> {
    if unsafe { MODE.get(0) }.copied().unwrap_or(0) & COLLECT_NET == 0 {
        return Ok(0);
    }

    // The kernel raises retransmissions from softirq context, so the current
    // TID is never the socket owner. Attribution goes through the socket
    // pointer, which both TCP tracepoints share.
    let tid = match attribute_tcp_socket(&ctx, TCP_RETRANS_SKADDR_OFFSET) {
        Some(tid) => tid,
        None => return Ok(0),
    };

    let family = match unsafe { ctx.read_at::<u16>(TCP_RETRANS_FAMILY_OFFSET) }.ok() {
        Some(value) => value,
        None => return Ok(0),
    };

    // saddr/daddr always hold the IPv4 addresses; saddr_v6/daddr_v6 hold
    // either the IPv6 address or a v4-mapped form of the IPv4 one. Reading
    // the pair that matches the family keeps the layout identical to what
    // tcp_probe produces, so both events land on the same endpoint.
    let (saddr, daddr) = if family == AF_INET6 {
        let s: [u8; 16] = match unsafe { ctx.read_at(TCP_RETRANS_SADDR_V6_OFFSET) } {
            Ok(value) => value,
            Err(_) => return Ok(0),
        };
        let d: [u8; 16] = match unsafe { ctx.read_at(TCP_RETRANS_DADDR_V6_OFFSET) } {
            Ok(value) => value,
            Err(_) => return Ok(0),
        };
        (s, d)
    } else if family == AF_INET {
        let s: [u8; 4] = match unsafe { ctx.read_at(TCP_RETRANS_SADDR_OFFSET) } {
            Ok(value) => value,
            Err(_) => return Ok(0),
        };
        let d: [u8; 4] = match unsafe { ctx.read_at(TCP_RETRANS_DADDR_OFFSET) } {
            Ok(value) => value,
            Err(_) => return Ok(0),
        };
        let mut wide_s = [0u8; 16];
        let mut wide_d = [0u8; 16];
        wide_s[..4].copy_from_slice(&s);
        wide_d[..4].copy_from_slice(&d);
        (wide_s, wide_d)
    } else {
        // Neither AF_INET nor AF_INET6, for example a Unix socket.
        return Ok(0);
    };

    let sport = unsafe { ctx.read_at::<u16>(TCP_RETRANS_SPORT_OFFSET) }.unwrap_or(0);
    let dport = unsafe { ctx.read_at::<u16>(TCP_RETRANS_DPORT_OFFSET) }.unwrap_or(0);

    let event = TcpEvent {
        tid,
        family,
        retrans: 1,
        _pad: 0,
        sport,
        dport,
        // A retransmission has no smoothed RTT or window to report.
        rtt_us: 0,
        snd_cwnd: 0,
        rcv_wnd: 0,
        saddr,
        daddr,
    };
    NET_EVENTS.output(&ctx, event, BPF_ANY);
    Ok(0)
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
