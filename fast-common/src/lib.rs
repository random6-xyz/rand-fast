#![no_std]

use bytemuck::{Pod, Zeroable};

/// Map-facing types need to satisfy aya's `Pod` marker so the userspace crate
/// can put them into aya maps. Implemented only under the opt-in `aya`
/// feature because the eBPF build must not link aya.
#[cfg(feature = "aya")]
mod aya_pod {
    unsafe impl aya::Pod for crate::PendingIo {}
    unsafe impl aya::Pod for crate::IoRequestId {}
    unsafe impl aya::Pod for crate::IoRequestLayout {}
    unsafe impl aya::Pod for crate::OffCpuPending {}
    unsafe impl aya::Pod for crate::MemoryCounters {}
}

pub const MAX_TARGET_TIDS: u32 = 4096;
/// Upper bound for in-flight target I/O requests keyed by kernel request
/// identity. If the map fills, the collector reports an unmatched request
/// instead of silently evicting a pending measurement.
pub const MAX_PENDING_IO: u32 = 8192;
/// Upper bound for per-thread memory counters. Only target threads get an
/// entry, so this matches the target thread limit.
pub const MAX_MEMORY_THREADS: u32 = MAX_TARGET_TIDS;
/// Stack trace map capacity. Sized for periodic on-CPU sampling where many
/// distinct user/kernel stacks accumulate over a run; entries are allocated
/// lazily (~1 KiB each at the default 127-frame depth).
pub const MAX_STACKS: u32 = 4096;
pub const MAX_STACK_DEPTH: u32 = 32;

pub const SLOW_1MS_NS: u64 = 1_000_000;
pub const SLOW_10MS_NS: u64 = 10_000_000;
pub const SLOW_50MS_NS: u64 = 50_000_000;

/// Collector mode bits written into the eBPF `MODE` map by the userspace
/// command, so each tracepoint program only does the work its command
/// consumes.
pub const COLLECT_SCHEDULER_LATENCY: u32 = 1;
pub const COLLECT_CPU_SAMPLE: u32 = 2;
pub const COLLECT_OFFCPU: u32 = 4;
pub const COLLECT_NET: u32 = 8;
pub const COLLECT_MEMORY: u32 = 16;

/// Address family of an IPv4 socket, as stored in [`TcpEvent::family`].
pub const AF_INET: u16 = 2;
/// Address family of an IPv6 socket, as stored in [`TcpEvent::family`].
pub const AF_INET6: u16 = 10;

/// Event type discriminator for the extensible ABI.
#[repr(u32)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EventType {
    SchedulerLatency = 1,
    CpuSample = 2,
    Io = 3,
    Network = 4,
    OffCpu = 5,
    Memory = 6,
}

/// A scheduler latency sample emitted when a target thread starts running.
#[repr(C)]
#[derive(Clone, Copy, Debug, Pod, Zeroable)]
pub struct SchedulerLatencyEvent {
    pub latency_ns: u64,
    pub wake_ns: u64,
    pub run_ns: u64,
    pub tid: u32,
    pub wake_cpu: u32,
    pub run_cpu: u32,
    pub reserved: u32,
}

/// The wakeup state kept for a runnable target thread.
#[repr(C)]
#[derive(Clone, Copy, Debug, Pod, Zeroable)]
pub struct PendingWakeup {
    pub wake_ns: u64,
    pub wake_cpu: u32,
    pub reserved: u32,
}

/// Pending block I/O request state carried from `block_rq_issue` to
/// `block_rq_complete`. `op` is derived from the request's REQ_OP bits: 0 read,
/// 1 write, 2 anything else (see [`io_op_name`]).
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Pod, Zeroable)]
pub struct PendingIo {
    pub start_ns: u64,
    pub tid: u32,
    pub op: u32,
}

/// Unique identity of a live kernel block request, taken from its struct
/// request pointer. This remains distinct even when requests share device and
/// sector values or complete out of issue order.
#[repr(transparent)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, Pod, Zeroable)]
pub struct IoRequestId(pub u64);

impl IoRequestId {
    /// Builds an identity from the raw address passed by a block tracepoint.
    pub const fn from_address(address: u64) -> Self {
        Self(address)
    }
}

/// BTF-derived byte offsets used to read the kernel request associated with a
/// block raw tracepoint. Userspace verifies the required fields from the
/// running kernel's BTF before attaching the I/O programs.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Pod, Zeroable)]
pub struct IoRequestLayout {
    pub request_q: u32,
    pub request_sector: u32,
    pub request_data_len: u32,
    pub request_cmd_flags: u32,
    pub queue_disk: u32,
    pub gendisk_major: u32,
    pub gendisk_first_minor: u32,
}

/// Operation code used for an I/O event whose request could not be tracked.
pub const IO_OP_UNMATCHED: u32 = 3;

/// Exit-state bits reported by sched_switch's prev_state field.
///
/// The tracepoint reports EXIT_DEAD/EXIT_ZOMBIE rather than TASK_DEAD itself.
pub const SCHED_EXIT_STATE_MASK: u64 = 0x10 | 0x20;

/// Whether sched_switch reports an exiting task rather than a wait.
pub fn scheduler_state_is_exiting(state: u64) -> bool {
    state & SCHED_EXIT_STATE_MASK != 0
}

/// Maps the low REQ_OP bits of request flags to rand-fast's operation codes.
pub fn io_op_from_request_flags(flags: u32) -> u32 {
    match flags & 0xff {
        0 => 0,
        1 => 1,
        _ => 2,
    }
}

/// Human-readable name for the operation code stored in I/O events. Read and
/// write use 0 and 1; 2 means any other block operation. `IO_OP_UNMATCHED` is
/// a diagnostic record, not a latency sample.
pub fn io_op_name(op: u32) -> &'static str {
    match op {
        0 => "read",
        1 => "write",
        IO_OP_UNMATCHED => "unmatched",
        _ => "other",
    }
}

/// On-CPU sampling event for hot-stack reporting.
#[repr(C)]
#[derive(Clone, Copy, Debug, Pod, Zeroable)]
pub struct CpuSampleEvent {
    pub tid: u32,
    pub cpu: u32,
    pub kernel_stack_id: i64,
    pub user_stack_id: i64,
    pub _pad: u32,
    pub _pad2: u32,
}

/// Snapshot of process CPU time read from /proc.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Pod, Zeroable)]
pub struct CpuUsageSnapshot {
    pub utime_ticks: u64,
    pub stime_ticks: u64,
    pub total_ticks: u64,
}

/// I/O latency event attributed to a thread and block device. An event with
/// `op == IO_OP_UNMATCHED` is a diagnostic indicating that an in-flight target
/// request could not be tracked; it must not be included in latency samples.
#[repr(C)]
#[derive(Clone, Copy, Debug, Pod, Zeroable)]
pub struct IoEvent {
    pub latency_ns: u64,
    pub tid: u32,
    pub dev: u32,
    pub sectors: u32,
    pub op: u32,
}

/// A TCP sample or retransmission attributed to a socket.
///
/// Addresses are stored in network byte order. For [`AF_INET`] only the first
/// four bytes of each address are meaningful and the rest are zero; for
/// [`AF_INET6`] all sixteen are. Ports are stored in host byte order.
///
/// The kernel's `tcp_probe` tracepoint reports its smoothed RTT as
/// `tp->srtt_us >> 3`, so [`Self::rtt_us`] carries the shifted-back value in
/// microseconds. Retransmission events have no RTT and report zero.
#[repr(C)]
#[derive(Clone, Copy, Debug, Pod, Zeroable)]
pub struct TcpEvent {
    /// Thread the event was attributed to.
    pub tid: u32,
    /// [`AF_INET`] or [`AF_INET6`].
    pub family: u16,
    /// 1 for a retransmission, 0 for an ordinary sample.
    pub retrans: u8,
    /// Padding, always zero.
    pub _pad: u8,
    /// Source port, host byte order.
    pub sport: u16,
    /// Destination port, host byte order.
    pub dport: u16,
    /// Smoothed RTT in microseconds, zero for retransmissions.
    pub rtt_us: u32,
    /// Congestion window in segments, zero for retransmissions.
    pub snd_cwnd: u32,
    /// Receive window in bytes, zero for retransmissions.
    pub rcv_wnd: u32,
    /// Source address, network byte order.
    pub saddr: [u8; 16],
    /// Destination address, network byte order.
    pub daddr: [u8; 16],
}

/// The wait reason could not be classified from the task state alone.
pub const OFFCPU_REASON_UNKNOWN: u32 = 0;
/// The task was sleeping in an interruptible wait. Futexes, condition
/// variables and timed sleeps all land here, because the kernel blocks them
/// the same way.
pub const OFFCPU_REASON_WAIT: u32 = 1;
/// The task was in an uninterruptible wait, which is what disk and network
/// I/O use for the duration of a request.
pub const OFFCPU_REASON_IO: u32 = 2;

/// A target thread that has switched out and not yet been woken.
///
/// The blocking stack is captured here, at switch-out, rather than at
/// wakeup: by the time the task is woken the frame that blocked it is gone,
/// and the captured stack would describe whatever woke the task instead.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Pod, Zeroable)]
pub struct OffCpuPending {
    /// When the thread stopped running, from `bpf_ktime_get_ns`.
    pub start_ns: u64,
    /// Stack id of the blocking context, or a negative value when the capture
    /// failed.
    pub stack_id: i64,
    /// One of the `OFFCPU_REASON_*` constants, derived from the task state.
    pub reason: u32,
    /// Padding, always zero.
    pub _pad: u32,
}

/// Off-CPU wait event with stack.
#[repr(C)]
#[derive(Clone, Copy, Debug, Pod, Zeroable)]
pub struct OffCpuEvent {
    pub wait_ns: u64,
    pub stack_id: i64,
    pub tid: u32,
    pub reason: u32,
    pub _pad: u32,
    pub _pad2: u32,
}

/// Per-thread memory activity, accumulated in the kernel and read by
/// userspace.
///
/// A process can take hundreds of thousands of page faults a second, and
/// emitting a perf event for each one drowns the buffer and loses records.
/// Counting in a map instead costs a map update per fault and produces no
/// events at all, so userspace polls the map and differences two snapshots to
/// get a rate. The counts are cumulative from the start of collection.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Pod, Zeroable)]
pub struct MemoryCounters {
    /// User page faults seen on this thread.
    pub faults: u64,
    /// Direct reclaim attempts this thread entered, which is where a task
    /// stalls when memory runs short.
    pub reclaims: u64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::mem::{align_of, size_of};

    #[test]
    fn event_layout_is_stable() {
        assert_eq!(size_of::<SchedulerLatencyEvent>(), 40);
        assert_eq!(align_of::<SchedulerLatencyEvent>(), 8);
    }

    #[test]
    fn pending_layout_is_stable() {
        assert_eq!(size_of::<PendingWakeup>(), 16);
        assert_eq!(align_of::<PendingWakeup>(), 8);
    }

    #[test]
    fn pending_io_layout_is_stable() {
        assert_eq!(size_of::<PendingIo>(), 16);
        assert_eq!(align_of::<PendingIo>(), 8);
    }

    #[test]
    fn io_request_id_layout_is_stable() {
        assert_eq!(size_of::<IoRequestId>(), 8);
        assert_eq!(align_of::<IoRequestId>(), 8);
        assert_eq!(IoRequestId::from_address(0x1234).0, 0x1234);
    }

    #[test]
    fn io_op_names() {
        assert_eq!(io_op_name(0), "read");
        assert_eq!(io_op_name(1), "write");
        assert_eq!(io_op_name(2), "other");
        assert_eq!(io_op_name(IO_OP_UNMATCHED), "unmatched");
    }

    #[test]
    fn request_flags_keep_read_write_and_flush_operation_semantics() {
        assert_eq!(io_op_from_request_flags(0), 0);
        assert_eq!(io_op_from_request_flags(1), 1);
        assert_eq!(io_op_from_request_flags(2), 2);
        assert_eq!(io_op_from_request_flags(3), 2);
        assert_eq!(io_op_from_request_flags(0x101), 1);
    }

    #[test]
    fn scheduler_exit_state_is_not_classified_as_an_off_cpu_wait() {
        assert!(!scheduler_state_is_exiting(0));
        assert!(!scheduler_state_is_exiting(1));
        assert!(!scheduler_state_is_exiting(2));
        assert!(scheduler_state_is_exiting(0x10));
        assert!(scheduler_state_is_exiting(0x20));
        assert!(scheduler_state_is_exiting(0x10 | 1));
    }

    #[test]
    fn cpu_sample_event_layout_is_stable() {
        assert_eq!(size_of::<CpuSampleEvent>(), 32);
        assert_eq!(align_of::<CpuSampleEvent>(), 8);
    }

    #[test]
    fn cpu_sample_event_round_trips_through_bytes() {
        let event = CpuSampleEvent {
            tid: 42,
            cpu: 3,
            kernel_stack_id: 7,
            user_stack_id: -1,
            _pad: 0,
            _pad2: 0,
        };
        let decoded: CpuSampleEvent = bytemuck::pod_read_unaligned(bytemuck::bytes_of(&event));
        assert_eq!(bytemuck::bytes_of(&decoded), bytemuck::bytes_of(&event));
        assert_eq!(decoded.tid, 42);
        assert_eq!(decoded.cpu, 3);
        assert_eq!(decoded.kernel_stack_id, 7);
        assert_eq!(decoded.user_stack_id, -1);
    }

    #[test]
    fn io_event_layout_is_stable() {
        assert_eq!(size_of::<IoEvent>(), 24);
        assert_eq!(align_of::<IoEvent>(), 8);
    }

    #[test]
    fn tcp_event_layout_is_stable() {
        assert_eq!(size_of::<TcpEvent>(), 56);
        assert_eq!(align_of::<TcpEvent>(), 4);
    }

    #[test]
    fn tcp_event_fits_the_decode_buffer() {
        // runtime::MAX_EVENT_SIZE is 64, so a TcpEvent must stay under it.
        assert!(size_of::<TcpEvent>() <= 64);
    }

    fn sample_tcp_event() -> TcpEvent {
        TcpEvent {
            tid: 42,
            family: AF_INET,
            retrans: 0,
            _pad: 0,
            sport: 1234,
            dport: 80,
            rtt_us: 1500,
            snd_cwnd: 10,
            rcv_wnd: 65535,
            saddr: [127, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            daddr: [10, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        }
    }

    #[test]
    fn tcp_event_round_trips_through_bytes() {
        let event = sample_tcp_event();
        let decoded: TcpEvent = bytemuck::pod_read_unaligned(bytemuck::bytes_of(&event));
        assert_eq!(decoded.tid, 42);
        assert_eq!(decoded.family, AF_INET);
        assert_eq!(decoded.sport, 1234);
        assert_eq!(decoded.rtt_us, 1500);
        assert_eq!(decoded.daddr[0], 10);
    }

    #[test]
    fn offcpu_event_layout_is_stable() {
        assert_eq!(size_of::<OffCpuEvent>(), 32);
        assert_eq!(align_of::<OffCpuEvent>(), 8);
    }

    #[test]
    fn offcpu_pending_layout_is_stable() {
        assert_eq!(size_of::<OffCpuPending>(), 24);
        assert_eq!(align_of::<OffCpuPending>(), 8);
    }

    #[test]
    fn offcpu_pending_round_trips_through_bytes() {
        let pending = OffCpuPending {
            start_ns: 1_000,
            stack_id: -3,
            reason: OFFCPU_REASON_IO,
            _pad: 0,
        };
        let decoded: OffCpuPending = bytemuck::pod_read_unaligned(bytemuck::bytes_of(&pending));
        assert_eq!(decoded.start_ns, 1_000);
        assert_eq!(decoded.stack_id, -3);
        assert_eq!(decoded.reason, OFFCPU_REASON_IO);
    }

    #[test]
    fn memory_counters_layout_is_stable() {
        assert_eq!(size_of::<MemoryCounters>(), 16);
        assert_eq!(align_of::<MemoryCounters>(), 8);
    }

    #[test]
    fn memory_counters_round_trip_through_bytes() {
        let counters = MemoryCounters {
            faults: 12_345,
            reclaims: 7,
        };
        let decoded: MemoryCounters = bytemuck::pod_read_unaligned(bytemuck::bytes_of(&counters));
        assert_eq!(decoded.faults, 12_345);
        assert_eq!(decoded.reclaims, 7);
    }
}
