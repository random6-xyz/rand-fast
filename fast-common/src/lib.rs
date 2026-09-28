#![no_std]

use bytemuck::{Pod, Zeroable};

/// Map-facing types need to satisfy aya's `Pod` marker so the userspace crate
/// can put them into aya maps. Implemented only under the opt-in `aya`
/// feature because the eBPF build must not link aya.
#[cfg(feature = "aya")]
mod aya_pod {
    unsafe impl aya::Pod for crate::PendingIo {}
    unsafe impl aya::Pod for crate::IoRequestKey {}
    unsafe impl aya::Pod for crate::OffCpuPending {}
}

pub const MAX_TARGET_TIDS: u32 = 4096;
/// Upper bound for in-flight per-request I/O entries. Only target-issued
/// requests enter the map, so this is generous headroom over any realistic
/// queue depth.
pub const MAX_PENDING_IO: u32 = 8192;
/// Upper bound for remembered TCP sockets. Entries are added only for sockets
/// a target thread is seen using, so this is generous headroom over the
/// number of connections a process keeps open.
pub const MAX_TCP_SOCKETS: u32 = 8192;
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
/// `block_rq_complete`. `op` is the operation code derived from the trace's
/// rwbs field: 0 read, 1 write, 2 anything else (see [`io_op_name`]).
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Pod, Zeroable)]
pub struct PendingIo {
    pub start_ns: u64,
    pub tid: u32,
    pub op: u32,
}

/// Identity of one in-flight block request: the device and its start sector.
///
/// `block_rq_issue` and `block_rq_complete` both carry these fields in their
/// tracepoint payloads, which makes the pair a portable request key. The
/// request pointer is not reachable from `BPF_PROG_TYPE_TRACEPOINT` programs
/// (only raw/BTF tracepoints expose TP_PROTO arguments), so the pair stands
/// in for it: an in-flight request is uniquely identified by where it starts.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Pod, Zeroable)]
pub struct IoRequestKey {
    pub dev: u32,
    pub _pad: u32,
    pub sector: u64,
}

/// Human-readable name for the operation code stored in I/O events. The
/// eBPF side derives it from the rwbs field's first character: 0 read,
/// 1 write, 2 anything else (discard, zone ops, ...).
pub fn io_op_name(op: u32) -> &'static str {
    match op {
        0 => "read",
        1 => "write",
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

/// I/O latency event attributed to a thread and block device.
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

/// Memory pressure snapshot.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Pod, Zeroable)]
pub struct MemoryEvent {
    pub minflt: u64,
    pub majflt: u64,
    pub swap_kb: u64,
    pub tid: u32,
    pub psi_some_pct: u32,
    pub psi_full_pct: u32,
    pub _pad: u32,
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
    fn io_request_key_layout_is_stable() {
        assert_eq!(size_of::<IoRequestKey>(), 16);
        assert_eq!(align_of::<IoRequestKey>(), 8);
    }

    #[test]
    fn io_op_names() {
        assert_eq!(io_op_name(0), "read");
        assert_eq!(io_op_name(1), "write");
        assert_eq!(io_op_name(2), "other");
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
    fn memory_event_layout_is_stable() {
        assert_eq!(size_of::<MemoryEvent>(), 40);
        assert_eq!(align_of::<MemoryEvent>(), 8);
    }
}
