#![no_std]

use bytemuck::{Pod, Zeroable};

/// Map-facing types need to satisfy aya's `Pod` marker so the userspace crate
/// can put them into aya maps. Implemented only under the opt-in `aya`
/// feature because the eBPF build must not link aya.
#[cfg(feature = "aya")]
mod aya_pod {
    unsafe impl aya::Pod for crate::PendingIo {}
}

pub const MAX_TARGET_TIDS: u32 = 4096;
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
/// `block_rq_complete`. `cmd_flags` is the raw request flag word; the
/// operation occupies its high 8 bits (see [`io_op_name`]).
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Pod, Zeroable)]
pub struct PendingIo {
    pub start_ns: u64,
    pub tid: u32,
    pub cmd_flags: u32,
}

/// Human-readable name for a block request operation code (the high 8 bits
/// of the tracepoint's `cmd_flags`), matching the kernel's `req_op` values.
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

/// TCP/network event for RTT and retransmission.
#[repr(C)]
#[derive(Clone, Copy, Debug, Pod, Zeroable)]
pub struct TcpEvent {
    pub tid: u32,
    pub saddr: u32,
    pub daddr: u32,
    pub rtt_us: u32,
    pub sport: u16,
    pub dport: u16,
    pub retrans: u8,
    pub _pad: [u8; 3],
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
    fn io_op_names() {
        assert_eq!(io_op_name(0), "read");
        assert_eq!(io_op_name(1), "write");
        assert_eq!(io_op_name(2), "other");
    }

    #[test]
    fn io_event_layout_is_stable() {
        assert_eq!(size_of::<IoEvent>(), 24);
        assert_eq!(align_of::<IoEvent>(), 8);
    }

    #[test]
    fn tcp_event_layout_is_stable() {
        assert_eq!(size_of::<TcpEvent>(), 24);
        assert_eq!(align_of::<TcpEvent>(), 4);
    }

    #[test]
    fn offcpu_event_layout_is_stable() {
        assert_eq!(size_of::<OffCpuEvent>(), 32);
        assert_eq!(align_of::<OffCpuEvent>(), 8);
    }

    #[test]
    fn memory_event_layout_is_stable() {
        assert_eq!(size_of::<MemoryEvent>(), 40);
        assert_eq!(align_of::<MemoryEvent>(), 8);
    }
}
