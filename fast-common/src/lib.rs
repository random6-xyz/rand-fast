#![no_std]

use bytemuck::{Pod, Zeroable};

pub const MAX_TARGET_TIDS: u32 = 4096;

pub const SLOW_1MS_NS: u64 = 1_000_000;
pub const SLOW_10MS_NS: u64 = 10_000_000;
pub const SLOW_50MS_NS: u64 = 50_000_000;

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
}
