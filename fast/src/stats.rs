use std::collections::BTreeMap;

use fast_common::{SLOW_1MS_NS, SLOW_10MS_NS, SLOW_50MS_NS, SchedulerLatencyEvent};

#[derive(Debug, Default)]
pub struct Statistics {
    latencies: Vec<u64>,
    by_cpu: BTreeMap<u32, Vec<u64>>,
    slow_1ms: u64,
    slow_10ms: u64,
    slow_50ms: u64,
    lost_events: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Summary {
    pub count: usize,
    pub p50_ns: u64,
    pub p95_ns: u64,
    pub p99_ns: u64,
    pub max_ns: u64,
}

impl Statistics {
    pub fn record(&mut self, event: SchedulerLatencyEvent) {
        let latency = event.latency_ns;
        self.latencies.push(latency);
        self.by_cpu.entry(event.run_cpu).or_default().push(latency);

        if latency > SLOW_1MS_NS {
            self.slow_1ms += 1;
        }
        if latency > SLOW_10MS_NS {
            self.slow_10ms += 1;
        }
        if latency > SLOW_50MS_NS {
            self.slow_50ms += 1;
        }
    }

    pub fn record_lost(&mut self, count: u64) {
        self.lost_events = self.lost_events.saturating_add(count);
    }

    pub fn summary(&self) -> Option<Summary> {
        summary(&self.latencies)
    }

    pub fn cpu_summaries(&self) -> impl Iterator<Item = (u32, Summary)> + '_ {
        self.by_cpu
            .iter()
            .filter_map(|(&cpu, latencies)| summary(latencies).map(|summary| (cpu, summary)))
    }

    pub fn slow_1ms(&self) -> u64 {
        self.slow_1ms
    }

    pub fn slow_10ms(&self) -> u64 {
        self.slow_10ms
    }

    pub fn slow_50ms(&self) -> u64 {
        self.slow_50ms
    }

    pub fn sample_count(&self) -> usize {
        self.latencies.len()
    }

    pub fn lost_events(&self) -> u64 {
        self.lost_events
    }
}

fn summary(values: &[u64]) -> Option<Summary> {
    if values.is_empty() {
        return None;
    }

    let mut sorted = values.to_vec();
    sorted.sort_unstable();
    Some(Summary {
        count: sorted.len(),
        p50_ns: nearest_rank(&sorted, 50),
        p95_ns: nearest_rank(&sorted, 95),
        p99_ns: nearest_rank(&sorted, 99),
        max_ns: *sorted.last().expect("non-empty values have a maximum"),
    })
}

fn nearest_rank(sorted: &[u64], percentile: usize) -> u64 {
    let rank = sorted.len().saturating_mul(percentile).saturating_add(99) / 100;
    sorted[rank.saturating_sub(1)]
}

#[cfg(test)]
mod tests {
    use super::*;

    fn event(latency_ns: u64, run_cpu: u32) -> SchedulerLatencyEvent {
        SchedulerLatencyEvent {
            latency_ns,
            wake_ns: 0,
            run_ns: latency_ns,
            tid: 1,
            wake_cpu: 0,
            run_cpu,
            reserved: 0,
        }
    }

    #[test]
    fn computes_nearest_rank_percentiles() {
        let mut stats = Statistics::default();
        for latency in [40, 10, 30, 20] {
            stats.record(event(latency, 0));
        }

        assert_eq!(
            stats.summary(),
            Some(Summary {
                count: 4,
                p50_ns: 20,
                p95_ns: 40,
                p99_ns: 40,
                max_ns: 40,
            })
        );
    }

    #[test]
    fn computes_cpu_summaries() {
        let mut stats = Statistics::default();
        stats.record(event(10, 2));
        stats.record(event(30, 2));
        stats.record(event(20, 4));

        let summaries: Vec<_> = stats.cpu_summaries().collect();
        assert_eq!(summaries[0].0, 2);
        assert_eq!(summaries[0].1.count, 2);
        assert_eq!(summaries[1].0, 4);
        assert_eq!(summaries[1].1.count, 1);
    }

    #[test]
    fn counts_slow_events_and_losses() {
        let mut stats = Statistics::default();
        stats.record(event(SLOW_1MS_NS + 1, 0));
        stats.record(event(SLOW_10MS_NS + 1, 0));
        stats.record(event(SLOW_50MS_NS + 1, 0));
        stats.record_lost(2);

        assert_eq!(stats.slow_1ms(), 3);
        assert_eq!(stats.slow_10ms(), 2);
        assert_eq!(stats.slow_50ms(), 1);
        assert_eq!(stats.lost_events(), 2);
    }

    #[test]
    fn empty_statistics_have_no_summary() {
        assert!(Statistics::default().summary().is_none());
    }
}
