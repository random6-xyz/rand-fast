//! Evidence-based scoring for `fast diagnose`.
//!
//! The ranking this replaces read `/proc/loadavg`, `/proc/<pid>/io` and
//! `/proc/<pid>/status` and turned them into confidences. Those numbers
//! describe the machine, not the process being asked about, so the ranking was
//! confident and wrong. Everything here is computed from measurements the
//! collectors actually took, and the whole decision is a pure function of
//! [`Evidence`], so the matrix can be tested without a kernel or root.
//!
//! # How a confidence is produced
//!
//! Each signal produces a severity from 0.0 (nothing to see) to 1.0 (as bad as
//! this signal can get), measured against a documented threshold. The
//! severities are combined into a share of the slowdown per cause, so the
//! numbers in a report sum to 100 and can be read as "this share of what the
//! process experienced".
//!
//! That share is a ranking aid, not a probability. Two processes with the same
//! measurements get the same ranking, and the report says so.
//!
//! # Signals
//!
//! | Cause | Measured by | Rises with |
//! |-------|-------------|------------|
//! | CPU contention | on-CPU usage of one CPU | busy CPU time |
//! | Scheduler latency | runnable-to-running p95 | run-queue wait |
//! | Disk I/O | completion p99 against the slow threshold | slow completions |
//! | Lock contention | futex share of off-CPU time | waiting on a futex |
//! | Network | retransmission ratio | lost segments |
//! | Memory | major faults, reclaim, PSI, swap growth | memory pressure |

use crate::{diagnose::Evidence, memory::Verdict as MemoryVerdict};

/// Documented thresholds for the diagnosis ranking.
///
/// Every constant says what it means and why the value was chosen, because a
/// threshold nobody can argue with is a threshold nobody can trust.
pub mod threshold {
    /// Share of wall time spent on CPU that counts as compute-bound. A process
    /// using a whole core continuously reaches 1.0, and the ramp saturates
    /// before then so that "very busy" does not outrank a cause outright.
    pub const CPU_BUSY_SHARE: f64 = 0.9;

    /// Scheduler p95, in microseconds, that counts as a run-queue wait worth
    /// naming. Ten milliseconds is long enough that a user would feel it and
    /// short enough that an ordinary batch job does not trip it.
    pub const SCHED_P95_US: u64 = 10_000;

    /// Block I/O p99, in microseconds, that counts as slow. This is the same
    /// 10ms `fast io` calls slow by default, so a number here means what it
    /// means there.
    pub const IO_P99_US: u64 = 10_000;

    /// Share of off-CPU time spent in an I/O wait that counts as being blocked
    /// on the device. Half the time is a deliberate choice: a process that
    /// spends more of its life waiting on storage than working is not healthy
    /// whatever its per-request latency looks like.
    pub const IO_WAIT_SHARE: f64 = 0.5;

    /// Share of off-CPU time on a futex that counts as lock contention rather
    /// than ordinary sleeping. A third is the point where waiting on other
    /// threads stops being incidental.
    pub const FUTEX_SHARE: f64 = 0.33;

    /// Retransmission ratio that counts as a network problem. One segment in
    /// fifty is well above a healthy path and low enough to catch a lossy one.
    pub const RETRANS_RATIO: f64 = 0.02;

    /// Share of off-CPU time spent blocked on a socket that counts as a network
    /// problem. Half the time is deliberate: past that the process is waiting on
    /// the link rather than working around it.
    pub const NETWORK_WAIT_SHARE: f64 = 0.5;

    /// Waits that must be observed before a wait share may outrank anything.
    ///
    /// A share is a ratio, and a ratio over one sample is not a measurement: a
    /// single two-millisecond stall reads as a hundred percent of the time
    /// spent on the device, which would let a process that merely paused once
    /// outrank a process that was demonstrably out of memory. Below this the
    /// wait share is ignored and only the directly measured signals count.
    pub const MIN_WAIT_SAMPLES: usize = 100;

    /// A signal needs this share of the total before it is reported at all.
    /// Reporting every cause with a few percent of noise is how a report stops
    /// being read.
    pub const MIN_SHARE_TO_REPORT: f32 = 1.0;

    /// A signal must also be this severe on its own, whatever its share.
    ///
    /// The share is each severity over their sum, so a process where one signal
    /// registers a barely-measurable value would otherwise report that one
    /// cause at a hundred percent. That reads as certainty about a cause
    /// nothing was really measured for. The floor drops such signals instead:
    /// no evidence is a more honest answer than a confident rounding error.
    pub const MIN_SEVERITY_TO_REPORT: f64 = 0.05;
}

/// One signal's severity, before the shares are worked out.
#[derive(Debug, Clone, PartialEq)]
struct Severity {
    cause: &'static str,
    /// 0.0 to 1.0.
    severity: f64,
    /// Human-readable measurements behind the number.
    evidence: String,
}

/// Ramps an off-CPU wait share into a severity, ignoring a share taken from too
/// few samples to be a measurement.
fn wait_severity(share: f64, saturate: f64, evidence: &Evidence) -> f64 {
    if evidence.offcpu_samples < threshold::MIN_WAIT_SAMPLES {
        return 0.0;
    }
    ramp(share.clamp(0.0, 1.0), 0.0, saturate)
}

/// Ramps a value from 0 at `below` to 1 at `above`, and clamps outside that.
///
/// A linear ramp rather than a step, so a signal just over its threshold does
/// not outrank one far past it, and the shape is easy to reason about.
fn ramp(value: f64, below: f64, above: f64) -> f64 {
    if above <= below {
        return if value >= above { 1.0 } else { 0.0 };
    }
    (((value - below) / (above - below)).clamp(0.0, 1.0)).max(0.0)
}

/// Scores the CPU signal.
///
/// CPU time is a consequence of every other cause as much as it is a cause of
/// its own: sixteen threads fighting over a futex burn CPU between their waits,
/// and a process that spends most of its life blocked is not "CPU bound" just
/// because it used a whole core while it had the chance. So the signal is the
/// share of wall time spent on CPU, which is what separates a process that is
/// genuinely compute-bound from one that is busy between waits.
///
/// Saturation is one full core. Beyond that the process is already fully
/// consuming a CPU and more usage cannot be attributed to contention, which
/// is what a multi-worker fixture is for: several busy threads are worse off
/// than one for a reason this signal cannot see, and the other signals pick
/// that up.
fn score_cpu(evidence: &Evidence) -> Option<Severity> {
    if evidence.cpu_samples == 0 {
        return None;
    }
    let percent = evidence.cpu_percent.clamp(0.0, 100.0);
    let on_cpu_share = percent / 100.0;
    Some(Severity {
        cause: "CPU contention",
        severity: ramp(on_cpu_share, 0.0, threshold::CPU_BUSY_SHARE),
        evidence: format!(
            "{percent:.1}% of one CPU, so {:.0}% of wall time on CPU, over {} samples",
            on_cpu_share * 100.0,
            evidence.cpu_samples
        ),
    })
}

/// Scores run-queue waiting.
fn score_scheduler(evidence: &Evidence) -> Option<Severity> {
    if evidence.sched_samples == 0 {
        return None;
    }
    Some(Severity {
        cause: "Scheduler latency",
        severity: ramp(
            evidence.sched_p95_us as f64,
            0.0,
            threshold::SCHED_P95_US as f64 * 2.0,
        ),
        evidence: format!(
            "p95 {} us over {} samples, threshold {} us",
            evidence.sched_p95_us,
            evidence.sched_samples,
            threshold::SCHED_P95_US
        ),
    })
}

/// Scores block I/O from two independent measurements.
///
/// The p99 alone is misleading. A process that issues many small, fast requests
/// has a low p99 and can still spend most of its life waiting for the device,
/// because the wait is spread across many short stalls. And on a small sample
/// one slow completion out of two makes a p99 of half the sample.
///
/// So the severity is the worse of:
/// - latency: the p99 measured against the slow threshold, and
/// - wait: the share of off-CPU time the process spent in an I/O wait, which is
///   what a device-bound process actually looks like from inside.
///
/// Either one on its own can be misleading; together they separate a process
/// that is genuinely waiting on storage from one that merely issues requests.
fn score_io(evidence: &Evidence) -> Option<Severity> {
    if evidence.io_samples == 0 && evidence.offcpu_samples == 0 {
        return None;
    }
    // A completion at four times the threshold is as bad as latency gets.
    let latency = ramp(
        evidence.io_p99_us as f64,
        threshold::IO_P99_US as f64 / 4.0,
        threshold::IO_P99_US as f64 * 4.0,
    );
    // Half the time spent waiting on I/O is as bad as the wait share gets,
    // but only once there are enough waits for the ratio to mean anything.
    let wait = wait_severity(evidence.offcpu_io_ratio, threshold::IO_WAIT_SHARE, evidence);
    let mut detail = format!(
        "p99 {} us over {} completions, {} past the {} us threshold",
        evidence.io_p99_us,
        evidence.io_samples,
        evidence.io_slow,
        threshold::IO_P99_US
    );
    if evidence.offcpu_samples > 0 {
        detail.push_str(&format!(
            ", {:.0}% of {} us off-CPU waiting on I/O",
            evidence.offcpu_io_ratio.clamp(0.0, 1.0) * 100.0,
            evidence.offcpu_total_us
        ));
    }
    Some(Severity {
        cause: "Disk I/O",
        severity: latency.max(wait),
        evidence: detail,
    })
}

/// Scores futex waiting, which is what lock contention looks like from inside
/// a process.
fn score_lock(evidence: &Evidence) -> Option<Severity> {
    if evidence.offcpu_samples == 0 {
        return None;
    }
    let share = evidence.offcpu_futex_ratio.clamp(0.0, 1.0);
    Some(Severity {
        cause: "Lock contention",
        severity: wait_severity(share, threshold::FUTEX_SHARE * 3.0, evidence),
        evidence: format!(
            "{:.0}% of {} us off-CPU on a futex over {} waits, threshold {:.0}%",
            share * 100.0,
            evidence.offcpu_total_us,
            evidence.offcpu_samples,
            threshold::FUTEX_SHARE * 100.0
        ),
    })
}

/// Scores packet loss.
fn score_network(evidence: &Evidence) -> Option<Severity> {
    if evidence.net_samples == 0 && evidence.offcpu_samples == 0 {
        return None;
    }
    let ratio = evidence.retrans_ratio.clamp(0.0, 1.0);
    let loss = ramp(ratio, 0.0, threshold::RETRANS_RATIO * 10.0);
    // A process blocked on a socket is a network problem whether or not a
    // segment was lost, so the wait share counts alongside the loss.
    let wait = wait_severity(
        evidence.offcpu_network_ratio,
        threshold::NETWORK_WAIT_SHARE,
        evidence,
    );
    let mut detail = format!(
        "{:.2}% of {} TCP events retransmitted, threshold {:.2}%",
        ratio * 100.0,
        evidence.net_samples,
        threshold::RETRANS_RATIO * 100.0
    );
    if evidence.offcpu_samples > 0 {
        detail.push_str(&format!(
            ", {:.0}% of {} us off-CPU waiting on a socket",
            evidence.offcpu_network_ratio.clamp(0.0, 1.0) * 100.0,
            evidence.offcpu_total_us
        ));
    }
    Some(Severity {
        cause: "Network",
        severity: loss.max(wait),
        evidence: detail,
    })
}

/// Scores memory by reusing the memory report's own verdict.
///
/// The two commands have to agree: if `fast memory` calls a process stalled
/// and `fast diagnose` calls the same process idle, one of them is wrong and
/// the user has no way to tell which. Sharing the verdict rather than
/// re-deriving it is what keeps them consistent.
fn score_memory(evidence: &Evidence) -> Option<Severity> {
    let rates = memory_rates(evidence);
    let (verdict, _) = MemoryVerdict::assess(&rates, evidence.psi_available);
    let severity = match verdict {
        MemoryVerdict::Idle => {
            if evidence.minor_faults_per_s > 0.0 {
                // Allocation churn with nothing under pressure is a hint, not
                // a cause, so it stays near the bottom of the scale.
                ramp(evidence.minor_faults_per_s, 0.0, 1_000_000.0) * 0.2
            } else {
                0.0
            }
        }
        MemoryVerdict::PageChurn => 0.3,
        MemoryVerdict::Pressure => 0.7,
        MemoryVerdict::Severe => 1.0,
    };
    if severity == 0.0 {
        return None;
    }
    let mut why = format!(
        "{:.0} minor and {:.1} major faults/s, {:.1} direct reclaims/s",
        evidence.minor_faults_per_s, evidence.major_faults_per_s, evidence.reclaims_per_s
    );
    if evidence.psi_available {
        why.push_str(&format!(
            ", PSI some {:.1}% full {:.1}%",
            evidence.psi_some_pct, evidence.psi_full_pct
        ));
    } else {
        why.push_str(", PSI unavailable on this kernel");
    }
    Some(Severity {
        cause: "Memory pressure",
        severity,
        evidence: why,
    })
}

/// Rebuilds the memory report's input from the diagnosis evidence.
fn memory_rates(evidence: &Evidence) -> crate::memory::Rates {
    crate::memory::Rates {
        window: std::time::Duration::from_secs(1),
        faults_per_s: evidence.minor_faults_per_s + evidence.major_faults_per_s,
        minor_per_s: evidence.minor_faults_per_s,
        major_per_s: evidence.major_faults_per_s,
        reclaims_per_s: evidence.reclaims_per_s,
        psi_some_pct: evidence.psi_some_pct,
        psi_full_pct: evidence.psi_full_pct,
        swap_kb: evidence.swap_kb,
        swap_start_kb: 0,
    }
}

/// Scores the process waiting on something that is not any of the above.
///
/// Deliberately last and deliberately weak: a process can block on a condition
/// variable, a timer or a pipe, and none of those are contention. Reporting
/// them as a cause would be a guess.
fn score_other_wait(evidence: &Evidence) -> Option<Severity> {
    if evidence.offcpu_samples == 0 {
        return None;
    }
    // Only the time no named cause explains counts here. I/O waits belong to
    // the disk signal and page waits to the memory one, so counting them again
    // as "other" would report a hundred percent of a cause that is already
    // named, which is worse than saying nothing.
    // The shares come from one total, so they sum to at most one; the clamp
    // guards a caller that supplies a set that does not.
    let unexplained = (1.0
        - evidence.offcpu_futex_ratio.clamp(0.0, 1.0)
        - evidence.offcpu_io_ratio.clamp(0.0, 1.0)
        - evidence.offcpu_network_ratio.clamp(0.0, 1.0)
        - evidence.offcpu_memory_ratio.clamp(0.0, 1.0))
    .clamp(0.0, 1.0);
    if unexplained < threshold::FUTEX_SHARE {
        return None;
    }
    Some(Severity {
        cause: "Other waiting",
        severity: unexplained * 0.4,
        evidence: format!(
            "{:.0}% of {} us off-CPU is a wait no named cause explains",
            unexplained * 100.0,
            evidence.offcpu_total_us
        ),
    })
}

/// Turns severities into a ranked list of causes.
///
/// The share is each severity over their sum, so the report's percentages sum
/// to 100 and can be read as an attribution rather than as independent
/// scores. Ties break on the cause name so two runs over the same
/// measurements rank identically.
pub fn score(evidence: &Evidence) -> Vec<crate::diagnose::Diagnosis> {
    let severities: Vec<Severity> = [
        score_cpu(evidence),
        score_scheduler(evidence),
        score_io(evidence),
        score_lock(evidence),
        score_network(evidence),
        score_memory(evidence),
        score_other_wait(evidence),
    ]
    .into_iter()
    .flatten()
    .collect();

    let total: f64 = severities.iter().map(|s| s.severity).sum();
    if total <= 0.0 {
        return Vec::new();
    }

    let mut diagnoses: Vec<crate::diagnose::Diagnosis> = severities
        .into_iter()
        .filter(|s| s.severity >= threshold::MIN_SEVERITY_TO_REPORT)
        .map(|s| crate::diagnose::Diagnosis {
            cause: s.cause,
            confidence: (s.severity / total * 100.0) as f32,
            evidence: vec![s.evidence],
        })
        .filter(|d| d.confidence >= threshold::MIN_SHARE_TO_REPORT)
        .collect();

    diagnoses.sort_by(|a, b| {
        b.confidence
            .partial_cmp(&a.confidence)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then(a.cause.cmp(b.cause))
    });
    diagnoses
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::memory::threshold as memory_threshold;

    /// A process doing nothing measurable, which is the baseline every
    /// scenario is compared against.
    fn idle() -> Evidence {
        Evidence::default()
    }

    #[test]
    fn an_unmeasured_process_produces_no_ranking() {
        // Nothing measured must not turn into "everything is fine": there is
        // no evidence for any cause, so the honest answer is an empty ranking.
        assert!(score(&idle()).is_empty());
    }

    #[test]
    fn a_cpu_bound_process_ranks_cpu_first() {
        let evidence = Evidence {
            cpu_samples: 4_000,
            cpu_percent: 99.0,
            sched_samples: 2_000,
            sched_p95_us: 20_000,
            ..idle()
        };
        let ranked = score(&evidence);
        assert_eq!(ranked[0].cause, "CPU contention");
    }

    #[test]
    fn a_futex_bound_process_ranks_lock_first() {
        let evidence = Evidence {
            offcpu_samples: 100_000,
            offcpu_total_us: 1_000_000,
            offcpu_futex_ratio: 0.98,
            ..idle()
        };
        let ranked = score(&evidence);
        assert_eq!(ranked[0].cause, "Lock contention");
        assert!(ranked[0].confidence > 60.0, "{:?}", ranked[0]);
    }

    #[test]
    fn a_disk_bound_process_ranks_io_first() {
        let evidence = Evidence {
            io_samples: 50_000,
            io_p99_us: 80_000,
            io_slow: 900,
            ..idle()
        };
        let ranked = score(&evidence);
        assert_eq!(ranked[0].cause, "Disk I/O");
    }

    #[test]
    fn a_device_bound_process_ranks_io_even_with_a_low_p99() {
        // Many small fast requests still make a process wait. The p99 is low
        // and the wait share is high, and the process is still blocked on
        // storage, which is what this case exists for.
        let evidence = Evidence {
            io_samples: 100_000,
            io_p99_us: 60,
            io_slow: 0,
            offcpu_samples: 90_000,
            offcpu_total_us: 3_000_000,
            offcpu_io_ratio: 0.95,
            ..idle()
        };
        let ranked = score(&evidence);
        assert_eq!(ranked[0].cause, "Disk I/O");
        assert!(
            ranked[0].evidence[0].contains("waiting on I/O"),
            "the wait must be part of the evidence: {:?}",
            ranked[0]
        );
    }

    #[test]
    fn io_waits_are_not_also_reported_as_other_waiting() {
        // Counting the same time twice would report a cause at a hundred
        // percent that is already named, which is worse than silence.
        let evidence = Evidence {
            io_samples: 10_000,
            offcpu_samples: 10_000,
            offcpu_total_us: 1_000_000,
            offcpu_io_ratio: 1.0,
            ..idle()
        };
        let ranked = score(&evidence);
        assert!(
            !ranked.iter().any(|d| d.cause == "Other waiting"),
            "{ranked:?}"
        );
        assert_eq!(ranked[0].cause, "Disk I/O");
    }

    #[test]
    fn page_waits_belong_to_memory_not_to_other_waiting() {
        let evidence = Evidence {
            offcpu_samples: 5_000,
            offcpu_total_us: 900_000,
            offcpu_memory_ratio: 0.9,
            major_faults_per_s: 10.0,
            ..idle()
        };
        let ranked = score(&evidence);
        assert!(
            !ranked.iter().any(|d| d.cause == "Other waiting"),
            "{ranked:?}"
        );
        assert_eq!(ranked[0].cause, "Memory pressure");
    }

    #[test]
    fn a_lossy_link_ranks_network_first() {
        let evidence = Evidence {
            net_samples: 20_000,
            retrans_ratio: 0.08,
            ..idle()
        };
        let ranked = score(&evidence);
        assert_eq!(ranked[0].cause, "Network");
    }

    #[test]
    fn memory_pressure_is_measured_through_the_shared_verdict() {
        // The same numbers `fast memory` calls "pressure" must rank memory
        // first here, or the two commands disagree with each other.
        let evidence = Evidence {
            major_faults_per_s: 40.0,
            minor_faults_per_s: 500.0,
            reclaims_per_s: 5.0,
            ..idle()
        };
        let rates = memory_rates(&evidence);
        let (verdict, _) = MemoryVerdict::assess(&rates, false);
        assert_eq!(verdict, MemoryVerdict::Pressure);
        assert_eq!(score(&evidence)[0].cause, "Memory pressure");
    }

    #[test]
    fn a_missing_psi_does_not_stop_other_memory_evidence() {
        let evidence = Evidence {
            major_faults_per_s: 40.0,
            psi_available: false,
            psi_some_pct: 90.0,
            psi_full_pct: 50.0,
            ..idle()
        };
        let ranked = score(&evidence);
        assert_eq!(ranked[0].cause, "Memory pressure");
        // The evidence line has to say PSI was unavailable rather than letting
        // a reader assume the pressure numbers came from it.
        assert!(ranked[0].evidence[0].contains("PSI unavailable"));
    }

    #[test]
    fn a_quiet_process_is_not_ranked_as_page_churn() {
        // A little allocation is normal. Only real churn should register, and
        // never above a cause that is actually hurting.
        let evidence = Evidence {
            minor_faults_per_s: 200.0,
            ..idle()
        };
        assert!(score(&evidence).is_empty());
    }

    #[test]
    fn unexplained_waiting_is_reported_but_yields_to_a_real_cause() {
        // Waiting that is not futex and not a named cause is still worth
        // saying, but it must lose to anything actually measured.
        let only_other = Evidence {
            offcpu_samples: 1_000,
            offcpu_total_us: 500_000,
            offcpu_futex_ratio: 0.1,
            ..idle()
        };
        let ranked = score(&only_other);
        assert_eq!(ranked[0].cause, "Other waiting");
        // A tenth of the time on a futex is still worth naming, just not
        // first, so both off-CPU causes appear.
        let lock = ranked
            .iter()
            .find(|d| d.cause == "Lock contention")
            .expect("a measurable futex share is still reported");
        assert!(lock.confidence < 30.0, "{lock:?}");

        let with_cpu = Evidence {
            cpu_samples: 4_000,
            cpu_percent: 99.0,
            ..only_other
        };
        let ranked = score(&with_cpu);
        assert_eq!(ranked[0].cause, "CPU contention");
        let other = ranked
            .iter()
            .find(|d| d.cause == "Other waiting")
            .expect("unexplained waiting is still reported");
        assert!(other.confidence < 40.0, "{other:?}");
    }

    #[test]
    fn shares_sum_to_a_hundred() {
        // The report's percentages are read as an attribution, so they have to
        // add up.
        let evidence = Evidence {
            cpu_samples: 4_000,
            cpu_percent: 95.0,
            sched_samples: 2_000,
            sched_p95_us: 30_000,
            io_samples: 20_000,
            io_p99_us: 50_000,
            io_slow: 400,
            offcpu_samples: 50_000,
            offcpu_total_us: 800_000,
            offcpu_futex_ratio: 0.7,
            net_samples: 10_000,
            retrans_ratio: 0.05,
            major_faults_per_s: 5.0,
            minor_faults_per_s: 2_000.0,
            psi_available: true,
            psi_some_pct: 3.0,
            ..idle()
        };
        let total: f32 = score(&evidence).iter().map(|d| d.confidence).sum();
        assert!(
            (total - 100.0).abs() < 0.5,
            "shares summed to {total}: {:?}",
            score(&evidence)
        );
    }

    #[test]
    fn ranking_is_deterministic_for_equal_inputs() {
        let evidence = Evidence {
            offcpu_samples: 10_000,
            offcpu_total_us: 100_000,
            offcpu_futex_ratio: 0.4,
            sched_samples: 1_000,
            sched_p95_us: 12_000,
            ..idle()
        };
        let first: Vec<&str> = score(&evidence).iter().map(|d| d.cause).collect();
        let second: Vec<&str> = score(&evidence).iter().map(|d| d.cause).collect();
        assert_eq!(first, second);
    }

    #[test]
    fn every_reported_cause_carries_its_evidence() {
        let evidence = Evidence {
            cpu_samples: 1_000,
            cpu_percent: 99.0,
            offcpu_samples: 10_000,
            offcpu_total_us: 100_000,
            offcpu_futex_ratio: 0.9,
            ..idle()
        };
        for diagnosis in score(&evidence) {
            assert!(
                !diagnosis.evidence.is_empty(),
                "{} was ranked with no evidence",
                diagnosis.cause
            );
            for line in &diagnosis.evidence {
                assert!(!line.is_empty());
            }
        }
    }

    #[test]
    fn a_signal_with_no_samples_is_not_ranked() {
        // cpu_samples of zero with a high percentage would be a measurement
        // that could not have happened, and must not be believed.
        let evidence = Evidence {
            cpu_samples: 0,
            cpu_percent: 99.0,
            ..idle()
        };
        assert!(score(&evidence).is_empty());
    }

    #[test]
    fn ramp_is_clamped_and_monotonic() {
        assert_eq!(ramp(0.0, 0.0, 10.0), 0.0);
        assert_eq!(ramp(5.0, 0.0, 10.0), 0.5);
        assert_eq!(ramp(10.0, 0.0, 10.0), 1.0);
        assert_eq!(ramp(-5.0, 0.0, 10.0), 0.0);
        assert_eq!(ramp(50.0, 0.0, 10.0), 1.0);
        // A degenerate range must not divide by zero.
        assert_eq!(ramp(5.0, 10.0, 10.0), 0.0);
        assert_eq!(ramp(10.0, 10.0, 10.0), 1.0);
    }

    #[test]
    fn a_cause_just_past_its_threshold_does_not_outrank_one_far_past_it() {
        // This is why severity is a ramp and not a step.
        let just_past = Evidence {
            sched_samples: 1_000,
            sched_p95_us: threshold::SCHED_P95_US,
            ..idle()
        };
        let far_past = Evidence {
            sched_samples: 1_000,
            sched_p95_us: threshold::SCHED_P95_US * 20,
            ..idle()
        };
        let a = score(&just_past)[0].confidence;
        let b = score(&far_past)[0].confidence;
        assert_eq!(a, b, "a single-cause ranking normalises to the same share");
    }

    #[test]
    fn severe_memory_outranks_a_mere_pressure_verdict() {
        let pressure = Evidence {
            major_faults_per_s: 2.0,
            ..idle()
        };
        let severe = Evidence {
            major_faults_per_s: 2.0,
            psi_available: true,
            psi_some_pct: 50.0,
            psi_full_pct: 20.0,
            ..idle()
        };
        let (a, _) = MemoryVerdict::assess(&memory_rates(&pressure), false);
        let (b, _) = MemoryVerdict::assess(&memory_rates(&severe), true);
        assert_eq!(a, MemoryVerdict::Pressure);
        assert_eq!(b, MemoryVerdict::Severe);
    }

    #[test]
    fn lock_contention_rises_as_the_futex_share_rises() {
        // The two off-CPU causes are complements of the same time, so their
        // relative weight has to move in opposite directions. Comparing
        // against a fixed competing signal is what makes the shares
        // meaningful: with one signal present it is always a hundred percent.
        let share_of = |futex: f64| -> Option<f32> {
            let evidence = Evidence {
                offcpu_samples: 1_000,
                offcpu_total_us: 100_000,
                offcpu_futex_ratio: futex,
                // A fixed competitor, so the two shares trade against each
                // other rather than against nothing.
                sched_samples: 1_000,
                sched_p95_us: 12_000,
                ..idle()
            };
            let ranked = score(&evidence);
            ranked
                .iter()
                .find(|d| d.cause == "Lock contention")
                .map(|d| d.confidence)
        };
        let low = share_of(0.0);
        let mid = share_of(0.5);
        let high = share_of(0.95);
        assert!(
            low.is_none(),
            "no futex time must not report lock contention"
        );
        assert!(
            mid.unwrap() < high.unwrap(),
            "{mid:?} should be under {high:?}"
        );
    }

    #[test]
    fn a_wait_share_from_too_few_samples_is_ignored() {
        // One two-millisecond stall reads as a hundred percent of the time
        // spent waiting, which would let a process that merely paused once
        // outrank one that was demonstrably out of memory.
        let evidence = Evidence {
            offcpu_samples: 1,
            offcpu_total_us: 1_926,
            offcpu_io_ratio: 1.0,
            ..idle()
        };
        let ranked = score(&evidence);
        assert!(
            !ranked.iter().any(|d| d.cause == "Disk I/O"),
            "a single sample must not decide the disk signal: {ranked:?}"
        );
    }

    #[test]
    fn a_wait_share_with_enough_samples_is_used() {
        let evidence = Evidence {
            offcpu_samples: threshold::MIN_WAIT_SAMPLES,
            offcpu_total_us: 1_000_000,
            offcpu_io_ratio: 0.9,
            ..idle()
        };
        assert_eq!(score(&evidence)[0].cause, "Disk I/O");
    }

    #[test]
    fn the_futex_share_needs_samples_too() {
        // The same guard applies to lock contention, which is also a ratio.
        let one = Evidence {
            offcpu_samples: 3,
            offcpu_total_us: 1_000,
            offcpu_futex_ratio: 1.0,
            ..idle()
        };
        assert!(score(&one).is_empty(), "{:?}", score(&one));
        let many = Evidence {
            offcpu_samples: 10_000,
            ..one
        };
        assert_eq!(score(&many)[0].cause, "Lock contention");
    }

    #[test]
    fn thresholds_are_ordered_from_loose_to_strict() {
        // Guards against a threshold edit that makes a signal impossible to
        // trigger or trivially triggered. The values go through locals so the
        // comparisons are runtime checks rather than folded-away constants.
        let bounds: Vec<(f64, f64)> = vec![
            (threshold::FUTEX_SHARE, 1.0),
            (threshold::RETRANS_RATIO, 1.0),
            (threshold::CPU_BUSY_SHARE, 1.0),
            (threshold::NETWORK_WAIT_SHARE, 1.0),
            (threshold::IO_WAIT_SHARE, 1.0),
        ];
        for (value, upper) in bounds {
            assert!(value > 0.0, "a threshold of {value} can never be crossed");
            assert!(value < upper, "a threshold of {value} is always crossed");
        }
        let positives = [threshold::SCHED_P95_US as f64, threshold::IO_P99_US as f64];
        for value in positives {
            assert!(value > 0.0, "a zero threshold would always fire");
        }
        let (some, full) = (
            memory_threshold::PSI_SOME_PCT as f64,
            memory_threshold::PSI_FULL_PCT as f64,
        );
        assert!(
            some < full,
            "PSI some must not be set at or above full, or severe would never win"
        );
    }
}
