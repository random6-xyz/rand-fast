//! What makes the flight recorder decide to write an incident.
//!
//! # Why a list rather than one threshold
//!
//! A slow server is slow for different reasons, and a recorder that only
//! watches one signal has a failure mode that looks like success: on a host
//! that is stalling on network retransmissions with a healthy scheduler, a
//! scheduler-only trigger never fires and the operator is told the machine was
//! fine. So the triggers are an OR-list over every signal the recorder already
//! measures, and the incident records *which* one fired rather than only that
//! something did.
//!
//! # Thresholds are opt-out
//!
//! Every trigger has a default, and any of them can be turned off with `off`.
//! The defaults are chosen to be well above an idle machine and well below a
//! genuinely bad interval; they are not tuned per host, because a recorder
//! that needs host-specific tuning is a recorder that will not be tuned.
//!
//! # An absent signal never fires
//!
//! A threshold of zero would fire on every interval, so a disabled trigger is
//! represented as no threshold at all rather than as a zero. This matters for
//! more than tidiness: a kernel built without `CONFIG_PSI` reports no pressure
//! data, and a trigger that treats missing data as "no pressure" would either
//! fire constantly or quietly claim a healthy machine. Neither is true, and
//! [`Trigger::evaluate`] returns nothing for a signal it could not read.

use crate::cli::DaemonArgs;

/// One signal the recorder watches, with the interval value that trips it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Signal {
    /// Scheduler latency p95 for the interval.
    SchedulerP95,
    /// Block I/O latency p99 for the interval.
    IoP99,
    /// Retransmissions during the interval.
    Retransmissions,
    /// Memory pressure "some" at the end of the interval, in percent.
    PsiSome,
    /// Memory pressure "full" at the end of the interval, in percent.
    PsiFull,
    /// On-CPU usage for the interval, as a percentage of one CPU.
    CpuUsage,
}

impl std::fmt::Display for Signal {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.name())
    }
}

impl Signal {
    /// The name used in output, JSON and incident files.
    pub const fn name(self) -> &'static str {
        match self {
            Signal::SchedulerP95 => "sched_p95",
            Signal::IoP99 => "io_p99",
            Signal::Retransmissions => "retrans",
            Signal::PsiSome => "psi_some",
            Signal::PsiFull => "psi_full",
            Signal::CpuUsage => "cpu_usage",
        }
    }

    /// The unit the threshold is expressed in, for the incident record.
    ///
    /// Written out rather than implied, because a bare number in a bundle
    /// collected hours later is the part most likely to be misread.
    pub const fn unit(self) -> &'static str {
        match self {
            Signal::SchedulerP95 | Signal::IoP99 => "microseconds",
            Signal::Retransmissions => "count",
            Signal::PsiSome | Signal::PsiFull | Signal::CpuUsage => "percent",
        }
    }

    /// The threshold this signal fires at, in microseconds, count, or percent.
    pub fn threshold(self, triggers: &Triggers) -> Option<f64> {
        match self {
            Signal::SchedulerP95 => triggers.sched_p95_us.map(|value| value as f64),
            Signal::IoP99 => triggers.io_p99_us.map(|value| value as f64),
            Signal::Retransmissions => triggers.retrans.map(|value| value as f64),
            Signal::PsiSome => triggers.psi_some_pct,
            Signal::PsiFull => triggers.psi_full_pct,
            Signal::CpuUsage => triggers.cpu_percent,
        }
    }

    /// Every signal, in the order they are reported.
    pub const ALL: [Signal; 6] = [
        Signal::SchedulerP95,
        Signal::IoP99,
        Signal::Retransmissions,
        Signal::PsiSome,
        Signal::PsiFull,
        Signal::CpuUsage,
    ];
}

/// The OR-list of thresholds that make the recorder write an incident.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Triggers {
    /// Scheduler latency p95 threshold, in microseconds. `None` disables it.
    pub sched_p95_us: Option<u64>,
    /// Block I/O latency p99 threshold, in microseconds. `None` disables it.
    pub io_p99_us: Option<u64>,
    /// Retransmissions per interval that count as a burst. `None` disables it.
    pub retrans: Option<u64>,
    /// Memory "some" pressure threshold, in percent. `None` disables it.
    pub psi_some_pct: Option<f64>,
    /// Memory "full" pressure threshold, in percent. `None` disables it.
    pub psi_full_pct: Option<f64>,
    /// On-CPU usage threshold, as a percentage of one CPU. `None` disables it.
    pub cpu_percent: Option<f64>,
}

impl Triggers {
    /// Reads the thresholds from the command line.
    pub fn from_args(args: &DaemonArgs) -> Self {
        Triggers {
            sched_p95_us: args.trigger_sched_p95.micros(),
            io_p99_us: args.trigger_io_p99.micros(),
            retrans: args.trigger_retrans.count(),
            psi_some_pct: args.trigger_psi_some.percent(),
            psi_full_pct: args.trigger_psi_full.percent(),
            cpu_percent: args.trigger_cpu.percent(),
        }
    }

    /// The signals that are switched on.
    pub fn enabled(&self) -> Vec<Signal> {
        Signal::ALL
            .into_iter()
            .filter(|signal| signal.threshold(self).is_some())
            .collect()
    }

    /// Checks one interval's measurements against every enabled trigger.
    ///
    /// Returns the signals that fired, most severe first, so an incident names
    /// the thing that actually went wrong rather than the first threshold in a
    /// list that happened to be checked first.
    pub fn evaluate(&self, entry: &Interval) -> Vec<Signal> {
        let mut fired: Vec<(f64, Signal)> = Signal::ALL
            .into_iter()
            .filter_map(|signal| {
                let threshold = signal.threshold(self)?;
                // A measured value of zero is below any positive threshold, and
                // an unreadable one is not compared at all: Option::zip is what
                // keeps a missing PSI reading from being treated as zero.
                let value = entry.read(signal)?;
                (value >= threshold).then_some((ratio(value, threshold), signal))
            })
            .collect();
        fired.sort_by(|left, right| {
            right
                .0
                .partial_cmp(&left.0)
                .unwrap_or(std::cmp::Ordering::Equal)
                .then(right.1.cmp(&left.1))
        });
        fired.into_iter().map(|(_, signal)| signal).collect()
    }
}

/// How far past its threshold a signal is, as a ratio.
///
/// Used only for ordering, so an overflow to infinity is acceptable and better
/// than a wrong sort: a signal 10,000 times over its threshold still belongs
/// at the top.
fn ratio(value: f64, threshold: f64) -> f64 {
    value / threshold
}

/// One interval's measurements, as the triggers need to see them.
///
/// Separate from the ring entry on purpose: the ring carries what an operator
/// reads, and this carries only what a threshold is compared against. Keeping
/// them apart means a field added to the ring for display cannot quietly become
/// part of a trigger decision.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Interval {
    /// Scheduler latency p95 for the interval, in microseconds.
    pub sched_p95_us: u64,
    /// Scheduler samples, so a percentile over a handful of samples can be held
    /// to a minimum sample count.
    pub sched_samples: u64,
    /// Block I/O latency p99 for the interval, in microseconds.
    pub io_p99_us: u64,
    /// Block I/O completions over the interval.
    pub io_samples: u64,
    /// Retransmissions during the interval.
    pub retrans: u64,
    /// Memory "some" pressure, absent when the kernel reports none.
    pub psi_some_pct: Option<f64>,
    /// Memory "full" pressure, absent when the kernel reports none.
    pub psi_full_pct: Option<f64>,
    /// On-CPU usage for the interval, as a percentage of one CPU.
    pub cpu_percent: Option<f64>,
}

impl Interval {
    /// The measured value for one signal, or `None` when it was not readable.
    ///
    /// A signal that is enabled but whose interval carried no samples is
    /// deliberately *not* treated as a reading of zero. A percentile over no
    /// samples has no value, and pretending it is zero is how a recorder
    /// claims a machine was healthy because it measured nothing.
    pub fn read(&self, signal: Signal) -> Option<f64> {
        match signal {
            Signal::SchedulerP95 => (self.sched_samples > 0).then_some(self.sched_p95_us as f64),
            Signal::IoP99 => (self.io_samples > 0).then_some(self.io_p99_us as f64),
            // A retransmission count is a count, so zero is a real reading: a
            // count of nothing in this interval is an answer, not a silence.
            Signal::Retransmissions => Some(self.retrans as f64),
            Signal::PsiSome => self.psi_some_pct,
            Signal::PsiFull => self.psi_full_pct,
            Signal::CpuUsage => self.cpu_percent,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn all_on() -> Triggers {
        Triggers {
            sched_p95_us: Some(10_000),
            io_p99_us: Some(25_000),
            retrans: Some(8),
            psi_some_pct: Some(10.0),
            psi_full_pct: Some(5.0),
            cpu_percent: Some(80.0),
        }
    }

    #[test]
    fn a_quiet_interval_fires_nothing() {
        let entry = Interval {
            sched_p95_us: 40,
            sched_samples: 900,
            io_p99_us: 100,
            io_samples: 40,
            retrans: 0,
            psi_some_pct: Some(0.0),
            psi_full_pct: Some(0.0),
            cpu_percent: Some(3.0),
        };
        assert_eq!(all_on().evaluate(&entry), Vec::new());
    }

    #[test]
    fn each_signal_fires_on_its_own_measurement() {
        // The acceptance criterion of the issue, as a table: a slow disk must
        // trip the I/O trigger and nothing else, so a recorder that fires every
        // trigger on any trouble cannot pass this.
        let cases: [(Signal, Interval, Signal); 6] = [
            (
                Signal::SchedulerP95,
                Interval {
                    sched_p95_us: 90_000,
                    sched_samples: 900,
                    ..quiet_io()
                },
                Signal::SchedulerP95,
            ),
            (
                Signal::IoP99,
                Interval {
                    io_p99_us: 400_000,
                    io_samples: 20,
                    ..quiet_io()
                },
                Signal::IoP99,
            ),
            (
                Signal::Retransmissions,
                Interval {
                    retrans: 40,
                    ..quiet_io()
                },
                Signal::Retransmissions,
            ),
            (
                Signal::PsiSome,
                Interval {
                    psi_some_pct: Some(22.0),
                    ..quiet_io()
                },
                Signal::PsiSome,
            ),
            (
                Signal::PsiFull,
                Interval {
                    psi_full_pct: Some(9.0),
                    ..quiet_io()
                },
                Signal::PsiFull,
            ),
            (
                Signal::CpuUsage,
                Interval {
                    cpu_percent: Some(97.0),
                    ..quiet_io()
                },
                Signal::CpuUsage,
            ),
        ];
        for (signal, entry, expected) in cases {
            let fired = all_on().evaluate(&entry);
            assert_eq!(
                fired,
                vec![expected],
                "{signal:?} should be the only trigger to fire, got {fired:?}"
            );
        }
    }

    /// An interval that is quiet on everything except the field under test.
    fn quiet_io() -> Interval {
        Interval {
            sched_p95_us: 40,
            sched_samples: 900,
            io_p99_us: 100,
            io_samples: 40,
            retrans: 0,
            psi_some_pct: Some(0.0),
            psi_full_pct: Some(0.0),
            cpu_percent: Some(3.0),
        }
    }

    #[test]
    fn several_signals_can_fire_and_the_worst_comes_first() {
        // A host that is both memory starved and stuck behind retransmissions
        // must report all three, and must lead with the one furthest past its
        // threshold so the incident says what to look at first.
        let entry = Interval {
            sched_p95_us: 90_000,
            sched_samples: 900,
            psi_some_pct: Some(14.0),
            retrans: 40,
            ..quiet_io()
        };
        // How far past each threshold: 90000/10000 = 9x, 40/8 = 5x, 14/10 = 1.4x.
        // The scheduler leads even though retransmissions sound more alarming,
        // because the order follows the measurement rather than the order the
        // triggers happen to be listed in.
        let fired = all_on().evaluate(&entry);
        assert_eq!(
            fired,
            vec![
                Signal::SchedulerP95,
                Signal::Retransmissions,
                Signal::PsiSome
            ]
        );
    }

    #[test]
    fn a_trigger_at_its_threshold_fires() {
        // "At or above" rather than "above": a threshold an operator typed is
        // a line they expect the recorder to respect exactly.
        let entry = Interval {
            sched_p95_us: 10_000,
            sched_samples: 1,
            ..quiet_io()
        };
        assert_eq!(all_on().evaluate(&entry), vec![Signal::SchedulerP95]);

        let just_under = Interval {
            sched_p95_us: 9_999,
            ..entry
        };
        assert_eq!(all_on().evaluate(&just_under), Vec::new());
    }

    #[test]
    fn a_disabled_trigger_never_fires() {
        // A zero threshold is not "off", it is "fire on every interval", which
        // is how a threshold of zero would be misread. Every trigger is
        // therefore either a positive threshold or no threshold at all.
        let mut triggers = all_on();
        triggers.retrans = None;
        let busy = Interval {
            retrans: 1_000_000,
            ..quiet_io()
        };
        assert_eq!(triggers.evaluate(&busy), Vec::new());

        triggers.psi_some_pct = None;
        let pressured = Interval {
            psi_some_pct: Some(99.0),
            ..quiet_io()
        };
        assert_eq!(triggers.evaluate(&pressured), Vec::new());
    }

    #[test]
    fn a_zero_threshold_would_fire_on_everything() {
        // Why the word `off` exists. If zero were accepted as a threshold, an
        // idle interval would trip it and the recorder would write an incident
        // per interval for the whole run.
        let zero = Triggers {
            sched_p95_us: Some(0),
            ..all_on()
        };
        assert!(zero.evaluate(&quiet_io()).contains(&Signal::SchedulerP95));
    }

    #[test]
    fn missing_pressure_data_does_not_fire_the_pressure_triggers() {
        // The verified kernel has CONFIG_PSI off. A recorder that treated the
        // absent reading as zero pressure would be making a claim about a
        // machine it cannot see, and a trigger that treated it as unknown
        // pressure would fire on every interval forever.
        let entry = Interval {
            psi_some_pct: None,
            psi_full_pct: None,
            ..quiet_io()
        };
        assert_eq!(all_on().evaluate(&entry), Vec::new());
    }

    #[test]
    fn a_percentile_over_no_samples_is_not_a_reading_of_zero() {
        // The difference that matters: a retransmission count of zero is a
        // fact about the interval, while a latency percentile with no samples
        // says nothing at all.
        let entry = Interval {
            sched_samples: 0,
            sched_p95_us: 0,
            io_samples: 0,
            io_p99_us: 0,
            ..quiet_io()
        };
        assert_eq!(entry.read(Signal::SchedulerP95), None);
        assert_eq!(entry.read(Signal::IoP99), None);
        assert_eq!(entry.read(Signal::Retransmissions), Some(0.0));
    }

    #[test]
    fn enabled_lists_only_the_switched_on_signals() {
        let triggers = Triggers {
            psi_some_pct: None,
            psi_full_pct: None,
            cpu_percent: None,
            ..all_on()
        };
        assert_eq!(
            triggers.enabled(),
            vec![Signal::SchedulerP95, Signal::IoP99, Signal::Retransmissions]
        );
    }

    #[test]
    fn every_signal_reports_a_name_and_a_unit() {
        // A bundle read without the code in front of you has to say what the
        // numbers mean.
        let triggers = all_on();
        for signal in Signal::ALL {
            assert!(!signal.name().is_empty());
            assert!(!signal.unit().is_empty());
            assert!(
                signal.threshold(&triggers).is_some(),
                "{signal:?} should have a threshold when everything is on"
            );
        }
    }
}
