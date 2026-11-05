//! Opt-in progress reporting for `fast diagnose`.
//!
//! Progress is written to stderr so that stdout stays the report and
//! `--format json` keeps producing exactly one document per run. The reporter
//! only formats what the collection loop tells it; it never decides that a run
//! finished. A run that is interrupted, exits with its target, or fails prints
//! the corresponding status instead of a completion line, so a redirected log
//! cannot claim 100% for a collection that did not finish.

use std::io::Write;
use std::time::Duration;

/// How often an intermediate update is printed.
///
/// Fixed rather than derived from the collection duration: a log line every
/// second is readable whether the run lasts two seconds or two hours, and a
/// short run simply prints its start and final status.
pub const UPDATE_INTERVAL: Duration = Duration::from_secs(1);

/// An intermediate update never claims the run is done. Completion is only
/// reported by [`ProgressReporter::completed`], after the collector returned.
const MAX_INTERMEDIATE_PERCENT: u64 = 99;

/// Writes collection progress to a sink that is expected to be stderr.
pub struct ProgressReporter<W: Write> {
    out: W,
    total: Duration,
}

impl<W: Write> ProgressReporter<W> {
    pub fn new(out: W, total: Duration) -> Self {
        Self { out, total }
    }

    /// Announces the collection before any signal is attached.
    pub fn started(&mut self) {
        let _ = writeln!(
            self.out,
            "progress: collecting for {}",
            humantime::format_duration(self.total)
        );
        let _ = self.out.flush();
    }

    /// Prints elapsed and total time. The percentage is rounded down and
    /// capped below 100 so a slow final drain cannot look like completion.
    pub fn update(&mut self, elapsed: Duration) {
        let percent = self.percent(elapsed);
        let _ = writeln!(
            self.out,
            "progress: {} / {} ({percent}%)",
            humantime::format_duration(elapsed),
            humantime::format_duration(self.total)
        );
        let _ = self.out.flush();
    }

    /// The collection reached its configured duration.
    pub fn completed(&mut self, elapsed: Duration) {
        let _ = writeln!(
            self.out,
            "progress: complete after {}",
            humantime::format_duration(elapsed)
        );
        let _ = self.out.flush();
    }

    /// Ctrl-C stopped the collection before its configured duration.
    pub fn interrupted(&mut self, elapsed: Duration) {
        let _ = writeln!(
            self.out,
            "progress: interrupted after {} of {}",
            humantime::format_duration(elapsed),
            humantime::format_duration(self.total)
        );
        let _ = self.out.flush();
    }

    /// The observed process exited before the configured duration.
    pub fn target_exited(&mut self, elapsed: Duration) {
        let _ = writeln!(
            self.out,
            "progress: target exited after {} of {}",
            humantime::format_duration(elapsed),
            humantime::format_duration(self.total)
        );
        let _ = self.out.flush();
    }

    /// The collection ended with an error. The caller reports the error
    /// itself, so this line only states that progress stopped early.
    pub fn failed(&mut self) {
        let _ = writeln!(self.out, "progress: failed before completion");
        let _ = self.out.flush();
    }

    fn percent(&self, elapsed: Duration) -> u64 {
        let total = self.total.as_secs_f64();
        if total <= 0.0 {
            return 0;
        }
        let percent = (elapsed.as_secs_f64() / total * 100.0).floor();
        if percent.is_finite() && percent > 0.0 {
            (percent as u64).min(MAX_INTERMEDIATE_PERCENT)
        } else {
            0
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lines(bytes: &[u8]) -> Vec<String> {
        String::from_utf8_lossy(bytes)
            .lines()
            .map(str::to_owned)
            .collect()
    }

    #[test]
    fn start_line_names_the_duration_for_seconds_and_milliseconds() {
        let mut reporter = ProgressReporter::new(Vec::new(), Duration::from_secs(10));
        reporter.started();
        reporter.update(Duration::from_secs(3));
        reporter.completed(Duration::from_secs(10));
        let out = lines(reporter.out.as_slice());
        assert_eq!(out[0], "progress: collecting for 10s");
        assert_eq!(out.last().unwrap(), "progress: complete after 10s");

        let mut short = ProgressReporter::new(Vec::new(), Duration::from_millis(250));
        short.started();
        assert_eq!(
            lines(short.out.as_slice())[0],
            "progress: collecting for 250ms"
        );
    }

    #[test]
    fn intermediate_percentages_round_down_and_stop_below_complete() {
        let mut reporter = ProgressReporter::new(Vec::new(), Duration::from_secs(10));
        reporter.update(Duration::from_secs(3));
        reporter.update(Duration::from_millis(9_999));
        reporter.update(Duration::from_secs(10));
        reporter.update(Duration::from_secs(30));
        let out = lines(reporter.out.as_slice());
        assert_eq!(out[0], "progress: 3s / 10s (30%)");
        assert_eq!(out[1], "progress: 9s 999ms / 10s (99%)");
        assert_eq!(out[2], "progress: 10s / 10s (99%)");
        assert_eq!(out[3], "progress: 30s / 10s (99%)");
    }

    #[test]
    fn a_zero_total_never_reports_a_percentage_it_cannot_know() {
        let mut reporter = ProgressReporter::new(Vec::new(), Duration::ZERO);
        reporter.update(Duration::from_secs(1));
        assert_eq!(lines(reporter.out.as_slice())[0], "progress: 1s / 0s (0%)");
    }

    #[test]
    fn unfinished_runs_report_their_status_instead_of_completion() {
        let mut interrupted = ProgressReporter::new(Vec::new(), Duration::from_secs(10));
        interrupted.interrupted(Duration::from_secs(4));
        assert_eq!(
            lines(interrupted.out.as_slice())[0],
            "progress: interrupted after 4s of 10s"
        );

        let mut exited = ProgressReporter::new(Vec::new(), Duration::from_secs(10));
        exited.target_exited(Duration::from_millis(1500));
        assert_eq!(
            lines(exited.out.as_slice())[0],
            "progress: target exited after 1s 500ms of 10s"
        );

        let mut failed = ProgressReporter::new(Vec::new(), Duration::from_secs(10));
        failed.failed();
        assert_eq!(
            lines(failed.out.as_slice())[0],
            "progress: failed before completion"
        );
    }

    #[test]
    fn a_broken_progress_sink_does_not_break_the_reporter() {
        struct Broken;
        impl Write for Broken {
            fn write(&mut self, _buf: &[u8]) -> std::io::Result<usize> {
                Err(std::io::Error::new(
                    std::io::ErrorKind::BrokenPipe,
                    "closed",
                ))
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Err(std::io::Error::new(
                    std::io::ErrorKind::BrokenPipe,
                    "closed",
                ))
            }
        }

        let mut reporter = ProgressReporter::new(Broken, Duration::from_secs(10));
        reporter.started();
        reporter.update(Duration::from_secs(1));
        reporter.completed(Duration::from_secs(10));
    }
}
