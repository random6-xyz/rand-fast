use std::time::Duration;

use clap::{Args, Parser, Subcommand};

use crate::json::Format;

#[derive(Debug, Parser)]
#[command(name = "fast", version, about = "Linux performance diagnostics")]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

/// Adds the shared `--format` flag to a subcommand's arguments.
#[derive(Debug, Clone, Args)]
pub struct FormatArg {
    /// Output format.
    #[arg(long, value_enum, default_value_t = Format::Text)]
    pub format: Format,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Measure scheduler latency for a process and its threads.
    Sched(SchedArgs),
    /// Measure CPU usage and on-CPU hot stacks.
    Cpu(CpuArgs),
    /// Measure disk I/O latency.
    Io(IoArgs),
    /// Measure network latency and retransmissions.
    Net(NetArgs),
    /// Measure off-CPU wait time.
    OffCpu(OffCpuArgs),
    /// Measure memory pressure.
    Memory(MemoryArgs),
    /// Diagnose likely causes.
    Diagnose(DiagnoseArgs),
    /// Flight recorder daemon.
    Daemon(DaemonArgs),
}

#[derive(Debug, Clone, Args)]
pub struct SchedArgs {
    /// Process ID (TGID) to observe.
    #[arg(long, value_name = "PID", value_parser = parse_pid)]
    pub pid: u32,

    /// Collection duration, for example 10s or 500ms.
    #[arg(long, value_name = "DURATION", value_parser = parse_duration)]
    pub duration: Duration,

    #[command(flatten)]
    pub format: FormatArg,
}

fn parse_pid(value: &str) -> Result<u32, String> {
    let pid = value
        .parse::<u32>()
        .map_err(|_| format!("invalid PID: {value}"))?;
    if pid == 0 {
        return Err("PID must be greater than zero".to_string());
    }
    Ok(pid)
}

fn parse_duration(value: &str) -> Result<Duration, String> {
    let duration = humantime::parse_duration(value)
        .map_err(|error| format!("invalid duration `{value}`: {error}"))?;
    if duration.is_zero() {
        return Err("duration must be greater than zero".to_string());
    }
    Ok(duration)
}

/// Is this value the word that turns a trigger off?
fn is_off(value: &str) -> bool {
    value.eq_ignore_ascii_case("off")
}

/// A latency threshold in microseconds, or the decision not to watch it.
///
/// A separate type from [`CountThreshold`] and [`PercentThreshold`] so that
/// each flag accepts only what makes sense for it. A percentage of scheduler
/// latency is not a number a person can mean, and a flag that quietly accepted
/// it would produce a trigger nobody asked for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct LatencyThreshold(Option<u64>);

impl LatencyThreshold {
    /// The threshold in microseconds, or `None` when the trigger is off.
    pub fn micros(self) -> Option<u64> {
        self.0
    }
}

impl std::str::FromStr for LatencyThreshold {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        if is_off(value) {
            return Ok(LatencyThreshold(None));
        }
        let micros = parse_duration(value)?.as_micros();
        let micros = u64::try_from(micros)
            .map_err(|_| format!("latency threshold is too large: {value}"))?;
        Ok(LatencyThreshold(Some(micros)))
    }
}

/// A count threshold, or the decision not to watch it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct CountThreshold(Option<u64>);

impl CountThreshold {
    /// The threshold, or `None` when the trigger is off.
    pub fn count(self) -> Option<u64> {
        self.0
    }
}

impl std::str::FromStr for CountThreshold {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        if is_off(value) {
            return Ok(CountThreshold(None));
        }
        let count: u64 = value
            .parse()
            .map_err(|_| format!("invalid count `{value}`: expected a whole number or `off`"))?;
        if count == 0 {
            return Err(
                "a count of zero would fire on every interval; use `off` to disable the trigger"
                    .to_string(),
            );
        }
        Ok(CountThreshold(Some(count)))
    }
}

/// A percentage threshold, or the decision not to watch it.
#[derive(Debug, Clone, Copy, PartialEq, Default)]
pub struct PercentThreshold(Option<f64>);

impl PercentThreshold {
    /// The threshold, or `None` when the trigger is off.
    pub fn percent(self) -> Option<f64> {
        self.0
    }
}

impl std::str::FromStr for PercentThreshold {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        if is_off(value) {
            return Ok(PercentThreshold(None));
        }
        let percent: f64 = value
            .parse()
            .map_err(|_| format!("invalid percentage `{value}`: expected a number or `off`"))?;
        if !(0.0..=100.0).contains(&percent) {
            return Err(format!(
                "percentage must be between 0 and 100, got {percent}"
            ));
        }
        if percent == 0.0 {
            return Err(
                "a threshold of zero would fire on every interval; use `off` to disable the trigger"
                    .to_string(),
            );
        }
        Ok(PercentThreshold(Some(percent)))
    }
}

fn parse_frequency(value: &str) -> Result<u64, String> {
    let frequency = value
        .parse::<u64>()
        .map_err(|_| format!("invalid frequency: {value}"))?;
    if frequency == 0 {
        return Err("frequency must be greater than zero".to_string());
    }
    if frequency > 100_000 {
        return Err(
            "frequency must be at most 100000 Hz (the common perf_event_max_sample_rate)"
                .to_string(),
        );
    }
    Ok(frequency)
}

#[derive(Debug, Clone, Args)]
pub struct CpuArgs {
    /// Process ID (TGID) to observe.
    #[arg(long, value_name = "PID", value_parser = parse_pid)]
    pub pid: u32,

    /// Collection duration, for example 10s or 500ms.
    #[arg(long, value_name = "DURATION", value_parser = parse_duration)]
    pub duration: Duration,

    /// On-CPU sampling frequency in Hz (default 99).
    #[arg(long, value_name = "HZ", default_value_t = 99, value_parser = parse_frequency)]
    pub frequency: u64,

    #[command(flatten)]
    pub format: FormatArg,
}

#[derive(Debug, Clone, Args)]
pub struct IoArgs {
    /// Process ID (TGID) to observe.
    #[arg(long, value_name = "PID", value_parser = parse_pid)]
    pub pid: u32,

    /// Collection duration, for example 10s or 500ms.
    #[arg(long, value_name = "DURATION", value_parser = parse_duration)]
    pub duration: Duration,

    /// Slow I/O threshold (default 10ms).
    #[arg(long, default_value = "10ms", value_parser = parse_duration)]
    pub threshold: Duration,

    #[command(flatten)]
    pub format: FormatArg,
}

#[derive(Debug, Clone, Args)]
pub struct NetArgs {
    /// Process ID (TGID) to observe.
    #[arg(long, value_name = "PID", value_parser = parse_pid)]
    pub pid: u32,

    /// Collection duration, for example 10s or 500ms.
    #[arg(long, value_name = "DURATION", value_parser = parse_duration)]
    pub duration: Duration,

    #[command(flatten)]
    pub format: FormatArg,
}

#[derive(Debug, Clone, Args)]
pub struct OffCpuArgs {
    /// Process ID (TGID) to observe.
    #[arg(long, value_name = "PID", value_parser = parse_pid)]
    pub pid: u32,

    /// Collection duration, for example 10s or 500ms.
    #[arg(long, value_name = "DURATION", value_parser = parse_duration)]
    pub duration: Duration,

    #[command(flatten)]
    pub format: FormatArg,
}

#[derive(Debug, Clone, Args)]
pub struct MemoryArgs {
    /// Process ID (TGID) to observe.
    #[arg(long, value_name = "PID", value_parser = parse_pid)]
    pub pid: u32,

    /// Collection duration, for example 10s or 500ms.
    #[arg(long, value_name = "DURATION", value_parser = parse_duration)]
    pub duration: Duration,

    #[command(flatten)]
    pub format: FormatArg,
}

#[derive(Debug, Clone, Args)]
pub struct DiagnoseArgs {
    /// Process ID (TGID) to diagnose.
    #[arg(long, value_name = "PID", value_parser = parse_pid)]
    pub pid: u32,

    /// Collection duration, for example 10s or 500ms.
    #[arg(long, default_value = "10s", value_parser = parse_duration)]
    pub duration: Duration,

    #[command(flatten)]
    pub format: FormatArg,
}

#[derive(Debug, Clone, Args)]
pub struct DaemonArgs {
    /// Process ID (TGID) to observe.
    #[arg(long, value_name = "PID", value_parser = parse_pid)]
    pub pid: u32,

    /// Collection duration (0 for infinite).
    #[arg(long, default_value = "0s", value_parser = parse_duration)]
    pub duration: Duration,

    /// How often an interval is recorded into the rolling window.
    ///
    /// Shorter intervals catch a shorter regression and cost proportionally more
    /// of the overhead budget, so this and the window are the two knobs that
    /// decide what the recorder is able to see.
    #[arg(long, default_value = "1s", value_parser = parse_duration)]
    pub interval: Duration,

    /// How much history the rolling window keeps.
    #[arg(long, default_value = "60s", value_parser = parse_duration)]
    pub window: Duration,

    /// Trigger threshold for scheduler latency p95.
    ///
    /// One of several triggers; the recorder writes an incident when any of
    /// them fires, and the incident names which. `off` disables this one.
    #[arg(long, default_value = "10ms", value_name = "DURATION|off")]
    pub trigger_sched_p95: LatencyThreshold,

    /// Trigger threshold for block I/O latency p99.
    #[arg(long, default_value = "25ms", value_name = "DURATION|off")]
    pub trigger_io_p99: LatencyThreshold,

    /// Trigger threshold for retransmissions in one interval.
    #[arg(long, default_value = "8", value_name = "COUNT|off")]
    pub trigger_retrans: CountThreshold,

    /// Trigger threshold for memory pressure "some", in percent.
    #[arg(long, default_value = "10", value_name = "PERCENT|off")]
    pub trigger_psi_some: PercentThreshold,

    /// Trigger threshold for memory pressure "full", in percent.
    #[arg(long, default_value = "5", value_name = "PERCENT|off")]
    pub trigger_psi_full: PercentThreshold,

    /// Trigger threshold for on-CPU usage, as a percentage of one CPU.
    #[arg(long, default_value = "off", value_name = "PERCENT|off")]
    pub trigger_cpu: PercentThreshold,

    /// Output directory for incidents.
    #[arg(long, default_value = "./incidents")]
    pub output: std::path::PathBuf,

    #[command(flatten)]
    pub format: FormatArg,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_duration() {
        assert_eq!(parse_duration("10s").unwrap(), Duration::from_secs(10));
        assert_eq!(parse_duration("250ms").unwrap(), Duration::from_millis(250));
    }

    #[test]
    fn rejects_invalid_duration() {
        assert!(parse_duration("0s").is_err());
        assert!(parse_duration("not-a-duration").is_err());
    }

    #[test]
    fn rejects_zero_pid() {
        assert!(parse_pid("0").is_err());
        assert_eq!(parse_pid("1234").unwrap(), 1234);
    }

    #[test]
    fn parses_frequency() {
        assert_eq!(parse_frequency("99").unwrap(), 99);
        assert_eq!(parse_frequency("100000").unwrap(), 100_000);
    }

    #[test]
    fn rejects_invalid_frequency() {
        assert!(parse_frequency("0").is_err());
        assert!(parse_frequency("100001").is_err());
        assert!(parse_frequency("high").is_err());
    }
}
