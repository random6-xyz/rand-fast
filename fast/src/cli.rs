use std::time::Duration;

use clap::{Args, Parser, Subcommand};

#[derive(Debug, Parser)]
#[command(name = "fast", version, about = "Linux performance diagnostics")]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
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
}

#[derive(Debug, Clone, Args)]
pub struct NetArgs {
    /// Process ID (TGID) to observe.
    #[arg(long, value_name = "PID", value_parser = parse_pid)]
    pub pid: u32,

    /// Collection duration, for example 10s or 500ms.
    #[arg(long, value_name = "DURATION", value_parser = parse_duration)]
    pub duration: Duration,
}

#[derive(Debug, Clone, Args)]
pub struct OffCpuArgs {
    /// Process ID (TGID) to observe.
    #[arg(long, value_name = "PID", value_parser = parse_pid)]
    pub pid: u32,

    /// Collection duration, for example 10s or 500ms.
    #[arg(long, value_name = "DURATION", value_parser = parse_duration)]
    pub duration: Duration,
}

#[derive(Debug, Clone, Args)]
pub struct MemoryArgs {
    /// Process ID (TGID) to observe.
    #[arg(long, value_name = "PID", value_parser = parse_pid)]
    pub pid: u32,

    /// Collection duration, for example 10s or 500ms.
    #[arg(long, value_name = "DURATION", value_parser = parse_duration)]
    pub duration: Duration,
}

#[derive(Debug, Clone, Args)]
pub struct DiagnoseArgs {
    /// Process ID (TGID) to diagnose.
    #[arg(long, value_name = "PID", value_parser = parse_pid)]
    pub pid: u32,

    /// Collection duration, for example 10s or 500ms.
    #[arg(long, default_value = "10s", value_parser = parse_duration)]
    pub duration: Duration,
}

#[derive(Debug, Clone, Args)]
pub struct DaemonArgs {
    /// Process ID (TGID) to observe.
    #[arg(long, value_name = "PID", value_parser = parse_pid)]
    pub pid: u32,

    /// Collection duration (0 for infinite).
    #[arg(long, default_value = "0s", value_parser = parse_duration)]
    pub duration: Duration,

    /// Trigger threshold for scheduler p95 (default 10ms).
    #[arg(long, default_value = "10ms", value_parser = parse_duration)]
    pub trigger: Duration,

    /// Output directory for incidents.
    #[arg(long, default_value = "./incidents")]
    pub output: std::path::PathBuf,
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
