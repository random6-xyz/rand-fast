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
}
