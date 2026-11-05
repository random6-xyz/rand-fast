//! Paired baseline/instrumented benchmark for the collector overhead.
//!
//! The tool does not try to make wall-clock timings from different runners
//! comparable. It records the runner, kernel, accelerator and raw samples so a
//! later policy can decide which metrics are stable enough to gate.

use std::{
    ffi::OsString,
    fs::{self, File},
    io::Write,
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    thread,
    time::{Duration, Instant},
};

use anyhow::{Context, Result, bail};
use clap::{Parser, ValueEnum};
use serde::{Deserialize, Serialize};

const SCHEMA: &str = "rand-fast/bench/v1";
const SAMPLE_INTERVAL: Duration = Duration::from_millis(50);
const ATTACH_DELAY: Duration = Duration::from_millis(300);

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum Mode {
    /// CPU and page-fault churn through the fast-workload memory hog.
    Cpu,
    /// O_DIRECT reads through the fast-workload I/O hog.
    Io,
    /// Futex contention without the CPU-heavy mixed workload.
    Lock,
    /// Loopback request/response traffic with a slow peer.
    Net,
}

impl Mode {
    fn name(self) -> &'static str {
        match self {
            Self::Cpu => "cpu",
            Self::Io => "io",
            Self::Lock => "lock",
            Self::Net => "net",
        }
    }

    fn workload_args(
        self,
        workload: &Path,
        duration: Duration,
        report: &Path,
        io_path: &Path,
    ) -> Vec<OsString> {
        let duration = humantime::format_duration(duration).to_string();
        let mut args: Vec<OsString> = Vec::new();
        let subcommand = match self {
            Self::Cpu => "mem-hog",
            Self::Lock => "lock-hog",
            Self::Io => "io-hog",
            Self::Net => "net-hog",
        };
        args.push(subcommand.into());
        args.push("--duration".into());
        args.push(duration.into());
        args.push("--report".into());
        args.push(report.into());
        match self {
            Self::Cpu => {
                args.extend([
                    "--workers".into(),
                    "2".into(),
                    "--size-mib".into(),
                    "16".into(),
                ]);
            }
            Self::Lock => {
                args.extend([
                    "--workers".into(),
                    "16".into(),
                    "--hold-ms".into(),
                    "1".into(),
                ]);
            }
            Self::Io => {
                args.extend([
                    "--workers".into(),
                    "2".into(),
                    "--path".into(),
                    io_path.into(),
                ]);
            }
            Self::Net => {
                args.extend([
                    "--workers".into(),
                    "2".into(),
                    "--peer-delay-ms".into(),
                    "5".into(),
                ]);
            }
        }
        // Keep the workload binary path out of the arguments but assert it is
        // passed by the caller; this keeps the argument builder testable.
        let _ = workload;
        args
    }
}

/// A child that is killed and reaped when dropped, so a failed measurement
/// cannot leave a process running into the next mode or repetition.
struct KillOnDrop(Child);

impl Drop for KillOnDrop {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[derive(Debug, Parser)]
#[command(name = "fast-bench", about = "Paired collector-overhead benchmark")]
struct Args {
    /// Path to the fast binary under test.
    #[arg(long, value_name = "PATH")]
    fast: PathBuf,

    /// Path to the fast-workload fixture binary.
    #[arg(long, value_name = "PATH")]
    workload: PathBuf,

    /// Duration of each workload/collector run, for example 5s.
    #[arg(long, value_name = "DURATION", default_value = "5s")]
    duration: humantime::Duration,

    /// Recorded repetitions per mode (warmups are additional).
    #[arg(long, default_value_t = 3)]
    repetitions: usize,

    /// Warmup repetitions per mode, discarded from the report.
    #[arg(long, default_value_t = 1)]
    warmup: usize,

    /// Comma-separated modes to run.
    #[arg(long, value_name = "LIST", default_value = "cpu,io,lock,net")]
    modes: String,

    /// File the I/O workload uses. Defaults to IO_HOG_PATH, then a file under
    /// the output directory (which is not a block device and will be reported
    /// as an invalid I/O measurement).
    #[arg(long, value_name = "PATH")]
    io_path: Option<PathBuf>,

    /// Directory for raw reports and the final report.json.
    #[arg(long, value_name = "DIR")]
    out: PathBuf,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct Latency {
    p50: u64,
    p95: u64,
    p99: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct WorkloadReport {
    workload: String,
    ops: u64,
    #[serde(default)]
    latency_us: Option<Latency>,
}

#[derive(Debug, Clone, Serialize)]
struct Phase {
    order: &'static str,
    ops: u64,
    p50_us: Option<u64>,
    p95_us: Option<u64>,
    p99_us: Option<u64>,
    wall_ms: u64,
}

#[derive(Debug, Clone, Serialize)]
struct Collector {
    cpu_pct: f64,
    peak_rss_bytes: Option<u64>,
    lost_events: u64,
    wall_ms: u64,
}

#[derive(Debug, Clone, Serialize)]
struct Run {
    mode: &'static str,
    repetition: usize,
    baseline: Option<Phase>,
    instrumented: Option<Phase>,
    collector: Option<Collector>,
    ops_ratio: Option<f64>,
    p95_ratio: Option<f64>,
    error: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
struct Summary {
    mode: &'static str,
    runs: usize,
    valid_runs: usize,
    ops_ratio_median: Option<f64>,
    p95_ratio_median: Option<f64>,
    collector_cpu_pct_median: Option<f64>,
    collector_rss_bytes_max: Option<u64>,
    lost_events_max: Option<u64>,
}

#[derive(Debug, Clone, Serialize)]
struct Metadata {
    kernel: String,
    cpus: usize,
    accelerator: String,
    loadavg: String,
    fast: String,
    workload: String,
    io_path: String,
}

#[derive(Debug, Clone, Serialize)]
struct Report {
    schema: &'static str,
    generated_at_unix_s: u64,
    metadata: Metadata,
    duration_ms: u64,
    repetitions: usize,
    warmup: usize,
    runs: Vec<Run>,
    summary: Vec<Summary>,
}

fn main() {
    if let Err(error) = run() {
        eprintln!("fast-bench: {error:#}");
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    let args = Args::parse();
    if args.repetitions == 0 {
        bail!("--repetitions must be greater than zero");
    }
    let modes = parse_modes(&args.modes)?;
    fs::create_dir_all(args.out.join("raw"))
        .with_context(|| format!("create {}", args.out.display()))?;
    let io_path = args
        .io_path
        .clone()
        .or_else(|| std::env::var_os("IO_HOG_PATH").map(PathBuf::from))
        .unwrap_or_else(|| args.out.join("io-bench-file"));
    let mut runs = Vec::new();
    let mut any_invalid = false;

    for mode in modes {
        for warmup in 0..args.warmup {
            let _ = fs::remove_file(&io_path);
            let record = run_pair(&args, mode, usize::MAX - warmup, &io_path, true);
            if let Err(error) = record {
                bail!(
                    "warmup {} for {} failed: {error:#}",
                    warmup + 1,
                    mode.name()
                );
            }
        }
        for repetition in 0..args.repetitions {
            let _ = fs::remove_file(&io_path);
            let record = run_pair(&args, mode, repetition, &io_path, false);
            match record {
                Ok(run) => {
                    if run.error.is_some() {
                        any_invalid = true;
                    }
                    runs.push(run);
                }
                Err(error) => {
                    any_invalid = true;
                    runs.push(Run {
                        mode: mode.name(),
                        repetition,
                        baseline: None,
                        instrumented: None,
                        collector: None,
                        ops_ratio: None,
                        p95_ratio: None,
                        error: Some(format!("{error:#}")),
                    });
                }
            }
        }
    }

    let summary = summarize(&runs);
    let report = Report {
        schema: SCHEMA,
        generated_at_unix_s: unix_now(),
        metadata: metadata(&args, &io_path),
        duration_ms: args.duration.as_millis().min(u128::from(u64::MAX)) as u64,
        repetitions: args.repetitions,
        warmup: args.warmup,
        runs,
        summary,
    };
    let path = args.out.join("report.json");
    let mut file = File::create(&path).with_context(|| format!("create {}", path.display()))?;
    serde_json::to_writer_pretty(&mut file, &report)?;
    writeln!(file)?;
    println!("fast-bench: wrote {}", path.display());
    if any_invalid {
        bail!(
            "one or more benchmark runs were invalid; see {}",
            path.display()
        );
    }
    Ok(())
}

fn parse_modes(list: &str) -> Result<Vec<Mode>> {
    let mut modes = Vec::new();
    for item in list.split(',') {
        let mode = match item.trim() {
            "cpu" => Mode::Cpu,
            "io" => Mode::Io,
            "lock" => Mode::Lock,
            "net" => Mode::Net,
            other => bail!("unknown mode {other:?}; expected cpu, io, lock or net"),
        };
        if !modes.contains(&mode) {
            modes.push(mode);
        }
    }
    if modes.is_empty() {
        bail!("--modes must name at least one mode");
    }
    Ok(modes)
}

fn run_pair(
    args: &Args,
    mode: Mode,
    repetition: usize,
    io_path: &Path,
    warmup: bool,
) -> Result<Run> {
    let baseline_first = repetition.is_multiple_of(2);
    let mut run = Run {
        mode: mode.name(),
        repetition,
        baseline: None,
        instrumented: None,
        collector: None,
        ops_ratio: None,
        p95_ratio: None,
        error: None,
    };
    if mode == Mode::Io && std::env::var("FAST_BLOCK_DEVICE").as_deref() != Ok("1") {
        run.error = Some(
            "io mode requires FAST_BLOCK_DEVICE=1; the guest block disk was not mounted"
                .to_string(),
        );
        return Ok(run);
    }
    let result = (|| -> Result<()> {
        if baseline_first {
            run.baseline = Some(run_baseline(args, mode, repetition, io_path, warmup)?);
            let (phase, collector) = run_instrumented(args, mode, repetition, io_path, warmup)?;
            run.instrumented = Some(phase);
            run.collector = Some(collector);
        } else {
            let (phase, collector) = run_instrumented(args, mode, repetition, io_path, warmup)?;
            run.instrumented = Some(phase);
            run.collector = Some(collector);
            run.baseline = Some(run_baseline(args, mode, repetition, io_path, warmup)?);
        }
        Ok(())
    })();
    if let Err(error) = result {
        run.error = Some(format!("{error:#}"));
        return Ok(run);
    }
    let baseline = run.baseline.as_ref().unwrap();
    let instrumented = run.instrumented.as_ref().unwrap();
    if baseline.ops == 0 || instrumented.ops == 0 {
        run.error = Some("measurement performed no work".to_string());
        return Ok(run);
    }
    run.ops_ratio = Some(instrumented.ops as f64 / baseline.ops as f64);
    run.p95_ratio = match (baseline.p95_us, instrumented.p95_us) {
        (Some(0), _) | (_, None) | (None, _) => None,
        (Some(base), Some(inst)) => Some(inst as f64 / base as f64),
    };
    Ok(run)
}

fn run_baseline(
    args: &Args,
    mode: Mode,
    repetition: usize,
    io_path: &Path,
    warmup: bool,
) -> Result<Phase> {
    let report = raw_path(args, mode, repetition, warmup, "baseline.json");
    let out = raw_path(args, mode, repetition, warmup, "baseline.log");
    let started = Instant::now();
    let log = File::create(&out)?;
    let status = Command::new(&args.workload)
        .args(mode.workload_args(&args.workload, *args.duration, &report, io_path))
        .stdout(Stdio::from(log.try_clone()?))
        .stderr(Stdio::from(log))
        .status()
        .with_context(|| format!("run baseline workload for {}", mode.name()))?;
    if !status.success() {
        bail!("baseline workload exited with {status}");
    }
    let report = read_workload(&report)?;
    Ok(phase("baseline", &report, started.elapsed()))
}

fn run_instrumented(
    args: &Args,
    mode: Mode,
    repetition: usize,
    io_path: &Path,
    warmup: bool,
) -> Result<(Phase, Collector)> {
    let report = raw_path(args, mode, repetition, warmup, "instrumented.json");
    let workload_log = raw_path(args, mode, repetition, warmup, "instrumented.log");
    let collector_out = raw_path(args, mode, repetition, warmup, "collector.json");
    let collector_err = raw_path(args, mode, repetition, warmup, "collector.err");

    let workload_started = Instant::now();
    let workload_file = File::create(&workload_log)?;
    let mut workload = KillOnDrop(
        Command::new(&args.workload)
            .args(mode.workload_args(&args.workload, *args.duration, &report, io_path))
            .stdout(Stdio::from(workload_file.try_clone()?))
            .stderr(Stdio::from(workload_file))
            .spawn()
            .with_context(|| format!("start instrumented workload for {}", mode.name()))?,
    );
    thread::sleep(ATTACH_DELAY);
    if let Some(status) = workload.0.try_wait()? {
        bail!("workload exited before the collector attached: {status}");
    }

    let started = Instant::now();
    let mut collector = KillOnDrop(
        Command::new(&args.fast)
            .args([
                "diagnose",
                "--pid",
                &workload.0.id().to_string(),
                "--duration",
                &humantime::format_duration(*args.duration).to_string(),
                "--format",
                "json",
            ])
            .stdout(Stdio::from(File::create(&collector_out)?))
            .stderr(Stdio::from(File::create(&collector_err)?))
            .spawn()
            .context("start fast diagnose")?,
    );

    let (cpu_pct, peak_rss_bytes) = sample_collector(&mut collector.0, started)?;
    let collector_status = collector.0.wait()?;
    if !collector_status.success() {
        let error = fs::read_to_string(&collector_err).unwrap_or_default();
        bail!("collector exited with {collector_status}: {error}");
    }
    let collector_wall = started.elapsed();

    let workload_status = workload.0.wait()?;
    if !workload_status.success() {
        bail!("instrumented workload exited with {workload_status}");
    }
    let report = read_workload(&report)?;
    let lost_events = read_lost_events(&collector_out)?;
    Ok((
        phase("instrumented", &report, workload_started.elapsed()),
        Collector {
            cpu_pct,
            peak_rss_bytes: Some(peak_rss_bytes),
            lost_events,
            wall_ms: collector_wall.as_millis().min(u128::from(u64::MAX)) as u64,
        },
    ))
}

fn sample_collector(child: &mut Child, started: Instant) -> Result<(f64, u64)> {
    let pid = child.id();
    let mut first_ticks = None;
    let mut last_ticks = 0;
    let mut peak_rss: Option<u64> = None;
    loop {
        if let Some(ticks) = proc_ticks(pid) {
            first_ticks.get_or_insert(ticks);
            last_ticks = ticks;
        }
        if let Some(rss) = proc_rss(pid) {
            peak_rss = Some(peak_rss.unwrap_or(0).max(rss));
        }
        if child.try_wait()?.is_some() {
            break;
        }
        thread::sleep(SAMPLE_INTERVAL);
    }
    let elapsed = started.elapsed().as_secs_f64().max(0.001);
    let first = first_ticks.context("could not read collector CPU time from /proc")?;
    let ticks = last_ticks.saturating_sub(first);
    let clk_tck = unsafe { libc::sysconf(libc::_SC_CLK_TCK) };
    if clk_tck <= 0 {
        bail!("sysconf(_SC_CLK_TCK) returned {clk_tck}");
    }
    let cpu_pct = ticks as f64 / clk_tck as f64 / elapsed * 100.0;
    let peak_rss = peak_rss.context("could not read collector VmHWM from /proc")?;
    Ok((cpu_pct, peak_rss))
}

fn proc_ticks(pid: u32) -> Option<u64> {
    let stat = fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    let close = stat.rfind(')')?;
    let fields: Vec<&str> = stat[close + 1..].split_whitespace().collect();
    // The slice starts at field 3 (state); utime and stime are fields 14 and 15.
    let utime: u64 = fields.get(11)?.parse().ok()?;
    let stime: u64 = fields.get(12)?.parse().ok()?;
    Some(utime + stime)
}

fn proc_rss(pid: u32) -> Option<u64> {
    let status = fs::read_to_string(format!("/proc/{pid}/status")).ok()?;
    for line in status.lines() {
        if let Some(rest) = line.strip_prefix("VmHWM:") {
            let kb: u64 = rest.split_whitespace().next()?.parse().ok()?;
            return Some(kb * 1024);
        }
    }
    None
}

fn read_workload(path: &Path) -> Result<WorkloadReport> {
    let text = fs::read_to_string(path)
        .with_context(|| format!("read workload report {}", path.display()))?;
    let report: WorkloadReport = serde_json::from_str(&text)
        .with_context(|| format!("parse workload report {}", path.display()))?;
    Ok(report)
}

fn read_lost_events(path: &Path) -> Result<u64> {
    let text = fs::read_to_string(path)
        .with_context(|| format!("read collector output {}", path.display()))?;
    let value: serde_json::Value =
        serde_json::from_str(&text).with_context(|| format!("parse {}", path.display()))?;
    let lost = value["data"]["lost_events"]
        .as_array()
        .context("collector document has no data.lost_events array")?;
    Ok(lost
        .iter()
        .filter_map(|entry| entry["count"].as_u64())
        .sum())
}

fn phase(order: &'static str, report: &WorkloadReport, elapsed: Duration) -> Phase {
    Phase {
        order,
        ops: report.ops,
        p50_us: report.latency_us.as_ref().map(|l| l.p50),
        p95_us: report.latency_us.as_ref().map(|l| l.p95),
        p99_us: report.latency_us.as_ref().map(|l| l.p99),
        wall_ms: elapsed.as_millis().min(u128::from(u64::MAX)) as u64,
    }
}

fn raw_path(args: &Args, mode: Mode, repetition: usize, warmup: bool, name: &str) -> PathBuf {
    let prefix = if warmup { "warmup" } else { "run" };
    args.out
        .join("raw")
        .join(format!("{}-{prefix}-{repetition}-{name}", mode.name()))
}

fn summarize(runs: &[Run]) -> Vec<Summary> {
    let mut modes: Vec<&str> = runs.iter().map(|run| run.mode).collect();
    modes.sort_unstable();
    modes.dedup();
    modes
        .into_iter()
        .map(|mode| {
            let selected: Vec<&Run> = runs.iter().filter(|run| run.mode == mode).collect();
            let valid: Vec<&Run> = selected
                .iter()
                .copied()
                .filter(|r| r.error.is_none())
                .collect();
            Summary {
                mode: mode_ref(mode),
                runs: selected.len(),
                valid_runs: valid.len(),
                ops_ratio_median: median(valid.iter().filter_map(|r| r.ops_ratio)),
                p95_ratio_median: median(valid.iter().filter_map(|r| r.p95_ratio)),
                collector_cpu_pct_median: median(
                    valid
                        .iter()
                        .filter_map(|r| r.collector.as_ref().map(|c| c.cpu_pct)),
                ),
                collector_rss_bytes_max: valid
                    .iter()
                    .filter_map(|r| r.collector.as_ref().and_then(|c| c.peak_rss_bytes))
                    .max(),
                lost_events_max: valid
                    .iter()
                    .filter_map(|r| r.collector.as_ref().map(|c| c.lost_events))
                    .max(),
            }
        })
        .collect()
}

fn mode_ref(mode: &str) -> &'static str {
    match mode {
        "cpu" => "cpu",
        "io" => "io",
        "lock" => "lock",
        "net" => "net",
        _ => "unknown",
    }
}

fn median(values: impl Iterator<Item = f64>) -> Option<f64> {
    let mut values: Vec<f64> = values.filter(|value| value.is_finite()).collect();
    if values.is_empty() {
        return None;
    }
    values.sort_by(|a, b| a.total_cmp(b));
    let middle = values.len() / 2;
    if !values.len().is_multiple_of(2) {
        Some(values[middle])
    } else {
        Some((values[middle - 1] + values[middle]) / 2.0)
    }
}

fn metadata(args: &Args, io_path: &Path) -> Metadata {
    Metadata {
        kernel: fs::read_to_string("/proc/sys/kernel/osrelease")
            .map(|value| value.trim().to_string())
            .unwrap_or_else(|_| "unknown".to_string()),
        cpus: std::thread::available_parallelism()
            .map(usize::from)
            .unwrap_or(0),
        accelerator: std::env::var("FAST_ACCEL").unwrap_or_else(|_| "unknown".to_string()),
        loadavg: fs::read_to_string("/proc/loadavg")
            .map(|value| value.trim().to_string())
            .unwrap_or_else(|_| "unknown".to_string()),
        fast: args.fast.display().to_string(),
        workload: args.workload.display().to_string(),
        io_path: io_path.display().to_string(),
    }
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|value| value.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_modes_and_rejects_unknown() {
        assert_eq!(
            parse_modes("cpu,io,lock,net").unwrap(),
            vec![Mode::Cpu, Mode::Io, Mode::Lock, Mode::Net]
        );
        assert_eq!(parse_modes("cpu,cpu").unwrap(), vec![Mode::Cpu]);
        assert!(parse_modes("cpu,disk").is_err());
        assert!(parse_modes("").is_err());
    }

    #[test]
    fn mode_arguments_name_the_duration_and_report() {
        let report = Path::new("/tmp/report.json");
        let io = Path::new("/tmp/io");
        let args = Mode::Cpu.workload_args(
            Path::new("/bin/fast-workload"),
            Duration::from_secs(5),
            report,
            io,
        );
        let text: Vec<String> = args
            .iter()
            .map(|value| value.to_string_lossy().into_owned())
            .collect();
        assert_eq!(text[0], "mem-hog");
        assert!(text.contains(&"5s".to_string()));
        assert!(text.contains(&"/tmp/report.json".to_string()));
        assert!(!text.contains(&"/bin/fast-workload".to_string()));
    }

    #[test]
    fn parses_proc_stat_ticks() {
        let line = "123 (fast diagnose) S 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16";
        let close = line.rfind(')').unwrap();
        let fields: Vec<&str> = line[close + 1..].split_whitespace().collect();
        let utime: u64 = fields[11].parse().unwrap();
        let stime: u64 = fields[12].parse().unwrap();
        assert_eq!((utime, stime), (11, 12));
    }

    #[test]
    fn median_handles_even_and_odd_counts() {
        assert_eq!(median([3.0, 1.0, 2.0].into_iter()), Some(2.0));
        assert_eq!(median([4.0, 1.0, 3.0, 2.0].into_iter()), Some(2.5));
        assert_eq!(median(std::iter::empty()), None);
        assert_eq!(median([f64::NAN].into_iter()), None);
    }

    #[test]
    fn workload_report_requires_an_ops_count() {
        let report: WorkloadReport = serde_json::from_str(r#"{"workload":"x","ops":42}"#).unwrap();
        assert_eq!(report.ops, 42);
        assert!(report.latency_us.is_none());
    }
}
