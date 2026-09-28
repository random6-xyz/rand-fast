use std::{collections::BTreeSet, fs, time::Duration};

use anyhow::{Context, Result, bail};
use aya::{
    Ebpf, include_bytes_aligned,
    maps::{HashMap as AyaHashMap, MapData},
};
use fast_common::{COLLECT_MEMORY, MemoryCounters};

use crate::{cli::MemoryArgs, process, runtime};

/// How often the kernel-side counters are sampled. Short enough that a
/// transient spike still shows up in a rate, long enough that reading one
/// map entry per target thread stays far cheaper than the events it replaces.
const POLL_INTERVAL: Duration = Duration::from_millis(200);

/// A sample of every target thread's counters, summed.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Totals {
    /// Summed user page faults.
    pub faults: u64,
    /// Summed direct reclaim attempts.
    pub reclaims: u64,
}

impl Totals {
    /// Difference against an earlier sample, per counter.
    ///
    /// Counters only ever increase, so a decrease means the map was resized
    /// and the reading is meaningless. Saturating to zero keeps a bad sample
    /// from producing a negative rate in the report.
    pub fn since(&self, earlier: &Totals) -> Totals {
        Totals {
            faults: self.faults.saturating_sub(earlier.faults),
            reclaims: self.reclaims.saturating_sub(earlier.reclaims),
        }
    }
}

/// Reads the per-thread memory counters out of the eBPF map.
pub struct CounterReader {
    map: AyaHashMap<MapData, u32, MemoryCounters>,
}

impl CounterReader {
    /// Takes the counters map out of the loaded eBPF object.
    pub fn new(bpf: &mut aya::Ebpf) -> Result<Self> {
        let map = bpf
            .take_map("MEMORY_COUNTERS")
            .context("eBPF map MEMORY_COUNTERS is missing")?;
        let map: AyaHashMap<MapData, u32, MemoryCounters> = map
            .try_into()
            .context("MEMORY_COUNTERS has an unexpected map type or layout")?;
        Ok(Self { map })
    }

    /// Sums the counters across every thread currently in the map.
    pub fn totals(&self) -> Result<Totals> {
        let mut totals = Totals::default();
        for item in self.map.iter() {
            let (_tid, counters) = item.context("failed to read a memory counter entry")?;
            let counters: MemoryCounters = counters;
            totals.faults = totals.faults.saturating_add(counters.faults);
            totals.reclaims = totals.reclaims.saturating_add(counters.reclaims);
        }
        Ok(totals)
    }
}

/// Fault counters read from `/proc/<pid>/stat`.
///
/// The kernel's page fault tracepoint does not say whether a fault was minor
/// or major, so the split comes from the process accounting counters, which
/// are exact but only readable at a poll.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ProcFaults {
    /// Minor faults: pages that were mapped or already resident.
    pub minor: u64,
    /// Major faults: pages that had to be fetched from storage.
    pub major: u64,
}

impl ProcFaults {
    fn delta(&self, earlier: &Self) -> Self {
        Self {
            minor: self.minor.saturating_sub(earlier.minor),
            major: self.major.saturating_sub(earlier.major),
        }
    }
}

/// Reads the minor and major fault counters for a process.
pub fn read_proc_faults(pid: u32) -> Result<ProcFaults> {
    let stat = fs::read_to_string(format!("/proc/{pid}/stat")).context("read /proc/<pid>/stat")?;
    // The comm field is parenthesised and may contain spaces, so the fields
    // after the closing parenthesis are the ones with stable positions.
    let end = stat.rfind(')').context("malformed /proc/<pid>/stat")?;
    let fields: Vec<&str> = stat[end + 2..].split_whitespace().collect();
    if fields.len() < 10 {
        bail!("too few fields in /proc/{pid}/stat");
    }
    Ok(ProcFaults {
        minor: fields[7].parse().unwrap_or(0),
        major: fields[9].parse().unwrap_or(0),
    })
}

/// Pressure Stall Information, when the kernel exposes it.
///
/// PSI is the best single summary of memory pressure, but it needs
/// CONFIG_PSI, which plenty of running kernels are built without. Every read
/// therefore reports whether the data is present instead of returning zeroes
/// that would read as "no pressure".
#[derive(Debug, Clone, Copy, Default, PartialEq)]
pub struct Psi {
    /// True when /proc/pressure/memory could be read.
    pub available: bool,
    /// Share of the last 10s in which at least some task was stalled, in
    /// percent.
    pub some_pct: f32,
    /// Share of the last 10s in which all non-idle tasks were stalled, in
    /// percent.
    pub full_pct: f32,
}

/// Reads memory PSI, reporting unavailability rather than zeroes.
pub fn read_psi(path: &str) -> Psi {
    let Ok(content) = fs::read_to_string(path) else {
        return Psi::default();
    };
    let mut psi = Psi {
        available: true,
        ..Psi::default()
    };
    for line in content.lines() {
        let (which, value) = if let Some(rest) = line.strip_prefix("some") {
            ("some", parse_avg10(rest))
        } else if let Some(rest) = line.strip_prefix("full") {
            ("full", parse_avg10(rest))
        } else {
            continue;
        };
        match which {
            "some" => psi.some_pct = value,
            _ => psi.full_pct = value,
        }
    }
    psi
}

/// Extracts the avg10 value from a PSI line body, which is a space-separated
/// list of key=value pairs.
fn parse_avg10(body: &str) -> f32 {
    body.split_whitespace()
        .find_map(|part| part.strip_prefix("avg10="))
        .and_then(|value| value.parse().ok())
        .unwrap_or(0.0)
}

/// Swap currently in use, in KiB.
pub fn read_swap_used_kb() -> u64 {
    let Ok(content) = fs::read_to_string("/proc/meminfo") else {
        return 0;
    };
    let field = |name: &str| -> u64 {
        content
            .lines()
            .find_map(|line| line.strip_prefix(name))
            .and_then(|rest| rest.split_whitespace().next())
            .and_then(|value| value.parse().ok())
            .unwrap_or(0)
    };
    field("SwapTotal:").saturating_sub(field("SwapFree:"))
}

/// Formats a count of faults with thousands separators, so six digits are
/// readable at a glance.
pub fn format_faults(count: u64) -> String {
    let digits = count.to_string();
    let mut out = String::with_capacity(digits.len() + digits.len() / 3);
    for (index, ch) in digits.chars().enumerate() {
        if index > 0 && (digits.len() - index).is_multiple_of(3) {
            out.push(',');
        }
        out.push(ch);
    }
    out
}

/// One poll of every memory signal.
#[derive(Debug, Clone, Copy, Default)]
pub struct Sample {
    at: Duration,
    kernel: Totals,
    faults: ProcFaults,
    psi: Psi,
    swap_kb: u64,
}

/// A rate derived from two samples.
#[derive(Debug, Clone, Copy, Default)]
pub struct Rates {
    /// Wall time between the two samples.
    pub window: Duration,
    /// User page faults per second, from the kernel counters.
    pub faults_per_s: f64,
    /// Minor faults per second, from process accounting.
    pub minor_per_s: f64,
    /// Major faults per second, from process accounting.
    pub major_per_s: f64,
    /// Direct reclaim attempts per second, from the kernel counters.
    pub reclaims_per_s: f64,
    /// Highest PSI seen in the window.
    pub psi_some_pct: f32,
    /// Highest full PSI seen in the window.
    pub psi_full_pct: f32,
    /// Highest swap usage in the window, in KiB.
    pub swap_kb: u64,
}

impl Rates {
    /// Derives rates from two consecutive samples.
    pub fn between(first: &Sample, last: &Sample) -> Self {
        let window = last
            .at
            .saturating_sub(first.at)
            .max(Duration::from_millis(1));
        let seconds = window.as_secs_f64();
        let kernel = last.kernel.since(&first.kernel);
        let faults = last.faults.delta(&first.faults);
        Self {
            window,
            faults_per_s: kernel.faults as f64 / seconds,
            minor_per_s: faults.minor as f64 / seconds,
            major_per_s: faults.major as f64 / seconds,
            reclaims_per_s: kernel.reclaims as f64 / seconds,
            psi_some_pct: last.psi.some_pct.max(first.psi.some_pct),
            psi_full_pct: last.psi.full_pct.max(first.psi.full_pct),
            swap_kb: last.swap_kb.max(first.swap_kb),
        }
    }

    /// True when the kernel exposes PSI at all, which decides whether a zero
    /// means "no pressure" or "cannot tell".
    pub fn psi_available(&self) -> bool {
        self.psi_some_pct > 0.0 || self.psi_full_pct > 0.0
    }
}

pub fn run(args: MemoryArgs) -> Result<()> {
    let pid = args.pid;
    let process_name =
        process::read_name(pid).with_context(|| format!("cannot read process {pid}"))?;
    let initial_tids =
        process::thread_ids(pid).with_context(|| format!("cannot enumerate threads for {pid}"))?;

    let mut bpf = Ebpf::load(include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/fast-ebpf"
    )))
    .context("failed to load eBPF object; run as root or grant CAP_BPF and CAP_PERFMON")?;
    runtime::attach_tracepoint(&mut bpf, "exceptions", "page_fault_user")?;
    runtime::attach_tracepoint(&mut bpf, "vmscan", "mm_vmscan_direct_reclaim_begin")?;

    let mut target_tids = runtime::take_target_map(&mut bpf)?;
    let counters = CounterReader::new(&mut bpf)?;

    let mut first: Option<Sample> = None;
    let mut last = Sample::default();
    let summary = runtime::run_map_collection(
        &mut bpf,
        &mut target_tids,
        &mut runtime::NoPendingCleanup,
        &mut BTreeSet::new(),
        &initial_tids,
        runtime::MapCollectionOptions {
            pid,
            duration: args.duration,
            interval: POLL_INTERVAL,
            mode: COLLECT_MEMORY,
        },
        |at| {
            let sample = Sample {
                at,
                kernel: counters.totals().unwrap_or_default(),
                faults: read_proc_faults(pid).unwrap_or(ProcFaults { minor: 0, major: 0 }),
                psi: read_psi("/proc/pressure/memory"),
                swap_kb: read_swap_used_kb(),
            };
            first.get_or_insert(sample);
            last = sample;
        },
    )?;

    print_report(&process_name, pid, &summary, first.as_ref(), &last);
    Ok(())
}

fn print_report(
    name: &str,
    pid: u32,
    summary: &runtime::CollectionSummary,
    first: Option<&Sample>,
    last: &Sample,
) {
    println!("PID: {name} ({pid})");
    println!("Duration: {}", humantime::format_duration(summary.elapsed));
    if summary.interrupted {
        println!("Status: interrupted");
    }
    if summary.process_exited {
        println!("Status: process exited");
    }

    let Some(first) = first else {
        println!("No samples collected.");
        return;
    };
    let rates = Rates::between(first, last);
    println!("Window: {}", humantime::format_duration(rates.window));
    println!();
    println!("Page faults");
    println!(
        "  eBPF user faults: {} ({:.0}/s)",
        format_faults(last.kernel.faults),
        rates.faults_per_s
    );
    println!(
        "  minor {} ({:.0}/s)  major {} ({:.0}/s)",
        format_faults(last.faults.minor),
        rates.minor_per_s,
        format_faults(last.faults.major),
        rates.major_per_s
    );
    println!(
        "  direct reclaim: {} ({:.1}/s)",
        format_faults(last.kernel.reclaims),
        rates.reclaims_per_s
    );
    println!();
    println!("Pressure");
    println!(
        "  PSI memory: {}",
        if rates.psi_available() {
            format!(
                "some {:.1}%  full {:.1}%",
                rates.psi_some_pct, rates.psi_full_pct
            )
        } else {
            "unavailable (kernel built without CONFIG_PSI)".to_string()
        }
    );
    println!("  swap used: {} KiB", rates.swap_kb);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn totals_difference_is_per_counter() {
        let first = Totals {
            faults: 100,
            reclaims: 2,
        };
        let second = Totals {
            faults: 350,
            reclaims: 5,
        };
        assert_eq!(
            second.since(&first),
            Totals {
                faults: 250,
                reclaims: 3
            }
        );
    }

    #[test]
    fn totals_difference_saturates_at_zero() {
        // A counter that went backwards means the map was resized; reporting a
        // negative rate would be worse than reporting none.
        let later = Totals {
            faults: 5,
            reclaims: 0,
        };
        let earlier = Totals {
            faults: 100,
            reclaims: 3,
        };
        assert_eq!(
            later.since(&earlier),
            Totals {
                faults: 0,
                reclaims: 0
            }
        );
    }

    #[test]
    fn proc_faults_difference() {
        let first = ProcFaults {
            minor: 10,
            major: 1,
        };
        let second = ProcFaults {
            minor: 60,
            major: 4,
        };
        assert_eq!(
            second.delta(&first),
            ProcFaults {
                minor: 50,
                major: 3
            }
        );
    }

    #[test]
    fn parses_psi_lines() {
        let dir = std::env::temp_dir().join(format!("fast-psi-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("memory");
        fs::write(
            &path,
            "some avg10=12.34 avg60=5.00 avg300=1.00 total=12345\nfull avg10=2.00 avg60=1.00 total=2345\n",
        )
        .unwrap();

        let psi = read_psi(path.to_str().unwrap());
        assert!(psi.available);
        assert!((psi.some_pct - 12.34).abs() < 0.01);
        assert!((psi.full_pct - 2.00).abs() < 0.01);
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn missing_psi_is_reported_as_unavailable() {
        // A kernel without CONFIG_PSI must not look like a kernel with no
        // pressure: the two need different verdicts.
        let psi = read_psi("/nonexistent/pressure/memory");
        assert!(!psi.available);
        assert_eq!(psi.some_pct, 0.0);
        assert_eq!(psi.full_pct, 0.0);
    }

    #[test]
    fn extracts_avg10_from_a_line() {
        assert!((parse_avg10(" avg10=7.50 avg60=1.00") - 7.50).abs() < 0.001);
        assert_eq!(parse_avg10(" avg60=1.00"), 0.0);
    }

    #[test]
    fn formats_faults_with_separators() {
        assert_eq!(format_faults(0), "0");
        assert_eq!(format_faults(999), "999");
        assert_eq!(format_faults(1_000), "1,000");
        assert_eq!(format_faults(12_345), "12,345");
        assert_eq!(format_faults(1_234_567), "1,234,567");
    }

    #[test]
    fn reads_this_process_faults() {
        let pid = std::process::id();
        let faults = read_proc_faults(pid).expect("read own fault counters");
        assert!(faults.minor > 0, "a running process has taken minor faults");
    }
}
