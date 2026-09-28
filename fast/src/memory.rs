use std::{collections::BTreeSet, fs, time::Duration};

use anyhow::{Context, Result, bail};
use aya::{
    Ebpf, include_bytes_aligned,
    maps::{HashMap as AyaHashMap, MapData},
};
use fast_common::{COLLECT_MEMORY, MemoryCounters};

use crate::{
    cli::MemoryArgs,
    json::{self, Envelope, Format},
    process, runtime,
};

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
    /// Wall time since collection started.
    pub at: Duration,
    /// Kernel-side counters, summed over the target threads.
    pub kernel: Totals,
    /// Process accounting fault counters.
    pub faults: ProcFaults,
    /// Memory PSI at this sample.
    pub psi: Psi,
    /// Swap in use at this sample, in KiB.
    pub swap_kb: u64,
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
    /// Swap usage at the start of the window, in KiB.
    pub swap_start_kb: u64,
}

impl Rates {
    /// Swap that appeared during the window, in KiB.
    ///
    /// Swap already resident says something about how the machine is
    /// configured; swap that appeared during the window says something about
    /// what this process did.
    pub fn swap_delta_kb(&self) -> u64 {
        self.swap_kb.saturating_sub(self.swap_start_kb)
    }

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
            swap_start_kb: first.swap_kb,
        }
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

    // Both output formats need the same derived numbers, so they are computed
    // once here rather than inside whichever printer happens to run.
    let rates = first.as_ref().map(|first| Rates::between(first, &last));
    let psi_available = last.psi.available;

    if args.format.format == Format::Json {
        json::emit(
            args.format.format,
            &Envelope::new(
                "memory",
                pid,
                Some(process_name),
                summary.elapsed,
                summary.interrupted,
                summary.process_exited,
                crate::json_payloads::memory_json(rates.as_ref(), psi_available, &last),
            ),
        );
    } else {
        print_report(&process_name, pid, &summary, first.as_ref(), &last);
    }
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
    // Whether PSI is readable decides if a zero means "no pressure" or
    // "cannot tell", so it is carried separately from the values.
    let psi_available = last.psi.available;
    let (verdict, reasons) = Verdict::assess(&rates, psi_available);

    println!("Window: {}", humantime::format_duration(rates.window));
    println!("Verdict: {}", verdict.label());
    for reason in &reasons {
        println!("  - {reason}");
    }
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
        if psi_available {
            format!(
                "some {:.1}%  full {:.1}%",
                rates.psi_some_pct, rates.psi_full_pct
            )
        } else {
            // Naming the absence matters: a zero here would otherwise read as
            // "no pressure" when it really means "cannot tell".
            "unavailable (kernel built without CONFIG_PSI)".to_string()
        }
    );
    println!(
        "  swap used: {} KiB ({} KiB new over the window)",
        rates.swap_kb,
        rates.swap_delta_kb()
    );
}

/// Documented thresholds for the memory verdict.
///
/// They are collected here rather than inlined so the diagnosis report can
/// rank memory against the same numbers, and so a change to what counts as
/// pressure is a single reviewable edit.
pub mod threshold {
    /// Major faults per second above which the process is fetching pages from
    /// storage. One per second is well above background noise and low enough
    /// to catch a genuinely disk-bound process.
    pub const MAJOR_FAULTS_PER_S: f64 = 1.0;

    /// Direct reclaim attempts per second above which the process is stalling
    /// on memory itself. This is the strongest per-process signal there is:
    /// the task has nowhere to run until pages come back. A tenth of a
    /// reclaim per second is already sustained, not a one-off.
    pub const RECLAIMS_PER_S: f64 = 0.1;

    /// PSI memory some above which the system is spending real time stalled.
    pub const PSI_SOME_PCT: f32 = 1.0;

    /// PSI memory full above which every non-idle task is stalled at once,
    /// which stops being a local problem.
    pub const PSI_FULL_PCT: f32 = 5.0;

    /// Minor faults per second above which the process is doing enough
    /// allocation churn to be worth naming even when nothing is under
    /// pressure. It is a hint, not a diagnosis.
    pub const MINOR_FAULTS_PER_S_CHURN: f64 = 100_000.0;

    /// Swap growth in KiB over the window that counts as the system leaning on
    /// swap rather than merely having some resident.
    pub const SWAP_DELTA_KB: u64 = 1024;
}

/// What the measurements say about a process' memory.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// Nothing worth naming: no faults, no reclaim, no pressure.
    Idle,
    /// The process is allocating hard but nothing is wrong: a high minor fault
    /// rate with no storage, reclaim or PSI cost behind it.
    PageChurn,
    /// The process is fetching pages from storage or reclaiming for itself.
    Pressure,
    /// Every non-idle task is stalled at once, so the pressure is system wide.
    Severe,
}

impl Verdict {
    /// The headline word in the report.
    pub fn label(&self) -> &'static str {
        match self {
            Self::Idle => "idle",
            Self::PageChurn => "page churn",
            Self::Pressure => "memory pressure",
            Self::Severe => "severe memory pressure",
        }
    }

    /// Derives the verdict and the reasons behind it from one window.
    ///
    /// The reasons come back alongside the label because a verdict a user
    /// cannot check is one they will not trust: each string names the
    /// measurement and the threshold it crossed. `psi_available` is passed
    /// separately so an absent PSI cannot be mistaken for a zero reading.
    pub fn assess(rates: &Rates, psi_available: bool) -> (Self, Vec<String>) {
        use threshold::*;

        let mut reasons = Vec::new();
        let mut pressure = false;

        if rates.major_per_s >= MAJOR_FAULTS_PER_S {
            reasons.push(format!(
                "{:.1} major faults/s, at or above the {MAJOR_FAULTS_PER_S:.1}/s threshold: pages are coming from storage",
                rates.major_per_s
            ));
            pressure = true;
        }
        if rates.reclaims_per_s >= RECLAIMS_PER_S {
            reasons.push(format!(
                "{:.1} direct reclaims/s, at or above the {RECLAIMS_PER_S:.1}/s threshold: the process stalled waiting for memory",
                rates.reclaims_per_s
            ));
            pressure = true;
        }
        if rates.swap_delta_kb() >= SWAP_DELTA_KB {
            reasons.push(format!(
                "{} KiB of new swap over the window, at or above the {SWAP_DELTA_KB} KiB threshold: the system leaned on swap",
                rates.swap_delta_kb()
            ));
            pressure = true;
        }
        if psi_available {
            if rates.psi_full_pct >= PSI_FULL_PCT {
                reasons.push(format!(
                    "memory PSI {:.1}% full, at or above the {PSI_FULL_PCT:.1}% threshold: all non-idle tasks are stalled",
                    rates.psi_full_pct
                ));
                return (Self::Severe, reasons);
            }
            if rates.psi_some_pct >= PSI_SOME_PCT {
                reasons.push(format!(
                    "memory PSI {:.1}% some, at or above the {PSI_SOME_PCT:.1}% threshold: tasks are spending time stalled",
                    rates.psi_some_pct
                ));
                pressure = true;
            }
        }

        if pressure {
            return (Self::Pressure, reasons);
        }
        if rates.minor_per_s >= MINOR_FAULTS_PER_S_CHURN {
            reasons.push(format!(
                "{:.0} minor faults/s, at or above the {MINOR_FAULTS_PER_S_CHURN:.0}/s threshold: heavy allocation, but nothing under pressure",
                rates.minor_per_s
            ));
            return (Self::PageChurn, reasons);
        }
        reasons.push(format!(
            "{:.0} minor faults/s, {:.1} major faults/s and {:.1} reclaims/s, all under their thresholds",
            rates.minor_per_s, rates.major_per_s, rates.reclaims_per_s
        ));
        (Self::Idle, reasons)
    }
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

#[cfg(test)]
mod verdict_tests {
    use super::*;

    /// A window where nothing is happening.
    fn idle() -> Rates {
        Rates {
            window: Duration::from_secs(10),
            faults_per_s: 12.0,
            minor_per_s: 12.0,
            major_per_s: 0.0,
            reclaims_per_s: 0.0,
            psi_some_pct: 0.0,
            psi_full_pct: 0.0,
            swap_kb: 0,
            swap_start_kb: 0,
        }
    }

    #[test]
    fn an_uneventful_process_is_idle() {
        let (verdict, reasons) = Verdict::assess(&idle(), true);
        assert_eq!(verdict, Verdict::Idle);
        assert_eq!(verdict.label(), "idle");
        assert_eq!(reasons.len(), 1);
        assert!(reasons[0].contains("under their thresholds"));
    }

    #[test]
    fn heavy_allocation_without_cost_is_churn_not_pressure() {
        // The distinction that matters: a million faults a second is only
        // worth naming as churn while nothing is actually stalling.
        let rates = Rates {
            minor_per_s: 1_000_000.0,
            ..idle()
        };
        let (verdict, reasons) = Verdict::assess(&rates, true);
        assert_eq!(verdict, Verdict::PageChurn);
        assert!(reasons[0].contains("heavy allocation"));
    }

    #[test]
    fn major_faults_mean_pressure() {
        let rates = Rates {
            major_per_s: 12.5,
            ..idle()
        };
        let (verdict, reasons) = Verdict::assess(&rates, true);
        assert_eq!(verdict, Verdict::Pressure);
        assert!(reasons[0].contains("coming from storage"));
    }

    #[test]
    fn direct_reclaim_means_pressure_even_with_no_major_faults() {
        // This is the signal that survives on a machine with no disk-backed
        // pages, which is exactly the case the QEMU guest is in.
        let rates = Rates {
            reclaims_per_s: 3.0,
            ..idle()
        };
        let (verdict, reasons) = Verdict::assess(&rates, true);
        assert_eq!(verdict, Verdict::Pressure);
        assert!(reasons[0].contains("stalled waiting for memory"));
    }

    #[test]
    fn swap_growth_means_pressure() {
        let rates = Rates {
            swap_start_kb: 0,
            swap_kb: 8 * 1024,
            ..idle()
        };
        let (verdict, reasons) = Verdict::assess(&rates, true);
        assert_eq!(verdict, Verdict::Pressure);
        assert!(reasons[0].contains("leaned on swap"));
    }

    #[test]
    fn resident_swap_alone_is_not_pressure() {
        // Swap that was already in use says how the machine is configured, not
        // what this process just did, so it must not raise the verdict.
        let rates = Rates {
            swap_start_kb: 8 * 1024,
            swap_kb: 8 * 1024,
            ..idle()
        };
        let (verdict, _) = Verdict::assess(&rates, true);
        assert_eq!(verdict, Verdict::Idle);
    }

    #[test]
    fn psi_some_means_pressure() {
        let rates = Rates {
            psi_some_pct: 3.0,
            ..idle()
        };
        let (verdict, reasons) = Verdict::assess(&rates, true);
        assert_eq!(verdict, Verdict::Pressure);
        assert!(reasons[0].contains("spending time stalled"));
    }

    #[test]
    fn psi_full_means_severe_and_outranks_everything_else() {
        let rates = Rates {
            psi_some_pct: 90.0,
            psi_full_pct: 40.0,
            major_per_s: 500.0,
            ..idle()
        };
        let (verdict, reasons) = Verdict::assess(&rates, true);
        assert_eq!(verdict, Verdict::Severe);
        assert!(reasons.last().unwrap().contains("all non-idle tasks"));
    }

    #[test]
    fn a_missing_psi_never_raises_the_verdict_on_its_own() {
        // Same measurements, PSI absent. The verdict must be unchanged, and no
        // PSI reason may appear, so a kernel without CONFIG_PSI cannot invent
        // pressure out of an absent file.
        let rates = Rates {
            psi_some_pct: 50.0,
            psi_full_pct: 20.0,
            ..idle()
        };
        let (verdict, reasons) = Verdict::assess(&rates, false);
        assert_eq!(verdict, Verdict::Idle);
        assert!(!reasons.iter().any(|reason| reason.contains("PSI")));
    }

    #[test]
    fn a_missing_psi_does_not_hide_other_evidence() {
        let rates = Rates {
            major_per_s: 40.0,
            psi_some_pct: 50.0,
            psi_full_pct: 20.0,
            ..idle()
        };
        let (verdict, reasons) = Verdict::assess(&rates, false);
        assert_eq!(verdict, Verdict::Pressure);
        assert!(reasons[0].contains("coming from storage"));
    }

    #[test]
    fn reasons_accumulate_across_signals() {
        let rates = Rates {
            major_per_s: 5.0,
            reclaims_per_s: 2.0,
            psi_some_pct: 4.0,
            swap_start_kb: 0,
            swap_kb: 4 * 1024,
            ..idle()
        };
        let (verdict, reasons) = Verdict::assess(&rates, true);
        assert_eq!(verdict, Verdict::Pressure);
        assert_eq!(
            reasons.len(),
            4,
            "every crossed signal is named: {reasons:?}"
        );
    }

    #[test]
    fn swap_delta_is_relative_to_the_window_start() {
        let rates = Rates {
            swap_start_kb: 4096,
            swap_kb: 6144,
            ..idle()
        };
        assert_eq!(rates.swap_delta_kb(), 2048);
    }

    #[test]
    fn swap_delta_never_goes_negative() {
        let rates = Rates {
            swap_start_kb: 8192,
            swap_kb: 0,
            ..idle()
        };
        assert_eq!(rates.swap_delta_kb(), 0);
    }
}
