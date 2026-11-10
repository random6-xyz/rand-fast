//! The `fast incidents` commands: reading what the recorder wrote.
//!
//! # The bundle is the evidence, not a summary of it
//!
//! A reader may not recompute anything. The daemon recorded a measurement, the
//! thresholds that were in force, and a diagnosis derived from that interval;
//! re-deriving any of them here would produce a number that no longer matches
//! what was recorded, and an operator comparing two bundles would have no way
//! to know which one had been recomputed. So the JSON outputs embed the
//! on-disk documents verbatim (as raw JSON, not a re-serialization) and the
//! text outputs print the recorded values.
//!
//! # Absence is reported, never filled in
//!
//! A measurement the recorder did not take, or a bundle written before the
//! manifest carried wall-clock time, is shown as absent. It is never estimated
//! from file timestamps and never rendered as zero: "0 retransmissions" and
//! "retransmissions were not attributable" are different facts, and an
//! incident report that confuses them is worse than no report.

use std::{
    ffi::OsStr,
    fmt::Write as _,
    fs::OpenOptions,
    io::Write as _,
    os::unix::fs::OpenOptionsExt,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result, bail};
use serde::Serialize;
use serde_json::{Value, value::RawValue};

use crate::{
    cli::{
        IncidentExportArgs, IncidentListArgs, IncidentShowArgs, IncidentSummaryArgs,
        IncidentsCommand, ReportFormat,
    },
    incident_store::{BULK_CAP, Bundle, Store, TEXT_CAP},
    json::Format,
    utc,
};

/// The reader's schema. New commands get a new number because a consumer has
/// to handle documents that are not process reports at all.
const SCHEMA: &str = "rand-fast/v3";

/// A bundle is complete when the daemon wrote its last document.
const COMPLETE: &str = "complete.json";

const MANIFEST: &str = "manifest.json";
const DIAGNOSIS: &str = "diagnosis.json";
const INTERVALS: &str = "intervals.json";
const SLOW_SAMPLES: &str = "slow-samples.json";
const SUMMARY: &str = "summary.txt";

pub(crate) fn run(command: IncidentsCommand) -> Result<()> {
    match command {
        IncidentsCommand::List(args) => list(args),
        IncidentsCommand::Show(args) => show(args),
        IncidentsCommand::Export(args) => export(args),
        IncidentsCommand::Summary(args) => summary(args),
    }
}

/// One entry of the incident directory that is not a bundle.
struct Skipped {
    name: String,
    reason: String,
}

/// One recorded incident, as much of it as a listing needs.
struct Incident {
    name: String,
    files: Vec<(String, u64)>,
    size_bytes: u64,
    manifest: Option<Value>,
    diagnosis: Option<Value>,
    complete: bool,
    recorded_at_unix_s: Option<f64>,
    recording_started_unix_s: Option<f64>,
    recorded_at_s: Option<f64>,
    triggered_by: Vec<Value>,
    thresholds: Vec<Value>,
    interval: Option<Value>,
    history: Option<Value>,
    causes: Vec<Value>,
    not_collected: Vec<String>,
    semantics: Option<String>,
    complete_present: bool,
    damage: Vec<String>,
}

impl Incident {
    fn readable(&self) -> bool {
        self.manifest.is_some()
    }

    fn complete_marker_present(&self) -> bool {
        self.complete_present
    }

    /// The first ranked cause, which is the one a listing has room for.
    fn top_cause(&self) -> Option<&Value> {
        self.causes.first()
    }

    fn tcp_available(&self) -> Option<bool> {
        self.interval
            .as_ref()
            .and_then(|interval| interval.get("tcp_available"))
            .and_then(Value::as_bool)
    }

    fn bundle_schema(&self) -> Option<&str> {
        self.manifest
            .as_ref()
            .and_then(|manifest| manifest.get("schema"))
            .and_then(Value::as_str)
    }

    fn carried(&self, key: &str) -> Option<u64> {
        self.history
            .as_ref()
            .and_then(|history| history.get(key))
            .and_then(Value::as_u64)
    }

    fn ring_window_s(&self) -> Option<f64> {
        self.history
            .as_ref()
            .and_then(|history| history.get("ring_window_s"))
            .and_then(Value::as_f64)
    }
}

/// What a directory holds, in the order a report shows it.
struct Scan {
    path: PathBuf,
    present: bool,
    incidents: Vec<Incident>,
    skipped: Vec<Skipped>,
}

fn scan(path: &Path) -> Result<Scan> {
    let Some(store) = Store::open_optional(path)? else {
        return Ok(Scan {
            path: path.to_path_buf(),
            present: false,
            incidents: Vec::new(),
            skipped: Vec::new(),
        });
    };
    let mut scan = Scan {
        path: path.to_path_buf(),
        present: true,
        incidents: Vec::new(),
        skipped: Vec::new(),
    };
    for entry in store.entries()? {
        let name = entry.name.to_string_lossy().into_owned();
        let reason = match entry.kind {
            crate::incident_store::Kind::Directory => match store.open_bundle(&entry.name) {
                Ok(bundle) => {
                    scan.incidents.push(inspect(bundle));
                    continue;
                }
                Err(reason) => reason,
            },
            crate::incident_store::Kind::Symlink => "symlink".to_string(),
            crate::incident_store::Kind::File | crate::incident_store::Kind::Other => {
                "not a directory".to_string()
            }
        };
        scan.skipped.push(Skipped { name, reason });
    }
    sort(&mut scan.incidents);
    Ok(scan)
}

/// Newest first by recorded time. A bundle without a recorded time sorts last
/// and by name, so a legacy incident is visible instead of misplaced.
fn sort(incidents: &mut [Incident]) {
    incidents.sort_by(
        |left, right| match (left.recorded_at_unix_s, right.recorded_at_unix_s) {
            (Some(left_at), Some(right_at)) => right_at
                .partial_cmp(&left_at)
                .unwrap_or(std::cmp::Ordering::Equal)
                .then_with(|| right.name.cmp(&left.name)),
            (Some(_), None) => std::cmp::Ordering::Less,
            (None, Some(_)) => std::cmp::Ordering::Greater,
            (None, None) => right.name.cmp(&left.name),
        },
    );
}

fn inspect(bundle: Bundle) -> Incident {
    let name = bundle.name().to_string();
    let mut incident = Incident {
        name,
        files: Vec::new(),
        size_bytes: 0,
        manifest: None,
        diagnosis: None,
        complete: false,
        recorded_at_unix_s: None,
        recording_started_unix_s: None,
        recorded_at_s: None,
        triggered_by: Vec::new(),
        thresholds: Vec::new(),
        interval: None,
        history: None,
        causes: Vec::new(),
        not_collected: Vec::new(),
        semantics: None,
        complete_present: false,
        damage: Vec::new(),
    };
    match bundle.files() {
        Ok(files) => {
            incident.size_bytes = files.iter().map(|(_, bytes)| bytes).sum();
            incident.files = files;
        }
        Err(error) => incident.damage.push(format!("bundle listing: {error}")),
    }
    match bundle.read_json(MANIFEST, TEXT_CAP) {
        Ok(Some(Value::Object(_))) => {}
        Ok(Some(_)) => incident
            .damage
            .push(format!("{MANIFEST} is not a JSON object")),
        Ok(None) => incident.damage.push(format!("{MANIFEST} is missing")),
        Err(error) => incident.damage.push(format!("{MANIFEST}: {error}")),
    }
    if incident.damage.is_empty() {
        // Only a parsed manifest can populate the fields, and only a manifest
        // that parsed counts as readable.
        incident.manifest = bundle.read_json(MANIFEST, TEXT_CAP).ok().flatten();
        if let Some(manifest) = incident.manifest.clone() {
            read_manifest(&mut incident, &manifest);
        }
    }
    match bundle.read_json(DIAGNOSIS, TEXT_CAP) {
        Ok(Some(diagnosis)) => {
            incident.causes = diagnosis
                .get("causes")
                .and_then(Value::as_array)
                .cloned()
                .unwrap_or_default();
            incident.not_collected = diagnosis
                .get("not_collected")
                .and_then(Value::as_array)
                .map(|reasons| {
                    reasons
                        .iter()
                        .filter_map(Value::as_str)
                        .map(str::to_string)
                        .collect()
                })
                .unwrap_or_default();
            incident.diagnosis = Some(diagnosis);
        }
        // A missing diagnosis is a bundle property (an older or interrupted
        // write), not damage: nobody recorded it.
        Ok(None) => {}
        Err(error) => incident.damage.push(format!("{DIAGNOSIS}: {error}")),
    }
    match bundle.read(COMPLETE, TEXT_CAP) {
        Ok(Some(_)) => incident.complete_present = true,
        Ok(None) => {}
        Err(error) => incident.damage.push(format!("{COMPLETE}: {error}")),
    }
    incident.complete = incident.complete_present;
    incident
}

fn read_manifest(incident: &mut Incident, manifest: &Value) {
    incident.recorded_at_unix_s = manifest.get("recorded_at_unix_s").and_then(Value::as_f64);
    incident.recording_started_unix_s = manifest
        .get("recording_started_unix_s")
        .and_then(Value::as_f64);
    incident.recorded_at_s = manifest.get("recorded_at_s").and_then(Value::as_f64);
    incident.triggered_by = manifest
        .get("triggered_by")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    incident.thresholds = manifest
        .get("thresholds")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    incident.history = manifest.get("history").cloned();
    if let Some(interval) = manifest.get("interval") {
        incident.semantics = interval
            .get("measurement_semantics")
            .and_then(Value::as_str)
            .map(str::to_string);
        incident.interval = Some(interval.clone());
    }
}

/// The subset of a scan a filtered report shows, with the counts that explain
/// what was left out.
struct Selection {
    shown: Vec<usize>,
    unreadable: usize,
    without_timestamp: usize,
}

/// Applies `--since` to a scan.
///
/// A bundle without a recorded time cannot be placed in a window, so it is
/// excluded and counted rather than guessed at from its file timestamp. An
/// unreadable bundle cannot be placed in a window either, but it is counted as
/// unreadable, which is the more specific problem.
fn select(incidents: &[Incident], since: Option<std::time::Duration>) -> Selection {
    let cutoff = since
        .zip(utc::now_unix_seconds())
        .map(|(since, now)| now - since.as_secs_f64());
    let mut selection = Selection {
        shown: Vec::new(),
        unreadable: 0,
        without_timestamp: 0,
    };
    for (index, incident) in incidents.iter().enumerate() {
        if !incident.readable() {
            selection.unreadable += 1;
            if cutoff.is_some() {
                continue;
            }
        }
        match (cutoff, incident.recorded_at_unix_s) {
            (Some(cutoff), Some(recorded)) if recorded < cutoff => continue,
            (Some(_), Some(_)) => {}
            (Some(_), None) => {
                if incident.readable() {
                    selection.without_timestamp += 1;
                }
                continue;
            }
            (None, _) => {}
        }
        selection.shown.push(index);
    }
    selection
}

fn list(args: IncidentListArgs) -> Result<()> {
    let scan = scan(&args.dir.dir)?;
    let selection = select(&scan.incidents, args.since);
    let total = selection.shown.len();
    let shown: Vec<&Incident> = selection
        .shown
        .iter()
        .take(if args.limit == 0 {
            usize::MAX
        } else {
            args.limit
        })
        .map(|index| &scan.incidents[*index])
        .collect();

    match args.format.format {
        Format::Text => print!("{}", list_text(&scan, &selection, &shown, args.since)),
        Format::Json => {
            let document = serde_json::json!({
                "schema": SCHEMA,
                "command": "incidents.list",
                "directory": scan.path.display().to_string(),
                "directory_exists": scan.present,
                "filters": {
                    "since_s": args.since.map(|since| since.as_secs_f64()),
                    "limit": args.limit,
                },
                "count": shown.len(),
                "total": total,
                "unreadable_count": selection.unreadable,
                "excluded_without_timestamp": selection.without_timestamp,
                "incidents": shown.iter().map(|incident| list_entry(incident)).collect::<Vec<_>>(),
                "skipped": scan.skipped.iter().map(|skipped| serde_json::json!({
                    "name": skipped.name,
                    "reason": skipped.reason,
                })).collect::<Vec<_>>(),
            });
            print_json(&document)?;
        }
    }
    Ok(())
}

fn list_entry(incident: &Incident) -> Value {
    let top_cause = incident.top_cause().map(|cause| {
        serde_json::json!({
            "cause": cause.get("cause").and_then(Value::as_str),
            "confidence_pct": cause.get("confidence_pct").and_then(Value::as_f64),
        })
    });
    serde_json::json!({
        "name": incident.name,
        "recorded_at_unix_s": incident.recorded_at_unix_s,
        "recording_started_unix_s": incident.recording_started_unix_s,
        "recorded_at_s": incident.recorded_at_s,
        "bundle_schema": incident.bundle_schema(),
        "complete": incident.complete,
        "size_bytes": incident.size_bytes,
        "intervals_carried": incident.carried("intervals_carried"),
        "interval_limit": incident.carried("interval_limit"),
        "ring_window_s": incident.ring_window_s(),
        "triggered_by": incident.triggered_by,
        "top_cause": top_cause,
        "tcp_available": incident.tcp_available(),
        "readable": incident.readable(),
        "reason": (!incident.damage.is_empty()).then(|| incident.damage.join("; ")),
    })
}

fn list_text(
    scan: &Scan,
    selection: &Selection,
    shown: &[&Incident],
    since: Option<std::time::Duration>,
) -> String {
    let mut text = String::new();
    if !scan.present {
        writeln!(
            text,
            "No incident directory at {} yet; the daemon has not recorded anything.",
            scan.path.display()
        )
        .unwrap();
        return text;
    }
    if since.is_some() {
        writeln!(
            text,
            "Window: last {}",
            humantime::format_duration(since.unwrap_or_default())
        )
        .unwrap();
        text.push('\n');
    }
    if shown.is_empty() {
        writeln!(text, "No incidents recorded in {}.", scan.path.display()).unwrap();
    } else {
        writeln!(
            text,
            "{:<30}  {:<20}  {:<9}  {:<19}  {:<23}  {:>10}",
            "NAME", "RECORDED (UTC)", "COMPLETE", "TRIGGERS", "TOP CAUSE", "SIZE"
        )
        .unwrap();
        for incident in shown {
            let recorded = incident
                .recorded_at_unix_s
                .map(utc::timestamp)
                .unwrap_or_else(|| "-".to_string());
            let complete = match (incident.readable(), incident.complete_marker_present()) {
                (false, _) => "unreadable",
                (true, true) => "yes",
                (true, false) => "no",
            };
            let triggered = if !incident.readable() {
                "-".to_string()
            } else {
                let names: Vec<&str> = incident
                    .triggered_by
                    .iter()
                    .filter_map(|trigger| trigger.get("signal").and_then(Value::as_str))
                    .collect();
                if names.is_empty() {
                    "-".to_string()
                } else {
                    names.join(",")
                }
            };
            let cause = match incident.top_cause() {
                Some(cause) => format_cause(cause),
                None if !incident.readable() => "see reason below".to_string(),
                None => "-".to_string(),
            };
            writeln!(
                text,
                "{:<30}  {:<20}  {:<9}  {:<19}  {:<23}  {:>10}",
                truncate(&incident.name, 30),
                recorded,
                complete,
                truncate(&triggered, 19),
                truncate(&cause, 23),
                crate::daemon::human_bytes(incident.size_bytes),
            )
            .unwrap();
        }
    }
    text.push('\n');
    writeln!(
        text,
        "{} incident(s) shown of {} in {}",
        shown.len(),
        scan.incidents.len(),
        scan.path.display()
    )
    .unwrap();
    let mut notes = Vec::new();
    if selection.unreadable > 0 {
        notes.push(format!("{} unreadable", selection.unreadable));
    }
    if selection.without_timestamp > 0 {
        notes.push(format!(
            "{} without a recorded time (excluded by --since)",
            selection.without_timestamp
        ));
    }
    if !scan.skipped.is_empty() {
        notes.push(format!("{} skipped", scan.skipped.len()));
    }
    if !notes.is_empty() {
        writeln!(text, "Not shown: {}", notes.join(", ")).unwrap();
    }
    for incident in shown.iter().filter(|incident| !incident.readable()) {
        writeln!(text, "  {}: {}", incident.name, incident.damage.join("; ")).unwrap();
    }
    for skipped in &scan.skipped {
        writeln!(text, "  {}: {} (skipped)", skipped.name, skipped.reason).unwrap();
    }
    text
}

/// The documents of one bundle, embedded exactly as recorded.
struct Documents {
    manifest: Option<Box<RawValue>>,
    diagnosis: Option<Box<RawValue>>,
    intervals: Option<Box<RawValue>>,
    slow_samples: Option<Box<RawValue>>,
    complete: Option<Box<RawValue>>,
    summary: Option<String>,
    missing: Vec<String>,
    damage: Vec<String>,
}

impl Documents {
    fn load(dir: &Path, name: &str) -> Result<Self> {
        let store = Store::open_optional(dir)?
            .with_context(|| format!("no incident directory at {}", dir.display()))?;
        let bundle = store
            .open_bundle(OsStr::new(name))
            .map_err(|reason| anyhow::anyhow!("cannot read {name}: {reason}"))?;
        let mut documents = Self {
            manifest: None,
            diagnosis: None,
            intervals: None,
            slow_samples: None,
            complete: None,
            summary: None,
            missing: Vec::new(),
            damage: Vec::new(),
        };
        documents.manifest = documents.json(&bundle, MANIFEST, TEXT_CAP);
        documents.diagnosis = documents.json(&bundle, DIAGNOSIS, TEXT_CAP);
        documents.intervals = documents.json(&bundle, INTERVALS, BULK_CAP);
        documents.slow_samples = documents.json(&bundle, SLOW_SAMPLES, BULK_CAP);
        documents.complete = documents.json(&bundle, COMPLETE, TEXT_CAP);
        match bundle.read(SUMMARY, TEXT_CAP) {
            Ok(Some(bytes)) => match String::from_utf8(bytes) {
                Ok(text) => documents.summary = Some(text),
                Err(_) => documents
                    .damage
                    .push(format!("{SUMMARY} is not valid UTF-8")),
            },
            Ok(None) => documents.missing.push(SUMMARY.to_string()),
            Err(error) => documents.damage.push(format!("{SUMMARY}: {error}")),
        }
        Ok(documents)
    }

    fn json(&mut self, bundle: &Bundle, name: &str, cap: u64) -> Option<Box<RawValue>> {
        match bundle.read(name, cap) {
            Ok(Some(bytes)) => match std::str::from_utf8(&bytes) {
                Ok(text) => match serde_json::from_str::<Box<RawValue>>(text) {
                    Ok(raw) => Some(raw),
                    Err(_) => {
                        self.damage.push(format!("{name} is not valid JSON"));
                        None
                    }
                },
                Err(_) => {
                    self.damage.push(format!("{name} is not valid UTF-8"));
                    None
                }
            },
            Ok(None) => {
                self.missing.push(name.to_string());
                None
            }
            Err(error) => {
                self.damage.push(format!("{name}: {error}"));
                None
            }
        }
    }

    fn value(&self, raw: &Option<Box<RawValue>>) -> Option<Value> {
        raw.as_ref()
            .and_then(|raw| serde_json::from_str(raw.get()).ok())
    }
}

struct Resolved {
    incident: Incident,
    documents: Documents,
}

impl std::fmt::Debug for Resolved {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Resolved")
            .field("name", &self.incident.name)
            .finish()
    }
}

/// Resolves `NAME` or `latest` against a directory and loads its documents.
///
/// `show` and `export` share this so that "the newest incident" means the same
/// thing in both, and so that a damaged document is reported by name instead
/// of rendering a plausible but invented report.
fn resolve(dir: &Path, requested: &str) -> Result<Resolved> {
    let scan = scan(dir)?;
    let incident = if requested == "latest" {
        scan.incidents
            .iter()
            .find(|incident| incident.readable())
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "no readable incident in {}{}",
                    scan.path.display(),
                    if scan.skipped.is_empty() {
                        "; the daemon has not recorded anything yet".to_string()
                    } else {
                        format!(" ({} entries skipped)", scan.skipped.len())
                    }
                )
            })?
    } else {
        let found = scan
            .incidents
            .iter()
            .find(|incident| incident.name == requested)
            .ok_or_else(|| {
                let skipped = scan
                    .skipped
                    .iter()
                    .find(|skipped| skipped.name == requested)
                    .map(|skipped| format!(" (skipped: {})", skipped.reason))
                    .unwrap_or_default();
                anyhow::anyhow!("no incident named {requested}{skipped}")
            })?;
        if !found.readable() {
            bail!("{} is unreadable: {}", found.name, found.damage.join("; "));
        }
        found
    };
    // Rebuild without the scan so the documents can borrow nothing.
    let incident = Incident {
        name: incident.name.clone(),
        files: incident.files.clone(),
        size_bytes: incident.size_bytes,
        manifest: incident.manifest.clone(),
        diagnosis: incident.diagnosis.clone(),
        complete: incident.complete,
        recorded_at_unix_s: incident.recorded_at_unix_s,
        recording_started_unix_s: incident.recording_started_unix_s,
        recorded_at_s: incident.recorded_at_s,
        triggered_by: incident.triggered_by.clone(),
        thresholds: incident.thresholds.clone(),
        interval: incident.interval.clone(),
        history: incident.history.clone(),
        causes: incident.causes.clone(),
        not_collected: incident.not_collected.clone(),
        semantics: incident.semantics.clone(),
        complete_present: incident.complete_present,
        damage: incident.damage.clone(),
    };
    let documents = Documents::load(dir, &incident.name)?;
    if !documents.damage.is_empty() {
        bail!(
            "{} is damaged: {}",
            incident.name,
            documents.damage.join("; ")
        );
    }
    Ok(Resolved {
        incident,
        documents,
    })
}

fn show(args: IncidentShowArgs) -> Result<()> {
    let resolved = resolve(&args.dir.dir, &args.name)?;
    match args.format.format {
        Format::Text => print!(
            "{}",
            report_text(
                &resolved.incident,
                &resolved.documents,
                &resolved_dir(&args.dir.dir, &resolved.incident.name),
            )
        ),
        Format::Json => {
            let incident = &resolved.incident;
            let documents = &resolved.documents;
            let document = serde_json::json!({
                "schema": SCHEMA,
                "command": "incidents.show",
                "name": incident.name,
                "directory": resolved_dir(&args.dir.dir, &incident.name),
                "complete": incident.complete_marker_present(),
                "files": incident.files.iter().map(|(name, bytes)| serde_json::json!({
                    "name": name,
                    "bytes": bytes,
                })).collect::<Vec<_>>(),
                "missing": documents.missing,
                "manifest": documents.manifest,
                "diagnosis": documents.diagnosis,
                "intervals": documents.intervals,
                "slow_samples": documents.slow_samples,
                "summary_text": documents.summary,
                "complete_marker": documents.complete,
            });
            print_json(&document)?;
        }
    }
    Ok(())
}

fn resolved_dir(dir: &Path, name: &str) -> String {
    dir.join(name).display().to_string()
}

fn print_json(document: &Value) -> Result<()> {
    println!("{}", serde_json::to_string_pretty(document)?);
    Ok(())
}

/// The human-readable incident report.
fn report_text(incident: &Incident, documents: &Documents, directory: &str) -> String {
    let mut text = String::new();
    writeln!(text, "Incident: {}", incident.name).unwrap();
    writeln!(text, "Directory: {directory}").unwrap();
    match incident.recorded_at_unix_s {
        Some(recorded) => {
            let mut line = format!("Recorded: {}", utc::timestamp(recorded));
            if let Some(offset) = incident.recorded_at_s {
                line.push_str(&format!(" ({offset:.3}s into the recording"));
                if let Some(started) = incident.recording_started_unix_s {
                    line.push_str(&format!(", started {}", utc::timestamp(started)));
                }
                line.push(')');
            }
            writeln!(text, "{line}").unwrap();
        }
        None => {
            writeln!(
                text,
                "Recorded: not recorded (this bundle predates wall-clock timestamps)"
            )
            .unwrap();
        }
    }
    if let Some(pid) = incident
        .manifest
        .as_ref()
        .and_then(|manifest| manifest.get("process"))
        .and_then(|process| process.get("pid"))
        .and_then(Value::as_u64)
    {
        writeln!(text, "Process: {pid}").unwrap();
    }
    if incident.complete_marker_present() {
        writeln!(text, "Status: complete").unwrap();
    } else {
        writeln!(text, "Status: incomplete (no completion marker)").unwrap();
    }
    let files: Vec<String> = incident
        .files
        .iter()
        .map(|(name, bytes)| format!("{name} ({})", crate::daemon::human_bytes(*bytes)))
        .collect();
    writeln!(text, "Files: {}", files.join(", ")).unwrap();
    if documents.missing.is_empty() {
        writeln!(text, "Missing: none").unwrap();
    } else {
        writeln!(text, "Missing: {}", documents.missing.join(", ")).unwrap();
    }
    if !documents.damage.is_empty() {
        writeln!(text, "Damage: {}", documents.damage.join("; ")).unwrap();
    }

    text.push('\n');
    writeln!(text, "Triggered by").unwrap();
    if incident.triggered_by.is_empty() {
        writeln!(text, "  no trigger recorded on this interval").unwrap();
    }
    for trigger in &incident.triggered_by {
        let signal = trigger.get("signal").and_then(Value::as_str).unwrap_or("?");
        let unit = trigger.get("unit").and_then(Value::as_str).unwrap_or("");
        let threshold = trigger.get("threshold");
        let measured = trigger.get("measured");
        writeln!(
            text,
            "  {signal:<12} measured {}  at or above {}",
            describe_measurement(measured, unit),
            describe_measurement(threshold, unit),
        )
        .unwrap();
    }

    if !incident.thresholds.is_empty() {
        text.push('\n');
        writeln!(text, "Thresholds in force").unwrap();
        for threshold in &incident.thresholds {
            let signal = threshold
                .get("signal")
                .and_then(Value::as_str)
                .unwrap_or("?");
            let unit = threshold.get("unit").and_then(Value::as_str).unwrap_or("");
            let at = threshold.get("at_or_above");
            let available = threshold.get("available").and_then(Value::as_bool);
            writeln!(
                text,
                "  {signal:<12} at or above {}{}",
                describe_measurement(at, unit),
                match available {
                    Some(false) => "  (unavailable in this interval)",
                    _ => "",
                }
            )
            .unwrap();
        }
    }

    if let Some(interval) = &incident.interval {
        text.push('\n');
        writeln!(text, "Interval").unwrap();
        interval_lines(&mut text, interval);
    }

    text.push('\n');
    text.push_str(
        "Ranked causes (the ranking fast diagnose uses, fed with the recorder's own measurements)\n",
    );
    if incident.causes.is_empty() {
        writeln!(text, "  no cause was ranked").unwrap();
    }
    for (rank, cause) in incident.causes.iter().enumerate() {
        let name = cause.get("cause").and_then(Value::as_str).unwrap_or("?");
        let confidence = cause
            .get("confidence_pct")
            .and_then(Value::as_f64)
            .unwrap_or_default();
        writeln!(text, "  {}. {name:<17}{confidence:>5.1}%", rank + 1).unwrap();
        for evidence in cause
            .get("evidence")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
        {
            writeln!(text, "     {evidence}").unwrap();
        }
    }
    writeln!(
        text,
        "Confidence is each cause's share of the measured slowdown, not a probability."
    )
    .unwrap();

    text.push('\n');
    writeln!(text, "Not collected").unwrap();
    if incident.not_collected.is_empty() {
        writeln!(text, "  none reported").unwrap();
    }
    for reason in &incident.not_collected {
        writeln!(text, "  - {reason}").unwrap();
    }

    if let (Some(carried), Some(limit)) = (
        incident.carried("intervals_carried"),
        incident.carried("interval_limit"),
    ) {
        text.push('\n');
        writeln!(text, "History").unwrap();
        writeln!(
            text,
            "  {carried} of {limit} intervals carried{}",
            incident
                .ring_window_s()
                .map(|window| format!(" (ring window {window:.0}s)"))
                .unwrap_or_default()
        )
        .unwrap();
    }

    if let Some(slow) = documents.value(&documents.slow_samples) {
        let sched: Vec<u64> = slow
            .get("sched_us")
            .and_then(Value::as_array)
            .map(|values| values.iter().filter_map(Value::as_u64).take(5).collect())
            .unwrap_or_default();
        let io: Vec<u64> = slow
            .get("io_us")
            .and_then(Value::as_array)
            .map(|values| values.iter().filter_map(Value::as_u64).take(5).collect())
            .unwrap_or_default();
        if !sched.is_empty() || !io.is_empty() {
            text.push('\n');
            writeln!(text, "Slowest samples in the triggering interval").unwrap();
            if !sched.is_empty() {
                writeln!(text, "  scheduler: {}", join_micros(&sched)).unwrap();
            }
            if !io.is_empty() {
                writeln!(text, "  block I/O: {}", join_micros(&io)).unwrap();
            }
        }
    }

    if let Some(semantics) = &incident.semantics {
        text.push('\n');
        writeln!(text, "Measurement semantics").unwrap();
        writeln!(text, "  {semantics}").unwrap();
    }
    text
}

fn join_micros(values: &[u64]) -> String {
    values
        .iter()
        .map(|value| format!("{value} µs"))
        .collect::<Vec<_>>()
        .join(", ")
}

fn interval_lines(text: &mut String, interval: &Value) {
    let row = |text: &mut String, label: &str, value: String| {
        writeln!(text, "  {label:<20} {value}").unwrap();
    };
    row(
        text,
        "scheduler p95",
        format!("{} µs", number(interval, "sched_p95_us")),
    );
    row(
        text,
        "scheduler samples",
        format!("{}", number(interval, "sched_samples")),
    );
    row(
        text,
        "block I/O p99",
        format!("{} µs", number(interval, "io_p99_us")),
    );
    row(
        text,
        "block I/O samples",
        format!("{}", number(interval, "io_samples")),
    );
    row(
        text,
        "I/O unmatched",
        format!("{}", number(interval, "io_unmatched")),
    );
    let retrans = interval
        .get("retrans")
        .and_then(Value::as_u64)
        .map(|value| value.to_string())
        .unwrap_or_else(|| "not available".to_string());
    row(text, "retransmissions", retrans);
    let tcp = match interval.get("tcp_available").and_then(Value::as_bool) {
        Some(true) => "available".to_string(),
        Some(false) => format!(
            "unavailable ({})",
            interval
                .get("tcp_reason")
                .and_then(Value::as_str)
                .unwrap_or("no reason recorded")
        ),
        None => "not recorded".to_string(),
    };
    row(text, "TCP attribution", tcp);
    row(
        text,
        "network RTT p95",
        optional_micros(interval.get("net_rtt_p95_us")),
    );
    row(
        text,
        "connect p95",
        optional_micros(interval.get("net_connect_p95_us")),
    );
    row(
        text,
        "connects",
        format!(
            "{} ({} failed)",
            number(interval, "net_connects"),
            number(interval, "net_connect_failures")
        ),
    );
    row(
        text,
        "memory PSI some",
        optional_percent(interval.get("psi_some_pct")),
    );
    row(
        text,
        "memory PSI full",
        optional_percent(interval.get("psi_full_pct")),
    );
    row(
        text,
        "CPU usage",
        interval
            .get("cpu_percent")
            .and_then(Value::as_f64)
            .map(|percent| format!("{percent:.1}% of one CPU"))
            .unwrap_or_else(|| "not measured".to_string()),
    );
    row(
        text,
        "lost events",
        format!(
            "{} ({} queued)",
            number(interval, "lost_events"),
            number(interval, "queue_lost_events")
        ),
    );
    row(
        text,
        "recorder cost",
        format!(
            "{:.2}% CPU, {}",
            interval
                .get("recorder_cpu_pct")
                .and_then(Value::as_f64)
                .unwrap_or_default(),
            crate::daemon::human_bytes(number(interval, "recorder_memory_bytes"))
        ),
    );
}

fn number(value: &Value, key: &str) -> u64 {
    value.get(key).and_then(Value::as_u64).unwrap_or_default()
}

fn optional_micros(value: Option<&Value>) -> String {
    value
        .and_then(Value::as_u64)
        .map(|value| format!("{value} µs"))
        .unwrap_or_else(|| "not measured".to_string())
}

fn optional_percent(value: Option<&Value>) -> String {
    value
        .and_then(Value::as_f64)
        .map(|value| format!("{value:.2}%"))
        .unwrap_or_else(|| "not measured".to_string())
}

fn describe_measurement(value: Option<&Value>, unit: &str) -> String {
    let Some(value) = value.and_then(Value::as_f64) else {
        return "not measured".to_string();
    };
    match unit {
        "microseconds" => format!("{value:.0} µs"),
        "percent" => format!("{value:.2}%"),
        _ => format!("{value:.0}"),
    }
}

fn format_cause(cause: &Value) -> String {
    let name = cause.get("cause").and_then(Value::as_str).unwrap_or("?");
    match cause.get("confidence_pct").and_then(Value::as_f64) {
        Some(confidence) => format!("{name} {confidence:.1}%"),
        None => name.to_string(),
    }
}

fn truncate(value: &str, width: usize) -> String {
    if value.chars().count() <= width {
        return value.to_string();
    }
    let mut truncated: String = value.chars().take(width.saturating_sub(1)).collect();
    truncated.push('…');
    truncated
}

fn export(args: IncidentExportArgs) -> Result<()> {
    let resolved = resolve(&args.dir.dir, &args.name)?;
    let incident = &resolved.incident;
    let documents = &resolved.documents;
    let (extension, content) = match args.format {
        ReportFormat::Text => (
            "txt",
            documents
                .summary
                .clone()
                .filter(|summary| !summary.trim().is_empty())
                .unwrap_or_else(|| {
                    report_text(
                        incident,
                        documents,
                        &resolved_dir(&args.dir.dir, &incident.name),
                    )
                }),
        ),
        ReportFormat::Markdown => ("md", markdown(incident, documents)),
        ReportFormat::Json => ("json", export_json(incident, documents)?),
    };
    match args.output.as_deref() {
        Some(path) if path == Path::new("-") => {
            print!("{content}");
            Ok(())
        }
        explicit => {
            let default = PathBuf::from(format!("{}.{extension}", incident.name));
            let path = explicit.unwrap_or(&default);
            write_report(path, &content, args.force)
                .with_context(|| format!("write {}", path.display()))?;
            eprintln!("wrote {}", path.display());
            Ok(())
        }
    }
}

/// Writes a report without following links and without replacing a file the
/// user did not ask to replace.
///
/// With `--force` the replacement is a rename of a freshly written temporary
/// file, so a report is either the old one or the new one and never a
/// half-written mixture.
fn write_report(path: &Path, content: &str, force: bool) -> Result<()> {
    // A report is never written through a link, and never replaces one: the
    // file the operator asked for is the file that changes.
    if std::fs::symlink_metadata(path).is_ok_and(|metadata| metadata.file_type().is_symlink()) {
        bail!(
            "{} is a symlink; refusing to write through it",
            path.display()
        );
    }
    if !force {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .custom_flags(libc::O_NOFOLLOW)
            .mode(0o600)
            .open(path)
            .map_err(|error| match error.kind() {
                std::io::ErrorKind::AlreadyExists => anyhow::anyhow!(
                    "already exists; pass --force to replace it (refusing to overwrite a report)"
                ),
                _ => anyhow::Error::from(error),
            })?;
        file.write_all(content.as_bytes())?;
        file.sync_all()?;
        return Ok(());
    }
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .context("output path has no file name")?;
    let temporary = parent.join(format!(".{file_name}.tmp-{}", std::process::id()));
    let _ = std::fs::remove_file(&temporary);
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .custom_flags(libc::O_NOFOLLOW)
        .mode(0o600)
        .open(&temporary)?;
    file.write_all(content.as_bytes())?;
    file.sync_all()?;
    drop(file);
    std::fs::rename(&temporary, path).inspect_err(|_| {
        let _ = std::fs::remove_file(&temporary);
    })?;
    Ok(())
}

#[derive(Serialize)]
struct ExportDocuments<'a> {
    manifest: Option<&'a RawValue>,
    intervals: Option<&'a RawValue>,
    slow_samples: Option<&'a RawValue>,
    diagnosis: Option<&'a RawValue>,
    complete: Option<&'a RawValue>,
    summary_text: Option<&'a String>,
}

fn export_json(incident: &Incident, documents: &Documents) -> Result<String> {
    let document = serde_json::json!({
        "schema": SCHEMA,
        "command": "incidents.export",
        "name": incident.name,
        "files_missing": documents.missing,
        "bundle": ExportDocuments {
            manifest: documents.manifest.as_deref(),
            intervals: documents.intervals.as_deref(),
            slow_samples: documents.slow_samples.as_deref(),
            diagnosis: documents.diagnosis.as_deref(),
            complete: documents.complete.as_deref(),
            summary_text: documents.summary.as_ref(),
        },
    });
    Ok(format!("{}\n", serde_json::to_string_pretty(&document)?))
}

fn markdown(incident: &Incident, documents: &Documents) -> String {
    let mut text = String::new();
    writeln!(text, "# Incident {}", incident.name).unwrap();
    text.push('\n');
    let recorded = match incident.recorded_at_unix_s {
        Some(recorded) => utc::timestamp(recorded),
        None => "**not recorded** (bundle predates wall-clock timestamps)".to_string(),
    };
    let status = if incident.complete_marker_present() {
        "complete"
    } else {
        "incomplete (no completion marker)"
    };
    writeln!(text, "**Recorded (UTC):** {recorded}  ").unwrap();
    writeln!(text, "**Status:** {status}  ").unwrap();
    if let Some(pid) = incident
        .manifest
        .as_ref()
        .and_then(|manifest| manifest.get("process"))
        .and_then(|process| process.get("pid"))
        .and_then(Value::as_u64)
    {
        writeln!(text, "**Process:** {pid}  ").unwrap();
    }
    writeln!(text).unwrap();

    writeln!(text, "## Triggered by").unwrap();
    writeln!(text).unwrap();
    if incident.triggered_by.is_empty() {
        writeln!(text, "No trigger was recorded on this interval.").unwrap();
    } else {
        writeln!(text, "| Signal | Threshold | Measured |").unwrap();
        writeln!(text, "| --- | --- | --- |").unwrap();
        for trigger in &incident.triggered_by {
            let signal = trigger.get("signal").and_then(Value::as_str).unwrap_or("?");
            let unit = trigger.get("unit").and_then(Value::as_str).unwrap_or("");
            writeln!(
                text,
                "| `{signal}` | {} | {} |",
                describe_measurement(trigger.get("threshold"), unit),
                describe_measurement(trigger.get("measured"), unit)
            )
            .unwrap();
        }
    }
    text.push('\n');

    writeln!(text, "## Diagnosis").unwrap();
    writeln!(text).unwrap();
    if incident.causes.is_empty() {
        writeln!(text, "No cause was ranked.").unwrap();
    } else {
        writeln!(text, "| Rank | Cause | Confidence |").unwrap();
        writeln!(text, "| --- | --- | --- |").unwrap();
        for (rank, cause) in incident.causes.iter().enumerate() {
            let name = cause.get("cause").and_then(Value::as_str).unwrap_or("?");
            let confidence = cause
                .get("confidence_pct")
                .and_then(Value::as_f64)
                .unwrap_or_default();
            writeln!(text, "| {} | {name} | {confidence:.1}% |", rank + 1).unwrap();
        }
    }
    text.push('\n');

    if let Some(interval) = &incident.interval {
        writeln!(text, "## Interval").unwrap();
        writeln!(text).unwrap();
        let mut lines = String::new();
        interval_lines(&mut lines, interval);
        writeln!(text, "```").unwrap();
        text.push_str(&lines);
        writeln!(text, "```").unwrap();
        text.push('\n');
    }

    writeln!(text, "## Not collected").unwrap();
    writeln!(text).unwrap();
    writeln!(
        text,
        "A signal listed here was never measured. It is unavailable, not zero, and the \\
         diagnosis could not have used it."
    )
    .unwrap();
    text.push('\n');
    if incident.not_collected.is_empty() {
        writeln!(text, "- none reported").unwrap();
    }
    for reason in &incident.not_collected {
        writeln!(text, "- {reason}").unwrap();
    }
    text.push('\n');

    writeln!(text, "## Bundle").unwrap();
    writeln!(text).unwrap();
    let files: Vec<String> = incident
        .files
        .iter()
        .map(|(name, bytes)| format!("`{name}` ({})", crate::daemon::human_bytes(*bytes)))
        .collect();
    writeln!(text, "- Files: {}", files.join(", ")).unwrap();
    writeln!(
        text,
        "- Missing: {}",
        if documents.missing.is_empty() {
            "none".to_string()
        } else {
            documents.missing.join(", ")
        }
    )
    .unwrap();
    if let (Some(carried), Some(limit)) = (
        incident.carried("intervals_carried"),
        incident.carried("interval_limit"),
    ) {
        writeln!(text, "- History: {carried} of {limit} intervals carried").unwrap();
    }
    text
}

fn summary(args: IncidentSummaryArgs) -> Result<()> {
    let scan = scan(&args.dir.dir)?;
    let selection = select(&scan.incidents, args.since);
    let readable: Vec<&Incident> = selection
        .shown
        .iter()
        .map(|index| &scan.incidents[*index])
        .filter(|incident| incident.readable())
        .collect();
    let complete = readable
        .iter()
        .filter(|incident| incident.complete_marker_present())
        .count();
    let incomplete = readable
        .iter()
        .filter(|incident| !incident.complete_marker_present())
        .count();
    let without_diagnosis = readable
        .iter()
        .filter(|incident| incident.causes.is_empty())
        .count();

    let mut trigger_counts: Vec<(String, u64)> = Vec::new();
    let mut cause_counts: Vec<(String, u64)> = Vec::new();
    let mut unavailable = 0u64;
    for incident in &readable {
        for trigger in &incident.triggered_by {
            if let Some(signal) = trigger.get("signal").and_then(Value::as_str) {
                count(&mut trigger_counts, signal);
            }
        }
        if let Some(name) = incident
            .causes
            .first()
            .and_then(|cause| cause.get("cause"))
            .and_then(Value::as_str)
        {
            count(&mut cause_counts, name);
        }
        if incident.tcp_available() == Some(false) {
            unavailable += 1;
        }
    }
    trigger_counts.sort_by(|left, right| right.1.cmp(&left.1).then_with(|| left.0.cmp(&right.0)));
    cause_counts.sort_by(|left, right| right.1.cmp(&left.1).then_with(|| left.0.cmp(&right.0)));
    let times: Vec<f64> = readable
        .iter()
        .filter_map(|incident| incident.recorded_at_unix_s)
        .collect();
    let oldest = times.iter().copied().reduce(f64::min);
    let newest = times.iter().copied().reduce(f64::max);

    match args.format.format {
        Format::Text => {
            let mut text = String::new();
            writeln!(text, "Incident summary").unwrap();
            writeln!(text, "Directory: {}", scan.path.display()).unwrap();
            if let Some(since) = args.since {
                writeln!(text, "Window: last {}", humantime::format_duration(since)).unwrap();
            }
            if !scan.present {
                writeln!(
                    text,
                    "No incident directory yet; the daemon has not recorded anything."
                )
                .unwrap();
                print!("{text}");
                return Ok(());
            }
            writeln!(
                text,
                "Bundles: {} ({} readable, {} unreadable), {} complete, {} incomplete, {} skipped",
                scan.incidents.len(),
                readable.len(),
                selection.unreadable,
                complete,
                incomplete,
                scan.skipped.len()
            )
            .unwrap();
            if let (Some(oldest), Some(newest)) = (oldest, newest) {
                writeln!(
                    text,
                    "Observed: {} to {}",
                    utc::timestamp(oldest),
                    utc::timestamp(newest)
                )
                .unwrap();
            }
            if selection.without_timestamp > 0 {
                writeln!(
                    text,
                    "Excluded: {} incident(s) without a recorded time",
                    selection.without_timestamp
                )
                .unwrap();
            }
            if without_diagnosis > 0 {
                writeln!(
                    text,
                    "No diagnosis: {} incident(s) carry no ranked cause",
                    without_diagnosis
                )
                .unwrap();
            }
            text.push('\n');
            if readable.is_empty() {
                writeln!(text, "No readable incidents in the window.").unwrap();
            }
            if !trigger_counts.is_empty() {
                writeln!(text, "Triggered by").unwrap();
                for (signal, count) in &trigger_counts {
                    writeln!(text, "  {signal:<14}{count}").unwrap();
                }
                text.push('\n');
            }
            if !cause_counts.is_empty() {
                writeln!(text, "Top causes (share of the readable bundles)").unwrap();
                for (cause, count) in &cause_counts {
                    let share = *count as f64 * 100.0 / readable.len() as f64;
                    writeln!(text, "  {cause:<20}{count:>3}  {share:>5.1}%").unwrap();
                }
                text.push('\n');
            }
            if unavailable > 0 {
                writeln!(text, "Unavailable signals").unwrap();
                writeln!(
                    text,
                    "  tcp            {unavailable} incident(s) could not attribute TCP ownership"
                )
                .unwrap();
                text.push('\n');
            }
            writeln!(
                text,
                "Note: rotated-away history is not included; a summary covers what the \
                 directory still holds."
            )
            .unwrap();
            print!("{text}");
        }
        Format::Json => {
            let document = serde_json::json!({
                "schema": SCHEMA,
                "command": "incidents.summary",
                "directory": scan.path.display().to_string(),
                "directory_exists": scan.present,
                "since_s": args.since.map(|since| since.as_secs_f64()),
                "counts": {
                    "bundles": scan.incidents.len(),
                    "readable": readable.len(),
                    "unreadable": selection.unreadable,
                    "complete": complete,
                    "incomplete": incomplete,
                    "skipped": scan.skipped.len(),
                    "excluded_without_timestamp": selection.without_timestamp,
                    "without_diagnosis": without_diagnosis,
                },
                "time_range": {
                    "oldest_unix_s": oldest,
                    "newest_unix_s": newest,
                },
                "trigger_counts": trigger_counts.iter().map(|(signal, count)| serde_json::json!({
                    "signal": signal,
                    "incidents": count,
                })).collect::<Vec<_>>(),
                "top_causes": cause_counts.iter().map(|(cause, count)| serde_json::json!({
                    "cause": cause,
                    "incidents": count,
                    "share_pct": *count as f64 * 100.0 / readable.len().max(1) as f64,
                    "share_of": "readable bundles",
                })).collect::<Vec<_>>(),
                "unavailable_counts": if unavailable == 0 { Vec::new() } else {
                    vec![serde_json::json!({"signal": "tcp", "incidents": unavailable})]
                },
                "matched_skipped": scan.skipped.iter().map(|skipped| serde_json::json!({
                    "name": skipped.name,
                    "reason": skipped.reason,
                })).collect::<Vec<_>>(),
            });
            print_json(&document)?;
        }
    }
    Ok(())
}

fn count(counts: &mut Vec<(String, u64)>, key: &str) {
    if let Some(entry) = counts.iter_mut().find(|(name, _)| name == key) {
        entry.1 += 1;
    } else {
        counts.push((key.to_string(), 1));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::incident_store::tests::Temp;
    use std::fs;

    const MARKER: &str = crate::daemon_storage::MARKER;
    const MARKER_CONTENT: &str = crate::daemon_storage::MARKER_CONTENT;

    /// Writes a bundle with the documents a real recorder produces.
    fn write_bundle(
        root: &Path,
        name: &str,
        recorded_at_unix_s: Option<f64>,
        causes: &[(&str, f64)],
        complete: bool,
    ) -> PathBuf {
        let dir = root.join(name);
        fs::create_dir(&dir).unwrap();
        fs::write(dir.join(MARKER), MARKER_CONTENT).unwrap();
        let mut manifest = serde_json::json!({
            "schema": "rand-fast/v2",
            "command": "daemon.incident",
            "recorded_at_s": 123.456,
            "process": { "pid": 4321 },
            "triggered_by": [
                { "signal": "sched_p95", "unit": "microseconds", "threshold": 10000.0, "measured": 18400.0 }
            ],
            "thresholds": [
                { "signal": "sched_p95", "unit": "microseconds", "at_or_above": 10000.0, "available": true },
                { "signal": "retrans", "unit": "count", "at_or_above": 8.0, "available": false }
            ],
            "history": { "intervals_carried": 2, "interval_limit": 60, "ring_window_s": 60.0 },
            "interval": {
                "at_s": 123.456,
                "sched_p95_us": 18400,
                "sched_samples": 500,
                "io_p99_us": 900,
                "io_samples": 20,
                "io_unmatched": 0,
                "retrans": null,
                "tcp_available": false,
                "tcp_reason": "no sockets attributable to the target",
                "net_rtt_p95_us": null,
                "net_connect_p95_us": null,
                "net_connects": 0,
                "net_connect_failures": 0,
                "psi_some_pct": null,
                "psi_full_pct": null,
                "lost_events": 0,
                "queue_lost_events": 0,
                "recorder_cpu_pct": 0.4,
                "recorder_memory_bytes": 3400000,
                "measurement_semantics": "test semantics"
            }
        });
        if let Some(recorded) = recorded_at_unix_s {
            manifest["recorded_at_unix_s"] = serde_json::json!(recorded);
            manifest["recording_started_unix_s"] = serde_json::json!(recorded - 123.456);
        }
        fs::write(
            dir.join(MANIFEST),
            serde_json::to_string_pretty(&manifest).unwrap(),
        )
        .unwrap();
        fs::write(
            dir.join(INTERVALS),
            r#"[{"at_s":122.0,"sched_p95_us":100}]"#,
        )
        .unwrap();
        fs::write(
            dir.join(SLOW_SAMPLES),
            r#"{"sched_us":[18400,15000],"io_us":[]}"#,
        )
        .unwrap();
        let diagnosis = serde_json::json!({
            "schema": "rand-fast/v2",
            "command": "daemon.incident.diagnosis",
            "pid": 4321,
            "causes": causes.iter().map(|(cause, confidence)| serde_json::json!({
                "cause": cause,
                "confidence_pct": confidence,
                "evidence": [format!("row for {cause}")],
            })).collect::<Vec<_>>(),
            "not_collected": ["off-CPU wait reasons and stacks"],
            "slowest_samples": {"sched_us": [18400], "io_us": []},
        });
        fs::write(
            dir.join(DIAGNOSIS),
            serde_json::to_string_pretty(&diagnosis).unwrap(),
        )
        .unwrap();
        fs::write(dir.join(SUMMARY), "Incident at 123s into the recording\n").unwrap();
        if complete {
            fs::write(dir.join(COMPLETE), r#"{"schema":"rand-fast/v2"}"#).unwrap();
        }
        dir
    }

    fn now_minus(seconds: f64) -> f64 {
        utc::now_unix_seconds().unwrap() - seconds
    }

    fn document(scan: &Scan, limit: usize, since: Option<std::time::Duration>) -> Value {
        let selection = select(&scan.incidents, since);
        let shown: Vec<&Incident> = selection
            .shown
            .iter()
            .take(if limit == 0 { usize::MAX } else { limit })
            .map(|index| &scan.incidents[*index])
            .collect();
        serde_json::json!({
            "count": shown.len(),
            "unreadable_count": selection.unreadable,
            "excluded_without_timestamp": selection.without_timestamp,
            "incidents": shown.iter().map(|incident| list_entry(incident)).collect::<Vec<_>>(),
            "skipped": scan.skipped.iter().map(|skipped| serde_json::json!({
                "name": skipped.name, "reason": skipped.reason,
            })).collect::<Vec<_>>(),
        })
    }

    #[test]
    fn a_missing_directory_reads_as_empty_not_as_an_error() {
        let t = Temp::new();
        let scan = scan(&t.0.join("absent")).unwrap();
        assert!(!scan.present);
        assert!(scan.incidents.is_empty());
        let text = list_text(&scan, &select(&[], None), &[], None);
        assert!(text.contains("has not recorded anything"));
    }

    #[test]
    fn listing_orders_by_recorded_time_and_separates_everything_else() {
        let t = Temp::new();
        write_bundle(
            &t.0,
            "incident-000000001000s",
            Some(now_minus(3_600.0)),
            &[("Disk I/O", 60.0)],
            true,
        );
        write_bundle(
            &t.0,
            "incident-000000002000s",
            Some(now_minus(60.0)),
            &[("CPU contention", 72.0)],
            true,
        );
        write_bundle(&t.0, "incident-000000003000s", None, &[], true);
        // Not a bundle, a symlink, and a bundle with an unreadable manifest.
        fs::write(t.0.join("notes"), "user data").unwrap();
        std::os::unix::fs::symlink(t.0.join("notes"), t.0.join("link")).unwrap();
        let damaged = write_bundle(
            &t.0,
            "incident-000000004000s",
            Some(now_minus(10.0)),
            &[],
            false,
        );
        fs::write(damaged.join(MANIFEST), "{ not json").unwrap();

        let scan = scan(&t.0).unwrap();
        let doc = document(&scan, 20, None);
        let names: Vec<&str> = doc["incidents"]
            .as_array()
            .unwrap()
            .iter()
            .map(|incident| incident["name"].as_str().unwrap())
            .collect();
        // The damaged bundle has no readable time, so it sorts with the legacy
        // group at the end instead of being given a guessed position.
        assert_eq!(
            names,
            vec![
                "incident-000000002000s",
                "incident-000000001000s",
                "incident-000000004000s",
                "incident-000000003000s",
            ]
        );
        assert_eq!(doc["incidents"][2]["readable"], false);
        assert!(
            doc["incidents"][2]["reason"]
                .as_str()
                .unwrap()
                .contains("not valid JSON")
        );
        assert_eq!(doc["incidents"][2]["complete"], false);
        assert_eq!(doc["unreadable_count"], 1);
        assert_eq!(doc["incidents"][0]["top_cause"]["cause"], "CPU contention");
        assert_eq!(doc["incidents"][3]["recorded_at_unix_s"], Value::Null);
        assert_eq!(doc["skipped"].as_array().unwrap().len(), 2);
    }

    #[test]
    fn since_excludes_bundles_without_a_timestamp_and_counts_them() {
        let t = Temp::new();
        write_bundle(
            &t.0,
            "incident-000000001000s",
            Some(now_minus(3_600.0)),
            &[],
            true,
        );
        write_bundle(&t.0, "incident-000000002000s", None, &[], true);
        let scan = scan(&t.0).unwrap();
        let doc = document(&scan, 20, Some(std::time::Duration::from_secs(600)));
        assert_eq!(doc["count"], 0);
        assert_eq!(doc["excluded_without_timestamp"], 1);
        let doc = document(&scan, 20, None);
        assert_eq!(doc["count"], 2);
        assert_eq!(doc["excluded_without_timestamp"], 0);
    }

    #[test]
    fn limit_is_applied_after_ordering() {
        let t = Temp::new();
        write_bundle(
            &t.0,
            "incident-000000001000s",
            Some(now_minus(600.0)),
            &[],
            true,
        );
        write_bundle(
            &t.0,
            "incident-000000002000s",
            Some(now_minus(60.0)),
            &[],
            true,
        );
        let scan = scan(&t.0).unwrap();
        let doc = document(&scan, 1, None);
        assert_eq!(doc["count"], 1);
        assert_eq!(doc["incidents"][0]["name"], "incident-000000002000s");
        assert_eq!(doc["incidents"][0]["intervals_carried"], 2);
    }

    #[test]
    fn a_legacy_manifest_still_reads_and_reports_no_time() {
        let t = Temp::new();
        let dir = write_bundle(&t.0, "incident-000000001000s", None, &[], true);
        let mut manifest: Value =
            serde_json::from_str(&fs::read_to_string(dir.join(MANIFEST)).unwrap()).unwrap();
        manifest.as_object_mut().unwrap().remove("recorded_at_s");
        fs::write(
            dir.join(MANIFEST),
            serde_json::to_string(&manifest).unwrap(),
        )
        .unwrap();
        let resolved = resolve(&t.0, "latest").unwrap();
        assert_eq!(resolved.incident.recorded_at_unix_s, None);
        let text = report_text(&resolved.incident, &resolved.documents, "path");
        assert!(text.contains("Recorded: not recorded"));
    }

    #[test]
    fn the_report_prints_recorded_evidence_and_completeness() {
        let t = Temp::new();
        write_bundle(
            &t.0,
            "incident-000000001000s",
            Some(1_762_398_845.0),
            &[("CPU contention", 72.5), ("Scheduler latency", 27.5)],
            true,
        );
        let resolved = resolve(&t.0, "latest").unwrap();
        let text = report_text(&resolved.incident, &resolved.documents, "path");
        assert!(text.contains("Recorded: 2025-11-06T03:14:05Z"));
        assert!(text.contains("sched_p95    measured 18400 µs  at or above 10000 µs"));
        assert!(text.contains("1. CPU contention"));
        assert!(text.contains("72.5%"));
        assert!(text.contains("unavailable (no sockets attributable to the target)"));
        assert!(text.contains("2 of 60 intervals carried (ring window 60s)"));
        assert!(text.contains("Status: complete"));
        assert!(text.contains("Slowest samples"));
    }

    #[test]
    fn an_incomplete_bundle_is_shown_not_refused() {
        let t = Temp::new();
        write_bundle(
            &t.0,
            "incident-000000001000s",
            Some(now_minus(60.0)),
            &[],
            false,
        );
        let resolved = resolve(&t.0, "latest").unwrap();
        assert!(!resolved.incident.complete_marker_present());
        let text = report_text(&resolved.incident, &resolved.documents, "path");
        assert!(text.contains("incomplete (no completion marker)"));
    }

    #[test]
    fn latest_prefers_the_recorded_time_then_the_name() {
        let t = Temp::new();
        write_bundle(
            &t.0,
            "incident-000000009000s",
            Some(now_minus(600.0)),
            &[],
            true,
        );
        write_bundle(
            &t.0,
            "incident-000000001000s",
            Some(now_minus(60.0)),
            &[],
            true,
        );
        assert_eq!(
            resolve(&t.0, "latest").unwrap().incident.name,
            "incident-000000001000s"
        );
        let legacy = Temp::new();
        write_bundle(&legacy.0, "incident-000000001000s", None, &[], true);
        write_bundle(&legacy.0, "incident-000000002000s", None, &[], true);
        assert_eq!(
            resolve(&legacy.0, "latest").unwrap().incident.name,
            "incident-000000002000s"
        );
    }

    #[test]
    fn unknown_and_skipped_names_are_errors_with_the_reason() {
        let t = Temp::new();
        fs::create_dir(t.0.join("notes")).unwrap();
        assert!(
            resolve(&t.0, "incident-000000001000s")
                .unwrap_err()
                .to_string()
                .contains("no incident named")
        );
        assert!(
            resolve(&t.0, "notes")
                .unwrap_err()
                .to_string()
                .contains("skipped: no bundle marker")
        );
    }

    #[test]
    fn damaged_documents_are_named_not_rendered() {
        let t = Temp::new();
        let dir = write_bundle(
            &t.0,
            "incident-000000001000s",
            Some(now_minus(1.0)),
            &[],
            true,
        );
        fs::write(dir.join(DIAGNOSIS), "{}").unwrap();
        fs::write(dir.join(DIAGNOSIS), "[1, 2").unwrap();
        let error = resolve(&t.0, "latest").unwrap_err().to_string();
        assert!(error.contains("diagnosis.json"), "{error}");
    }

    #[test]
    fn exports_never_replace_a_file_without_force_and_never_follow_links() {
        let t = Temp::new();
        let target = t.0.join("report.txt");
        write_report(&target, "first", false).unwrap();
        assert!(write_report(&target, "second", false).is_err());
        assert_eq!(fs::read_to_string(&target).unwrap(), "first");
        write_report(&target, "second", true).unwrap();
        assert_eq!(fs::read_to_string(&target).unwrap(), "second");
        let outside = Temp::new();
        fs::write(outside.0.join("keep"), "keep").unwrap();
        std::os::unix::fs::symlink(outside.0.join("keep"), t.0.join("link.txt")).unwrap();
        assert!(write_report(&t.0.join("link.txt"), "third", true).is_err());
        assert_eq!(fs::read_to_string(outside.0.join("keep")).unwrap(), "keep");
    }

    #[test]
    fn json_export_embeds_the_documents_verbatim() {
        let t = Temp::new();
        write_bundle(
            &t.0,
            "incident-000000001000s",
            Some(now_minus(1.0)),
            &[("Disk I/O", 90.0)],
            true,
        );
        let resolved = resolve(&t.0, "latest").unwrap();
        let text = export_json(&resolved.incident, &resolved.documents).unwrap();
        assert!(text.contains("rand-fast/v2\""));
        assert!(text.contains("row for Disk I/O"));
        // The raw document keeps its own key order and whitespace instead of
        // being re-serialized from a parsed map.
        assert!(text.contains("\"schema\": \"rand-fast/v2\""));
        let document: Value = serde_json::from_str(&text).unwrap();
        assert_eq!(document["command"], "incidents.export");
        assert_eq!(
            document["bundle"]["summary_text"],
            "Incident at 123s into the recording\n"
        );
    }

    #[test]
    fn text_export_prefers_the_recorded_summary() {
        let t = Temp::new();
        write_bundle(
            &t.0,
            "incident-000000001000s",
            Some(now_minus(1.0)),
            &[],
            true,
        );
        let resolved = resolve(&t.0, "latest").unwrap();
        let text = resolved.documents.summary.clone().unwrap();
        assert!(text.contains("Incident at 123s into the recording"));
    }

    #[test]
    fn markdown_is_a_shareable_report_with_the_unavailable_note() {
        let t = Temp::new();
        write_bundle(
            &t.0,
            "incident-000000001000s",
            Some(1_762_398_845.0),
            &[("CPU contention", 72.5)],
            true,
        );
        let resolved = resolve(&t.0, "latest").unwrap();
        let text = markdown(&resolved.incident, &resolved.documents);
        assert!(text.starts_with("# Incident incident-000000001000s"));
        assert!(text.contains("**Recorded (UTC):** 2025-11-06T03:14:05Z"));
        assert!(text.contains("| 1 | CPU contention | 72.5% |"));
        assert!(text.contains("It is unavailable, not zero"));
        assert!(text.contains("off-CPU wait reasons and stacks"));
    }

    #[test]
    fn summary_aggregates_triggers_causes_and_availability() {
        let t = Temp::new();
        write_bundle(
            &t.0,
            "incident-000000001000s",
            Some(now_minus(600.0)),
            &[("CPU contention", 60.0)],
            true,
        );
        write_bundle(
            &t.0,
            "incident-000000002000s",
            Some(now_minus(300.0)),
            &[("CPU contention", 55.0)],
            false,
        );
        write_bundle(
            &t.0,
            "incident-000000003000s",
            None,
            &[("Disk I/O", 90.0)],
            true,
        );
        fs::create_dir(t.0.join("notes")).unwrap();
        let scan = scan(&t.0).unwrap();
        let selection = select(&scan.incidents, Some(std::time::Duration::from_secs(3_600)));
        let readable: Vec<&Incident> = selection
            .shown
            .iter()
            .map(|index| &scan.incidents[*index])
            .filter(|incident| incident.readable())
            .collect();
        assert_eq!(readable.len(), 2);
        assert_eq!(selection.without_timestamp, 1);
        let mut causes = Vec::new();
        for incident in &readable {
            if let Some(name) = incident
                .causes
                .first()
                .and_then(|cause| cause.get("cause"))
                .and_then(Value::as_str)
            {
                count(&mut causes, name);
            }
        }
        assert_eq!(causes, vec![("CPU contention".to_string(), 2)]);
        assert_eq!(
            readable
                .iter()
                .filter(|incident| !incident.complete_marker_present())
                .count(),
            1
        );
    }
}
