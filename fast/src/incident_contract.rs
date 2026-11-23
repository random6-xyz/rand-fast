//! Shared names and the current writer's wire types for incident bundles.

use std::time::Duration;

use serde::Serialize;
use serde_json::Value;

use crate::{daemon::LostByStream, json::SCHEMA_V2};

const PREFIX: &str = "incident-";
const STAMP_SEPARATOR: char = 's';
const STAMP_WIDTH: usize = 12;
const SUFFIX_SEPARATOR: char = '-';

pub(crate) const MARKER: &str = ".rand-fast-incident";
pub(crate) const MARKER_CONTENT: &str = "rand-fast incident bundle v1\n";
pub(crate) const MANIFEST: &str = "manifest.json";
pub(crate) const INTERVALS: &str = "intervals.json";
pub(crate) const SLOW_SAMPLES: &str = "slow-samples.json";
pub(crate) const DIAGNOSIS: &str = "diagnosis.json";
pub(crate) const SUMMARY: &str = "summary.txt";
pub(crate) const COMPLETE: &str = "complete.json";

const PAYLOAD_FILES: &[&str] = &[MANIFEST, INTERVALS, SLOW_SAMPLES, DIAGNOSIS, SUMMARY];

pub(crate) fn is_bundle_file(name: &str) -> bool {
    matches!(name, MARKER | COMPLETE) || PAYLOAD_FILES.contains(&name)
}

// Zero-pad milliseconds so rotation and history restoration can sort names.
pub(crate) fn stamp(at: Duration) -> String {
    format!("{:0STAMP_WIDTH$}{STAMP_SEPARATOR}", at.as_millis())
}

pub(crate) fn bundle_name(stamp: &str, suffix: usize) -> String {
    if suffix == 1 {
        format!("{PREFIX}{stamp}")
    } else {
        format!("{PREFIX}{stamp}{SUFFIX_SEPARATOR}{suffix}")
    }
}

/// Name restriction for rotation, not for the marker-based reader.
pub(crate) fn valid_bundle_name(name: &str) -> bool {
    let Some((digits, suffix)) = name
        .strip_prefix(PREFIX)
        .and_then(|s| s.split_once(STAMP_SEPARATOR))
    else {
        return false;
    };
    digits.len() >= STAMP_WIDTH
        && digits.bytes().all(|b| b.is_ascii_digit())
        && (suffix.is_empty()
            || suffix
                .strip_prefix(SUFFIX_SEPARATOR)
                .is_some_and(|s| !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit())))
}

#[derive(Serialize)]
pub(crate) struct ManifestV2<'a> {
    pub recorded_at_s: f64,
    pub recorded_at_unix_s: Option<f64>,
    pub recording_started_unix_s: Option<f64>,
    pub process: Process,
    pub triggered_by: Vec<FiredTrigger>,
    pub thresholds: Vec<Threshold>,
    pub history: History,
    pub interval: Interval<'a>,
}

impl ManifestV2<'_> {
    pub(crate) fn to_value(&self) -> serde_json::Result<Value> {
        #[derive(Serialize)]
        struct Document<'a, 'b> {
            schema: &'static str,
            command: &'static str,
            #[serde(flatten)]
            manifest: &'a ManifestV2<'b>,
        }
        serde_json::to_value(Document {
            schema: SCHEMA_V2,
            command: "daemon.incident",
            manifest: self,
        })
    }
}

#[derive(Serialize)]
pub(crate) struct Process {
    pub pid: u32,
}

#[derive(Serialize)]
pub(crate) struct FiredTrigger {
    pub signal: &'static str,
    pub unit: &'static str,
    pub threshold: Option<f64>,
    pub measured: Option<f64>,
}

#[derive(Serialize)]
pub(crate) struct Threshold {
    pub signal: &'static str,
    pub unit: &'static str,
    pub at_or_above: Option<f64>,
    pub available: bool,
}

#[derive(Serialize)]
pub(crate) struct History {
    pub intervals_carried: usize,
    pub interval_limit: usize,
    pub ring_window_s: f64,
}

#[derive(Serialize)]
pub(crate) struct Interval<'a> {
    pub at_s: f64,
    pub sched_p95_us: u64,
    pub sched_samples: u64,
    pub io_p99_us: u64,
    pub io_samples: u64,
    pub io_unmatched: u64,
    pub retrans: Option<u64>,
    pub tcp_available: bool,
    pub tcp_reason: Option<&'a str>,
    pub net_rtt_p95_us: Option<u64>,
    pub net_connect_p95_us: Option<u64>,
    pub net_connects: u64,
    pub net_connect_failures: u64,
    pub psi_some_pct: Option<f32>,
    pub psi_full_pct: Option<f32>,
    pub lost_events: u64,
    pub queue_lost_events: u64,
    pub lost_events_by_stream: Option<LostByStream>,
    pub measurement_semantics: &'static str,
    pub recorder_cpu_pct: f64,
    pub recorder_memory_bytes: u64,
}

#[derive(Serialize)]
pub(crate) struct CompleteV2 {
    schema: &'static str,
    files: &'static [&'static str],
}

impl CompleteV2 {
    pub(crate) const DOCUMENT: Self = Self {
        schema: SCHEMA_V2,
        files: PAYLOAD_FILES,
    };
}
