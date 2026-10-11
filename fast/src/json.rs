//! Machine-readable output for every subcommand.
//!
//! # The schema
//!
//! Every command emits the same envelope, so a consumer can dispatch on
//! `command` and read `data` without special-casing:
//!
//! ```text
//! {
//!   "schema": "rand-fast/v1",
//!   "command": "sched",
//!   "pid": 1234,
//!   "process": "api-server",
//!   "duration_s": 10.0,
//!   "interrupted": false,
//!   "process_exited": false,
//!   "data": { ...command specific... }
//! }
//! ```
//!
//! Rules that hold for every command, so a consumer can rely on them:
//!
//! - All latencies are **microseconds** and all rates are **per second**,
//!   named with a `_us` or `_per_s` suffix. The human report mixes units for
//!   readability; JSON does not, because a consumer should never have to parse
//!   "1.5 ms".
//! - All byte counts are bytes, named with a `_bytes` suffix.
//! - A field is present whenever it is known, and absent rather than null when
//!   it is not. A consumer can tell "no samples" from "zero samples" by the
//!   absence of the count, which is the distinction the human report makes in
//!   words.
//! - `lost_events` is present on every eBPF-backed command, so a consumer can
//!   decide how far to trust the rest.
//!
//! # Stability
//!
//! The `schema` field is the contract. Within a major version, fields are only
//! added, never removed or retyped; a breaking change bumps the number. A
//! consumer should ignore fields it does not recognise, which is what makes
//! adding one safe.

use std::time::Duration;

use serde::Serialize;

/// The schema identifier every JSON document carries.
pub const SCHEMA: &str = "rand-fast/v1";

/// The output format a command was asked for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, clap::ValueEnum)]
pub enum Format {
    /// The human-readable report.
    #[default]
    Text,
    /// The machine-readable document described in this module.
    Json,
}

/// The fields every command's document carries, whatever it measured.
///
/// Serialized in a fixed order so a document is byte-stable for a given set of
/// measurements, which makes it diffable and cacheable.
#[derive(Debug, Clone, Serialize)]
pub struct Envelope<T: Serialize> {
    /// Always [`SCHEMA`].
    pub schema: &'static str,
    /// The subcommand that produced this document.
    pub command: &'static str,
    /// Process the report is about.
    pub pid: u32,
    /// Process name at the time of the report, when it could be read.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub process: Option<String>,
    /// Wall time actually collected, in seconds.
    pub duration_s: f64,
    /// True when the user pressed Ctrl-C.
    pub interrupted: bool,
    /// True when the observed process exited before the duration elapsed.
    pub process_exited: bool,
    /// The command's own measurements.
    pub data: T,
}

impl<T: Serialize> Envelope<T> {
    /// Builds an envelope for one run.
    pub fn new(
        command: &'static str,
        pid: u32,
        process: Option<String>,
        elapsed: Duration,
        interrupted: bool,
        process_exited: bool,
        data: T,
    ) -> Self {
        Self {
            schema: SCHEMA,
            command,
            pid,
            process,
            // Millisecond resolution is enough for a rate and avoids printing
            // a long float tail that a consumer would have to parse.
            duration_s: (elapsed.as_secs_f64() * 1_000.0).round() / 1_000.0,
            interrupted,
            process_exited,
            data,
        }
    }

    /// Serializes to a single line, which is what a streaming consumer wants
    /// and what makes the output diffable line by line.
    pub fn to_line(&self) -> String {
        // Serializing a struct of plain values cannot fail.
        serde_json::to_string(self).unwrap_or_else(|error| {
            format!("{{\"schema\":\"{SCHEMA}\",\"error\":\"json serialization failed: {error}\"}}")
        })
    }
}

/// Prints a document when the caller asked for JSON, and does nothing
/// otherwise.
///
/// The command-specific printer owns the human output, so this is the only
/// place the format choice is applied.
pub fn emit<T: Serialize>(format: Format, envelope: &Envelope<T>) {
    if format == Format::Json {
        println!("{}", envelope.to_line());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{Value, json};

    /// Renders an envelope to a [`Value`], for asserting on fields.
    fn to_value<T: Serialize>(envelope: &Envelope<T>) -> Value {
        serde_json::to_value(envelope).expect("a plain serializable value")
    }

    #[derive(Serialize)]
    struct Sample {
        count: u64,
        /// Optional fields follow the envelope's rule: omitted, never null.
        #[serde(skip_serializing_if = "Option::is_none")]
        note: Option<String>,
    }

    fn envelope(data: Sample) -> Envelope<Sample> {
        Envelope::new(
            "sched",
            42,
            Some("api-server".to_string()),
            Duration::from_millis(10_500),
            false,
            false,
            data,
        )
    }

    #[test]
    fn carries_the_schema_identifier() {
        let value = to_value(&envelope(Sample {
            count: 7,
            note: None,
        }));
        assert_eq!(value["schema"], json!("rand-fast/v1"));
    }

    #[test]
    fn carries_the_command_and_the_process() {
        let value = to_value(&envelope(Sample {
            count: 7,
            note: None,
        }));
        assert_eq!(value["command"], json!("sched"));
        assert_eq!(value["pid"], json!(42));
        assert_eq!(value["process"], json!("api-server"));
    }

    #[test]
    fn duration_is_seconds_to_millisecond_resolution() {
        let value = to_value(&envelope(Sample {
            count: 7,
            note: None,
        }));
        assert_eq!(value["duration_s"], json!(10.5));
    }

    #[test]
    fn an_absent_field_is_omitted_rather_than_null() {
        // A consumer must be able to tell "not known" from "known to be zero"
        // by the absence of the key, not by a null it has to special-case.
        let line = envelope(Sample {
            count: 7,
            note: None,
        })
        .to_line();
        assert!(!line.contains("note"), "absent field leaked: {line}");
        let parsed: Value = serde_json::from_str(&line).expect("valid JSON");
        assert!(parsed["data"].get("note").is_none());
    }

    #[test]
    fn a_present_field_is_serialized() {
        let parsed: Value = serde_json::from_str(
            &envelope(Sample {
                count: 7,
                note: Some("hello".to_string()),
            })
            .to_line(),
        )
        .expect("valid JSON");
        assert_eq!(parsed["data"]["note"], json!("hello"));
    }

    #[test]
    fn output_is_a_single_line() {
        // A streaming consumer reads one document per line, so a pretty-printed
        // document would break it.
        let line = envelope(Sample {
            count: 7,
            note: None,
        })
        .to_line();
        assert!(!line.contains('\n'), "document spans lines: {line}");
    }

    #[test]
    fn output_is_byte_stable_for_the_same_measurements() {
        let first = envelope(Sample {
            count: 7,
            note: Some("x".to_string()),
        })
        .to_line();
        let second = envelope(Sample {
            count: 7,
            note: Some("x".to_string()),
        })
        .to_line();
        assert_eq!(first, second);
    }

    #[test]
    fn the_document_round_trips_through_a_parser() {
        // The acceptance case for this format: a consumer reads the output
        // without ever looking at how it was written.
        let line = envelope(Sample {
            count: 7,
            note: Some("hello".to_string()),
        })
        .to_line();
        let parsed: Value = serde_json::from_str(&line).expect("the output must be valid JSON");
        assert_eq!(parsed["schema"], json!("rand-fast/v1"));
        assert_eq!(parsed["data"]["count"], json!(7));
    }

    #[test]
    fn text_format_prints_nothing_extra() {
        // The JSON printer is the only thing that reacts to the format, so text
        // output stays exactly as it was.
        let mut printed = Vec::new();
        emit_to(
            Format::Text,
            &envelope(Sample {
                count: 1,
                note: None,
            }),
            &mut printed,
        );
        assert!(printed.is_empty(), "text format emitted {printed:?}");

        let mut printed = Vec::new();
        emit_to(
            Format::Json,
            &envelope(Sample {
                count: 1,
                note: None,
            }),
            &mut printed,
        );
        assert_eq!(printed.len(), 1);
        assert!(printed[0].starts_with('{'));
    }

    /// The testable form of [`emit`], so the choice can be checked without
    /// capturing stdout.
    fn emit_to<T: Serialize>(format: Format, envelope: &Envelope<T>, out: &mut Vec<String>) {
        if format == Format::Json {
            out.push(envelope.to_line());
        }
    }
}

/// The acceptance case for this format, expressed as a consumer would write it:
/// parse the document with a real JSON parser, read the fields by name, and
/// require them to be there. Nothing here knows how the document was written,
/// which is the point.
#[cfg(test)]
mod schema_tests {
    use super::*;
    use crate::stats::Statistics;
    use serde_json::Value;

    /// The `data` object `fast sched --format json` produces, built through the
    /// same path the command uses.
    fn sched_document() -> String {
        let mut stats = Statistics::default();
        for latency_ns in [21_000u64, 840_000, 7_200_000, 84_000_000] {
            stats.record(fast_common::SchedulerLatencyEvent {
                latency_ns,
                wake_ns: 0,
                run_ns: latency_ns,
                tid: 1,
                wake_cpu: 0,
                run_cpu: 3,
                reserved: 0,
            });
        }
        stats.record_lost(1);
        Envelope::new(
            "sched",
            1234,
            Some("api-server".to_string()),
            Duration::from_secs(10),
            false,
            false,
            crate::output::scheduler_json(&stats),
        )
        .to_line()
    }

    /// Reads a field, failing with the field name when it is missing. A consumer
    /// written this way breaks loudly when a field disappears, which is what
    /// makes the schema worth versioning.
    fn field<'a>(document: &'a Value, path: &[&str]) -> &'a Value {
        let mut current = document;
        for name in path {
            current = current
                .get(*name)
                .unwrap_or_else(|| panic!("missing field {name} in {document}"));
        }
        current
    }

    #[test]
    fn a_consumer_can_read_the_sched_report() {
        let line = sched_document();
        // Parsed, never pattern-matched by hand.
        let document: Value = serde_json::from_str(&line)
            .unwrap_or_else(|error| panic!("output is not valid JSON: {error}\n{line}"));

        assert_eq!(field(&document, &["schema"]), "rand-fast/v1");
        assert_eq!(field(&document, &["command"]), "sched");
        assert_eq!(field(&document, &["pid"]), 1234);
        assert_eq!(field(&document, &["process"]), "api-server");
        assert_eq!(field(&document, &["duration_s"]), 10.0);
        assert_eq!(field(&document, &["interrupted"]), false);
        assert_eq!(field(&document, &["data", "samples"]), 4);
        assert_eq!(field(&document, &["data", "lost_events"]), 1);
    }

    #[test]
    fn the_percentiles_a_consumer_reads_match_the_measurement() {
        let line = sched_document();
        let document: Value = serde_json::from_str(&line).expect("valid JSON");
        // Four samples sorted are 21us, 840us, 7.2ms and 84ms. Nearest rank
        // puts p50 on the second and p95 and p99 on the fourth. The values
        // have to survive the trip as microseconds, not as a formatted string
        // a consumer would have to parse.
        assert_eq!(field(&document, &["data", "p50_us"]), 840);
        assert_eq!(field(&document, &["data", "p95_us"]), 84_000);
        assert_eq!(field(&document, &["data", "p99_us"]), 84_000);
        assert_eq!(field(&document, &["data", "max_us"]), 84_000);
    }

    #[test]
    fn the_per_cpu_table_is_machine_readable() {
        let line = sched_document();
        let document: Value = serde_json::from_str(&line).expect("valid JSON");
        let rows = field(&document, &["data", "per_cpu"])
            .as_array()
            .expect("per_cpu must be an array");
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0]["cpu"], 3);
        assert_eq!(rows[0]["samples"], 4);
    }

    #[test]
    fn every_latency_field_is_a_number_not_a_string() {
        // The human report prints "84.1 ms"; a document that did the same would
        // force every consumer to re-parse a formatted duration.
        let line = sched_document();
        let document: Value = serde_json::from_str(&line).expect("valid JSON");
        for name in [
            "p50_us",
            "p95_us",
            "p99_us",
            "max_us",
            "samples",
            "lost_events",
        ] {
            assert!(
                field(&document, &["data", name]).is_number(),
                "{name} must be a number"
            );
        }
    }

    #[test]
    fn the_document_survives_a_round_trip_through_a_file() {
        // The shape a real consumer has: written to a file, read back later.
        let line = sched_document();
        let path = std::env::temp_dir().join(format!("fast-json-{}.json", std::process::id()));
        std::fs::write(&path, &line).expect("write");
        let read_back = std::fs::read_to_string(&path).expect("read");
        std::fs::remove_file(&path).ok();

        let document: Value = serde_json::from_str(&read_back).expect("valid JSON");
        assert_eq!(field(&document, &["schema"]), "rand-fast/v1");
        assert_eq!(field(&document, &["data", "samples"]), 4);
    }
}
