//! Guards the fixed tracepoint payload offsets used by the eBPF programs.
//!
//! These offsets were verified against Linux 6.12.105 and Linux 7.2.0-rc6.
//! Before attaching an offset-reading program, compare the live tracefs format
//! with that known layout. A mismatch must stop collection rather than turn
//! into plausible-looking but corrupt samples.

use std::{collections::HashMap, fs, path::Path};

use anyhow::{Context, Result, bail};

const VERIFIED_KERNELS: &str = "Linux 6.12.105 and Linux 7.2.0-rc6";
const TRACEFS_EVENT_ROOTS: [&str; 2] = [
    "/sys/kernel/tracing/events",
    "/sys/kernel/debug/tracing/events",
];

#[derive(Clone, Copy, Debug)]
struct ExpectedField {
    name: &'static str,
    field_type: &'static str,
    offset: usize,
    size: usize,
}

#[derive(Clone, Copy, Debug)]
struct ExpectedEvent {
    category: &'static str,
    name: &'static str,
    fields: &'static [ExpectedField],
}

const SCHED_WAKEUP_FIELDS: &[ExpectedField] = &[ExpectedField {
    name: "pid",
    field_type: "pid_t",
    offset: 24,
    size: 4,
}];

const SCHED_SWITCH_FIELDS: &[ExpectedField] = &[
    ExpectedField {
        name: "prev_pid",
        field_type: "pid_t",
        offset: 24,
        size: 4,
    },
    ExpectedField {
        name: "prev_state",
        field_type: "long",
        offset: 32,
        size: 8,
    },
    ExpectedField {
        name: "next_pid",
        field_type: "pid_t",
        offset: 56,
        size: 4,
    },
];

const TCP_PROBE_FIELDS: &[ExpectedField] = &[
    ExpectedField {
        name: "saddr",
        field_type: "__u8",
        offset: 8,
        size: 28,
    },
    ExpectedField {
        name: "daddr",
        field_type: "__u8",
        offset: 36,
        size: 28,
    },
    ExpectedField {
        name: "sport",
        field_type: "__u16",
        offset: 64,
        size: 2,
    },
    ExpectedField {
        name: "dport",
        field_type: "__u16",
        offset: 66,
        size: 2,
    },
    ExpectedField {
        name: "family",
        field_type: "__u16",
        offset: 68,
        size: 2,
    },
    ExpectedField {
        name: "snd_cwnd",
        field_type: "__u32",
        offset: 88,
        size: 4,
    },
    ExpectedField {
        name: "srtt",
        field_type: "__u32",
        offset: 100,
        size: 4,
    },
    ExpectedField {
        name: "rcv_wnd",
        field_type: "__u32",
        offset: 104,
        size: 4,
    },
    ExpectedField {
        name: "skaddr",
        field_type: "const void *",
        offset: 128,
        size: 8,
    },
];

const TCP_RETRANSMIT_FIELDS: &[ExpectedField] = &[
    ExpectedField {
        name: "skaddr",
        field_type: "const void *",
        offset: 16,
        size: 8,
    },
    ExpectedField {
        name: "sport",
        field_type: "__u16",
        offset: 28,
        size: 2,
    },
    ExpectedField {
        name: "dport",
        field_type: "__u16",
        offset: 30,
        size: 2,
    },
    ExpectedField {
        name: "family",
        field_type: "__u16",
        offset: 32,
        size: 2,
    },
    ExpectedField {
        name: "saddr",
        field_type: "__u8",
        offset: 34,
        size: 4,
    },
    ExpectedField {
        name: "daddr",
        field_type: "__u8",
        offset: 38,
        size: 4,
    },
    ExpectedField {
        name: "saddr_v6",
        field_type: "__u8",
        offset: 42,
        size: 16,
    },
    ExpectedField {
        name: "daddr_v6",
        field_type: "__u8",
        offset: 58,
        size: 16,
    },
];

// Memory programs count event occurrences and do not read any payload fields.
// Their tracepoint existence is still checked before attachment.
const NO_PAYLOAD_FIELDS: &[ExpectedField] = &[];

const EVENTS: &[ExpectedEvent] = &[
    ExpectedEvent {
        category: "sched",
        name: "sched_wakeup",
        fields: SCHED_WAKEUP_FIELDS,
    },
    ExpectedEvent {
        category: "sched",
        name: "sched_switch",
        fields: SCHED_SWITCH_FIELDS,
    },
    ExpectedEvent {
        category: "tcp",
        name: "tcp_probe",
        fields: TCP_PROBE_FIELDS,
    },
    ExpectedEvent {
        category: "tcp",
        name: "tcp_retransmit_skb",
        fields: TCP_RETRANSMIT_FIELDS,
    },
    ExpectedEvent {
        category: "exceptions",
        name: "page_fault_user",
        fields: NO_PAYLOAD_FIELDS,
    },
    ExpectedEvent {
        category: "vmscan",
        name: "mm_vmscan_direct_reclaim_begin",
        fields: NO_PAYLOAD_FIELDS,
    },
];

#[derive(Debug, PartialEq, Eq)]
struct ActualField {
    field_type: String,
    offset: usize,
    size: usize,
}

/// Validates one tracepoint format before its eBPF program is loaded/attached.
pub fn validate(category: &str, event: &str) -> Result<()> {
    let spec = EVENTS
        .iter()
        .find(|spec| spec.category == category && spec.name == event)
        .with_context(|| format!("no verified layout policy for tracepoint {category}/{event}"))?;

    let relative_path = Path::new(category).join(event).join("format");
    let mut read_errors = Vec::new();
    for root in TRACEFS_EVENT_ROOTS {
        let path = Path::new(root).join(&relative_path);
        match fs::read_to_string(&path) {
            Ok(format) => return validate_format(spec, &format),
            Err(error) => read_errors.push(format!("{}: {error}", path.display())),
        }
    }

    bail!(
        "cannot validate tracepoint layout for {category}/{event}: unable to read its tracefs format ({}); mount tracefs and retry",
        read_errors.join("; ")
    )
}

fn validate_format(spec: &ExpectedEvent, format: &str) -> Result<()> {
    let actual_name = format
        .lines()
        .find_map(|line| line.trim().strip_prefix("name:"))
        .map(str::trim);
    if actual_name != Some(spec.name) {
        bail!(
            "unsupported tracepoint layout for {}/{}: format declares event {:?}; layouts verified on {VERIFIED_KERNELS}",
            spec.category,
            spec.name,
            actual_name
        );
    }

    let actual_fields = parse_fields(format).with_context(|| {
        format!(
            "invalid tracepoint format for {}/{}",
            spec.category, spec.name
        )
    })?;
    for expected in spec.fields {
        let Some(actual) = actual_fields.get(expected.name) else {
            bail!(
                "unsupported tracepoint layout for {}/{}: required field {} is missing; layouts verified on {VERIFIED_KERNELS}",
                spec.category,
                spec.name,
                expected.name
            );
        };
        if actual.field_type != expected.field_type
            || actual.offset != expected.offset
            || actual.size != expected.size
        {
            bail!(
                "unsupported tracepoint layout for {}/{}: field {} expected type {} at offset {} with size {}, found type {} at offset {} with size {}; layouts verified on {VERIFIED_KERNELS}",
                spec.category,
                spec.name,
                expected.name,
                expected.field_type,
                expected.offset,
                expected.size,
                actual.field_type,
                actual.offset,
                actual.size
            );
        }
    }
    Ok(())
}

fn parse_fields(format: &str) -> Result<HashMap<String, ActualField>> {
    let mut fields = HashMap::new();
    for (line_number, line) in format.lines().enumerate() {
        let Some(field) = line.trim().strip_prefix("field:") else {
            continue;
        };
        let (declaration, attributes) = field.split_once(';').with_context(|| {
            format!(
                "field declaration at line {} has no attributes",
                line_number + 1
            )
        })?;
        let mut declaration_parts = declaration.split_whitespace().collect::<Vec<_>>();
        let declarator = declaration_parts.pop().with_context(|| {
            format!("field declaration at line {} has no name", line_number + 1)
        })?;
        let name = declarator.split('[').next().unwrap_or(declarator);
        if name.is_empty() || declaration_parts.is_empty() {
            bail!("invalid field declaration at line {}", line_number + 1);
        }
        let field_type = declaration_parts.join(" ");
        let offset = parse_attribute(attributes, "offset")
            .with_context(|| format!("field {name} at line {} has no offset", line_number + 1))?;
        let size = parse_attribute(attributes, "size")
            .with_context(|| format!("field {name} at line {} has no size", line_number + 1))?;
        let actual = ActualField {
            field_type,
            offset,
            size,
        };
        if fields.insert(name.to_owned(), actual).is_some() {
            bail!(
                "duplicate tracepoint field {name} at line {}",
                line_number + 1
            );
        }
    }
    Ok(fields)
}

fn parse_attribute(attributes: &str, name: &str) -> Option<usize> {
    attributes.split(';').find_map(|attribute| {
        let (key, value) = attribute.trim().split_once(':')?;
        (key.trim() == name)
            .then(|| value.trim().parse().ok())
            .flatten()
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const LINUX_6_12_105: &str = include_str!("../tests/fixtures/tracepoints/linux-6.12.105.txt");
    const LINUX_7_2_RC6: &str = include_str!("../tests/fixtures/tracepoints/linux-7.2.0-rc6.txt");

    fn section<'a>(fixture: &'a str, event: &str) -> &'a str {
        let marker = format!("name: {event}");
        let start = fixture
            .lines()
            .scan(0, |offset, line| {
                let current = *offset;
                *offset += line.len() + 1;
                Some((current, line))
            })
            .find_map(|(offset, line)| (line.trim() == marker).then_some(offset))
            .unwrap_or_else(|| panic!("fixture is missing {event}"));
        let rest = &fixture[start..];
        let end = rest
            .match_indices("\nname: ")
            .next()
            .map_or(rest.len(), |(offset, _)| offset);
        &rest[..end]
    }

    fn assert_fixture_matches(fixture: &str) {
        for spec in EVENTS {
            validate_format(spec, section(fixture, spec.name))
                .unwrap_or_else(|error| panic!("{} / {}: {error:#}", spec.category, spec.name));
        }
    }

    #[test]
    fn verified_kernel_layout_fixtures_match_all_consumed_fields() {
        assert_fixture_matches(LINUX_6_12_105);
        assert_fixture_matches(LINUX_7_2_RC6);
    }

    #[test]
    fn rejects_missing_fields_and_wrong_types_or_sizes() {
        let spec = EVENTS
            .iter()
            .find(|spec| spec.category == "tcp" && spec.name == "tcp_probe")
            .unwrap();
        let original = section(LINUX_7_2_RC6, "tcp_probe");
        let missing = original.replace("field:__u16 family; offset:68; size:2; signed:0;\n", "");
        assert!(
            validate_format(spec, &missing)
                .unwrap_err()
                .to_string()
                .contains("family")
        );

        let wrong_type = original.replace("field:__u16 family;", "field:__u32 family;");
        assert!(validate_format(spec, &wrong_type).is_err());

        let wrong_size = original.replace(
            "field:__u16 family; offset:68; size:2;",
            "field:__u16 family; offset:68; size:4;",
        );
        assert!(validate_format(spec, &wrong_size).is_err());
    }
}
