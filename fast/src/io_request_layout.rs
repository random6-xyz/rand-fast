//! Reads the running kernel's BTF to locate fields needed to correlate block
//! raw tracepoint arguments by their `struct request *` identity.

use std::{fs, mem::size_of};

use anyhow::{Context, Result, bail};
use aya::{Ebpf, maps::HashMap as AyaHashMap, maps::MapData};
use fast_common::IoRequestLayout;

const BTF_MAGIC: u16 = 0xeb9f;
const BTF_HEADER_SIZE: usize = 24;
const KIND_INT: u8 = 1;
const KIND_PTR: u8 = 2;
const KIND_ARRAY: u8 = 3;
const KIND_STRUCT: u8 = 4;
const KIND_UNION: u8 = 5;
const KIND_ENUM: u8 = 6;
const KIND_FWD: u8 = 7;
const KIND_TYPEDEF: u8 = 8;
const KIND_VOLATILE: u8 = 9;
const KIND_CONST: u8 = 10;
const KIND_RESTRICT: u8 = 11;
const KIND_FUNC: u8 = 12;
const KIND_FUNC_PROTO: u8 = 13;
const KIND_VAR: u8 = 14;
const KIND_DATASEC: u8 = 15;
const KIND_FLOAT: u8 = 16;
const KIND_DECL_TAG: u8 = 17;
const KIND_TYPE_TAG: u8 = 18;
const KIND_ENUM64: u8 = 19;
const MAX_TYPE_RESOLVE_DEPTH: usize = 32;

#[derive(Clone, Copy, Debug)]
struct TypeRecord {
    name_offset: u32,
    kind: u8,
    vlen: usize,
    kind_flag: bool,
    size_or_type: u32,
    payload_offset: usize,
}

struct ParsedBtf<'a> {
    data: &'a [u8],
    types: Vec<TypeRecord>,
    strings_start: usize,
    strings_end: usize,
}

#[derive(Clone, Copy, Debug)]
struct Member {
    type_id: u32,
    offset: u32,
    bitfield_size: u8,
}

impl<'a> ParsedBtf<'a> {
    fn parse(data: &'a [u8]) -> Result<Self> {
        if data.len() < BTF_HEADER_SIZE {
            bail!("kernel BTF is shorter than its header");
        }
        if read_u16(data, 0)? != BTF_MAGIC {
            bail!("kernel BTF has an unsupported byte order or magic value");
        }
        if data[2] != 1 {
            bail!("kernel BTF version {} is unsupported", data[2]);
        }

        let header_len = read_u32(data, 4)? as usize;
        if header_len < BTF_HEADER_SIZE || header_len > data.len() {
            bail!("kernel BTF has an invalid header length {header_len}");
        }
        let type_start = header_len
            .checked_add(read_u32(data, 8)? as usize)
            .context("kernel BTF type offset overflow")?;
        let type_end = type_start
            .checked_add(read_u32(data, 12)? as usize)
            .context("kernel BTF type section overflow")?;
        let strings_start = header_len
            .checked_add(read_u32(data, 16)? as usize)
            .context("kernel BTF string offset overflow")?;
        let strings_end = strings_start
            .checked_add(read_u32(data, 20)? as usize)
            .context("kernel BTF string section overflow")?;
        if type_start > type_end
            || type_end > data.len()
            || strings_start > strings_end
            || strings_end > data.len()
        {
            bail!("kernel BTF sections extend beyond the file");
        }

        let mut cursor = type_start;
        let mut types = Vec::new();
        while cursor < type_end {
            let header_end = cursor
                .checked_add(12)
                .context("kernel BTF type header overflow")?;
            if header_end > type_end {
                bail!("kernel BTF ends in a partial type record");
            }
            let name_offset = read_u32(data, cursor)?;
            let info = read_u32(data, cursor + 4)?;
            let kind = ((info >> 24) & 0x1f) as u8;
            let vlen = (info & 0xffff) as usize;
            let kind_flag = info & 0x8000_0000 != 0;
            let size_or_type = read_u32(data, cursor + 8)?;
            let payload_offset = header_end;
            let payload_len = type_payload_len(kind, vlen)?;
            let next = payload_offset
                .checked_add(payload_len)
                .context("kernel BTF type payload overflow")?;
            if next > type_end {
                bail!("kernel BTF type {kind} has a truncated payload");
            }
            types.push(TypeRecord {
                name_offset,
                kind,
                vlen,
                kind_flag,
                size_or_type,
                payload_offset,
            });
            cursor = next;
        }
        if cursor != type_end {
            bail!("kernel BTF type section has trailing bytes");
        }

        Ok(Self {
            data,
            types,
            strings_start,
            strings_end,
        })
    }

    fn type_by_id(&self, type_id: u32) -> Result<&TypeRecord> {
        type_id
            .checked_sub(1)
            .and_then(|id| self.types.get(id as usize))
            .with_context(|| format!("kernel BTF refers to missing type id {type_id}"))
    }

    fn string_at(&self, offset: u32) -> Result<&'a str> {
        let start = self
            .strings_start
            .checked_add(offset as usize)
            .context("kernel BTF string offset overflow")?;
        if start >= self.strings_end {
            bail!("kernel BTF string offset {offset} is out of range");
        }
        let tail = &self.data[start..self.strings_end];
        let end = tail
            .iter()
            .position(|byte| *byte == 0)
            .context("kernel BTF string is not NUL-terminated")?;
        std::str::from_utf8(&tail[..end]).context("kernel BTF contains a non-UTF-8 name")
    }

    fn find_type(&self, name: &str, kind: u8) -> Result<(u32, &TypeRecord)> {
        self.types
            .iter()
            .enumerate()
            .find_map(|(index, record)| {
                (record.kind == kind && self.string_at(record.name_offset).ok() == Some(name))
                    .then_some((index as u32 + 1, record))
            })
            .with_context(|| format!("kernel BTF is missing {name} (kind {kind})"))
    }

    fn resolve_type(&self, mut type_id: u32) -> Result<(u32, &TypeRecord)> {
        for _ in 0..MAX_TYPE_RESOLVE_DEPTH {
            let record = self.type_by_id(type_id)?;
            if matches!(
                record.kind,
                KIND_TYPEDEF | KIND_VOLATILE | KIND_CONST | KIND_RESTRICT | KIND_TYPE_TAG
            ) {
                type_id = record.size_or_type;
                continue;
            }
            return Ok((type_id, record));
        }
        bail!("kernel BTF contains an excessively deep type chain")
    }

    fn type_size(&self, type_id: u32) -> Result<usize> {
        let (_, record) = self.resolve_type(type_id)?;
        match record.kind {
            KIND_INT | KIND_STRUCT | KIND_UNION | KIND_ENUM | KIND_FLOAT | KIND_ENUM64 => {
                Ok(record.size_or_type as usize)
            }
            KIND_PTR => Ok(size_of::<usize>()),
            KIND_ARRAY => {
                let element_type = read_u32(self.data, record.payload_offset)?;
                let count = read_u32(self.data, record.payload_offset + 8)? as usize;
                self.type_size(element_type)?
                    .checked_mul(count)
                    .context("kernel BTF array size overflow")
            }
            _ => bail!("kernel BTF type kind {} has no fixed size", record.kind),
        }
    }

    fn find_struct(&self, name: &str) -> Result<(u32, &TypeRecord)> {
        self.find_type(name, KIND_STRUCT)
    }

    fn member(&self, record: &TypeRecord, wanted: &str) -> Result<Member> {
        if record.kind != KIND_STRUCT && record.kind != KIND_UNION {
            bail!("kernel BTF type is not a struct or union");
        }
        for index in 0..record.vlen {
            let base = record
                .payload_offset
                .checked_add(index.checked_mul(12).context("BTF member index overflow")?)
                .context("BTF member offset overflow")?;
            let name_offset = read_u32(self.data, base)?;
            if self.string_at(name_offset)? != wanted {
                continue;
            }
            let type_id = read_u32(self.data, base + 4)?;
            let raw_offset = read_u32(self.data, base + 8)?;
            let (bit_offset, bitfield_size) = if record.kind_flag {
                (raw_offset & 0x00ff_ffff, (raw_offset >> 24) as u8)
            } else {
                (raw_offset, 0)
            };
            if bit_offset % 8 != 0 {
                bail!("kernel BTF member {wanted} is not byte-aligned");
            }
            return Ok(Member {
                type_id,
                offset: bit_offset / 8,
                bitfield_size,
            });
        }
        bail!("kernel BTF struct is missing field {wanted}")
    }

    fn require_pointer_to(&self, member: Member, pointee_name: &str) -> Result<u32> {
        if member.bitfield_size != 0 {
            bail!("kernel BTF pointer field is unexpectedly a bitfield");
        }
        let (pointer_id, pointer) = self.resolve_type(member.type_id)?;
        if pointer.kind != KIND_PTR || self.type_size(pointer_id)? != size_of::<usize>() {
            bail!("kernel BTF field is not a native pointer");
        }
        let (_, pointee) = self.resolve_type(pointer.size_or_type)?;
        let actual_name = self.string_at(pointee.name_offset)?;
        if !matches!(pointee.kind, KIND_STRUCT | KIND_FWD) || actual_name != pointee_name {
            bail!("kernel BTF pointer targets {actual_name}, expected {pointee_name}");
        }
        Ok(member.offset)
    }

    fn require_field_size(&self, member: Member, name: &str, expected_size: usize) -> Result<u32> {
        if member.bitfield_size != 0 {
            bail!("kernel BTF field {name} is unexpectedly a bitfield");
        }
        let actual_size = self.type_size(member.type_id)?;
        if actual_size != expected_size {
            bail!("kernel BTF field {name} has size {actual_size}, expected {expected_size}");
        }
        Ok(member.offset)
    }

    fn validate_raw_tracepoint_argument(&self, event: &str, expected_struct: &str) -> Result<()> {
        let typedef_name = format!("btf_trace_{event}");
        let (_, alias) = self.find_type(&typedef_name, KIND_TYPEDEF)?;
        let (_, mut prototype) = self
            .resolve_type(alias.size_or_type)
            .with_context(|| format!("resolving {typedef_name} type id {}", alias.size_or_type))?;
        if prototype.kind == KIND_FUNC || prototype.kind == KIND_PTR {
            let (_, resolved) = self.resolve_type(prototype.size_or_type).with_context(|| {
                format!(
                    "resolving raw tracepoint {event} function type id {}",
                    prototype.size_or_type
                )
            })?;
            prototype = resolved;
        }
        if prototype.kind != KIND_FUNC_PROTO || prototype.vlen < 2 {
            bail!(
                "kernel BTF tracepoint {event} has type kind {} with {} arguments, expected trace data plus the request pointer",
                prototype.kind,
                prototype.vlen
            );
        }
        // btf_trace_* prototypes prepend the trace data pointer before the
        // original TP_PROTO arguments; raw_tp programs receive only TP_PROTO.
        let request_arg_type = read_u32(self.data, prototype.payload_offset + 12)
            .with_context(|| format!("reading raw tracepoint {event} request argument type"))?;
        let (_, pointer) = self.resolve_type(request_arg_type).with_context(|| {
            format!("resolving raw tracepoint {event} request argument type {request_arg_type}")
        })?;
        if pointer.kind != KIND_PTR {
            bail!("raw tracepoint {event} does not take a request pointer as argument 0");
        }
        let (_, pointee) = self.resolve_type(pointer.size_or_type).with_context(|| {
            format!(
                "resolving raw tracepoint {event} pointee type {}",
                pointer.size_or_type
            )
        })?;
        let actual_name = self.string_at(pointee.name_offset)?;
        if pointee.kind != KIND_STRUCT || actual_name != expected_struct {
            bail!(
                "raw tracepoint {event} argument 0 points to {actual_name}, expected struct {expected_struct}"
            );
        }
        Ok(())
    }
}

/// Extracts and validates the BTF layout used by the block request programs.
fn request_layout_from_btf(data: &[u8]) -> Result<IoRequestLayout> {
    let btf = ParsedBtf::parse(data)?;
    btf.validate_raw_tracepoint_argument("block_rq_issue", "request")
        .context("validating the block_rq_issue BTF argument")?;
    btf.validate_raw_tracepoint_argument("block_rq_complete", "request")
        .context("validating the block_rq_complete BTF argument")?;

    let (_, request) = btf
        .find_struct("request")
        .context("finding struct request in kernel BTF")?;
    let (_, queue) = btf
        .find_struct("request_queue")
        .context("finding struct request_queue in kernel BTF")?;
    let (_, disk) = btf
        .find_struct("gendisk")
        .context("finding struct gendisk in kernel BTF")?;

    let request_q = btf
        .require_pointer_to(btf.member(request, "q")?, "request_queue")
        .context("validating request.q")?;
    let request_sector = btf
        .require_field_size(btf.member(request, "__sector")?, "request.__sector", 8)
        .context("validating request.__sector")?;
    let request_data_len = btf
        .require_field_size(btf.member(request, "__data_len")?, "request.__data_len", 4)
        .context("validating request.__data_len")?;
    let request_cmd_flags = btf
        .require_field_size(btf.member(request, "cmd_flags")?, "request.cmd_flags", 4)
        .context("validating request.cmd_flags")?;
    let queue_disk = btf
        .require_pointer_to(btf.member(queue, "disk")?, "gendisk")
        .context("validating request_queue.disk")?;
    let gendisk_major = btf
        .require_field_size(btf.member(disk, "major")?, "gendisk.major", 4)
        .context("validating gendisk.major")?;
    let gendisk_first_minor = btf
        .require_field_size(btf.member(disk, "first_minor")?, "gendisk.first_minor", 4)
        .context("validating gendisk.first_minor")?;

    Ok(IoRequestLayout {
        request_q,
        request_sector,
        request_data_len,
        request_cmd_flags,
        queue_disk,
        gendisk_major,
        gendisk_first_minor,
    })
}

/// Reads BTF from the running kernel and initializes the eBPF layout map.
pub fn configure(bpf: &mut Ebpf) -> Result<()> {
    let btf = fs::read("/sys/kernel/btf/vmlinux")
        .context("failed to read /sys/kernel/btf/vmlinux for block request correlation")?;
    let layout = request_layout_from_btf(&btf)
        .context("running kernel BTF does not expose a supported block request layout")?;

    let map = bpf
        .map_mut("IO_REQUEST_LAYOUT")
        .context("eBPF map IO_REQUEST_LAYOUT is missing")?;
    let mut map: AyaHashMap<&mut MapData, u32, IoRequestLayout> = map
        .try_into()
        .context("IO_REQUEST_LAYOUT has an unexpected map type or layout")?;
    map.insert(0, layout, 0)
        .context("failed to install the running kernel's block request BTF layout")?;
    Ok(())
}

fn type_payload_len(kind: u8, vlen: usize) -> Result<usize> {
    let repeated = |width: usize| {
        vlen.checked_mul(width)
            .context("kernel BTF type count overflow")
    };
    match kind {
        KIND_INT | KIND_VAR | KIND_DECL_TAG => Ok(4),
        KIND_ARRAY => Ok(12),
        KIND_STRUCT | KIND_UNION | KIND_DATASEC | KIND_ENUM64 => repeated(12),
        KIND_ENUM | KIND_FUNC_PROTO => repeated(8),
        KIND_PTR | KIND_FWD | KIND_TYPEDEF | KIND_VOLATILE | KIND_CONST | KIND_RESTRICT
        | KIND_FUNC | KIND_FLOAT | KIND_TYPE_TAG => Ok(0),
        _ => bail!("kernel BTF contains unsupported type kind {kind}"),
    }
}

fn read_u16(data: &[u8], offset: usize) -> Result<u16> {
    let bytes = data
        .get(offset..offset + 2)
        .with_context(|| format!("truncated BTF u16 at offset {offset}"))?;
    Ok(u16::from_le_bytes([bytes[0], bytes[1]]))
}

fn read_u32(data: &[u8], offset: usize) -> Result<u32> {
    let bytes = data
        .get(offset..offset + 4)
        .with_context(|| format!("truncated BTF u32 at offset {offset}"))?;
    Ok(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Default)]
    struct FixtureBuilder {
        strings: Vec<u8>,
        types: Vec<u8>,
        type_count: u32,
    }

    impl FixtureBuilder {
        fn new() -> Self {
            Self {
                strings: vec![0],
                ..Self::default()
            }
        }

        fn string(&mut self, value: &str) -> u32 {
            let offset = self.strings.len() as u32;
            self.strings.extend_from_slice(value.as_bytes());
            self.strings.push(0);
            offset
        }

        fn add_type(
            &mut self,
            name: &str,
            kind: u8,
            vlen: u16,
            size_or_type: u32,
            payload: &[u8],
        ) -> u32 {
            let name_offset = self.string(name);
            let info = (u32::from(kind) << 24) | u32::from(vlen);
            self.types.extend_from_slice(&name_offset.to_le_bytes());
            self.types.extend_from_slice(&info.to_le_bytes());
            self.types.extend_from_slice(&size_or_type.to_le_bytes());
            self.types.extend_from_slice(payload);
            self.type_count += 1;
            self.type_count
        }

        fn member(&mut self, name: &str, type_id: u32, bit_offset: u32) {
            let name_offset = self.string(name);
            self.types.extend_from_slice(&name_offset.to_le_bytes());
            self.types.extend_from_slice(&type_id.to_le_bytes());
            self.types.extend_from_slice(&bit_offset.to_le_bytes());
        }

        fn finish(self) -> Vec<u8> {
            let header_len = BTF_HEADER_SIZE as u32;
            let type_len = self.types.len() as u32;
            let string_len = self.strings.len() as u32;
            let mut result =
                Vec::with_capacity(BTF_HEADER_SIZE + self.types.len() + self.strings.len());
            result.extend_from_slice(&BTF_MAGIC.to_le_bytes());
            result.push(1);
            result.push(0);
            result.extend_from_slice(&header_len.to_le_bytes());
            result.extend_from_slice(&0u32.to_le_bytes());
            result.extend_from_slice(&type_len.to_le_bytes());
            result.extend_from_slice(&type_len.to_le_bytes());
            result.extend_from_slice(&string_len.to_le_bytes());
            result.extend_from_slice(&self.types);
            result.extend_from_slice(&self.strings);
            result
        }
    }

    fn fixture_btf() -> Vec<u8> {
        let mut btf = FixtureBuilder::new();
        let u32_type = btf.add_type("u32", KIND_INT, 0, 4, &32u32.to_le_bytes());
        let u64_type = btf.add_type("u64", KIND_INT, 0, 8, &64u32.to_le_bytes());
        let queue_fwd = btf.add_type("request_queue", KIND_FWD, 0, 0, &[]);
        let disk_fwd = btf.add_type("gendisk", KIND_FWD, 0, 0, &[]);
        let queue_ptr = btf.add_type("", KIND_PTR, 0, queue_fwd, &[]);
        let disk_ptr = btf.add_type("", KIND_PTR, 0, disk_fwd, &[]);

        let request_payload_start = btf.types.len();
        let request_id = btf.add_type("request", KIND_STRUCT, 4, 40, &[0; 48]);
        btf.types.truncate(request_payload_start + 12);
        btf.member("q", queue_ptr, 0);
        btf.member("__sector", u64_type, 24 * 8);
        btf.member("__data_len", u32_type, 32 * 8);
        btf.member("cmd_flags", u32_type, 36 * 8);
        debug_assert_eq!(request_id, 7);

        let queue_payload_start = btf.types.len();
        let queue_id = btf.add_type("request_queue", KIND_STRUCT, 1, 8, &[0; 12]);
        btf.types.truncate(queue_payload_start + 12);
        btf.member("disk", disk_ptr, 0);
        debug_assert_eq!(queue_id, 8);

        let disk_payload_start = btf.types.len();
        let disk_id = btf.add_type("gendisk", KIND_STRUCT, 2, 8, &[0; 24]);
        btf.types.truncate(disk_payload_start + 12);
        btf.member("major", u32_type, 0);
        btf.member("first_minor", u32_type, 4 * 8);
        debug_assert_eq!(disk_id, 9);

        let request_ptr = btf.add_type("", KIND_PTR, 0, request_id, &[]);
        let data_ptr = btf.add_type("", KIND_PTR, 0, 0, &[]);
        let data_arg = btf.string("data");
        let rq_arg = btf.string("rq");
        let mut issue_proto = Vec::new();
        issue_proto.extend_from_slice(&data_arg.to_le_bytes());
        issue_proto.extend_from_slice(&data_ptr.to_le_bytes());
        issue_proto.extend_from_slice(&rq_arg.to_le_bytes());
        issue_proto.extend_from_slice(&request_ptr.to_le_bytes());
        let issue_proto_id = btf.add_type("", KIND_FUNC_PROTO, 2, 0, &issue_proto);
        let issue_callback = btf.add_type("", KIND_PTR, 0, issue_proto_id, &[]);
        btf.add_type(
            "btf_trace_block_rq_issue",
            KIND_TYPEDEF,
            0,
            issue_callback,
            &[],
        );

        let error_arg = btf.string("error");
        let bytes_arg = btf.string("nr_bytes");
        let mut complete_proto = Vec::new();
        complete_proto.extend_from_slice(&data_arg.to_le_bytes());
        complete_proto.extend_from_slice(&data_ptr.to_le_bytes());
        complete_proto.extend_from_slice(&rq_arg.to_le_bytes());
        complete_proto.extend_from_slice(&request_ptr.to_le_bytes());
        complete_proto.extend_from_slice(&error_arg.to_le_bytes());
        complete_proto.extend_from_slice(&u32_type.to_le_bytes());
        complete_proto.extend_from_slice(&bytes_arg.to_le_bytes());
        complete_proto.extend_from_slice(&u32_type.to_le_bytes());
        let complete_proto_id = btf.add_type("", KIND_FUNC_PROTO, 4, 0, &complete_proto);
        let complete_callback = btf.add_type("", KIND_PTR, 0, complete_proto_id, &[]);
        btf.add_type(
            "btf_trace_block_rq_complete",
            KIND_TYPEDEF,
            0,
            complete_callback,
            &[],
        );
        btf.finish()
    }

    #[test]
    fn extracts_verified_request_layout_and_raw_tracepoint_arguments() {
        let layout = request_layout_from_btf(&fixture_btf()).unwrap();
        assert_eq!(
            layout,
            IoRequestLayout {
                request_q: 0,
                request_sector: 24,
                request_data_len: 32,
                request_cmd_flags: 36,
                queue_disk: 0,
                gendisk_major: 0,
                gendisk_first_minor: 4,
            }
        );
    }

    #[test]
    fn request_pointer_ids_keep_same_sector_and_flushes_separate_out_of_order() {
        use std::collections::HashMap;

        use fast_common::{IoRequestId, PendingIo};

        // These target requests all use the same device and sector. The
        // non-target request has a distinct pointer but is deliberately not
        // inserted into the target map.
        let read = IoRequestId::from_address(0x1000);
        let write = IoRequestId::from_address(0x2000);
        let flush_a = IoRequestId::from_address(0x3000);
        let flush_b = IoRequestId::from_address(0x4000);
        let non_target = IoRequestId::from_address(0x5000);
        let mut pending = HashMap::new();
        pending.insert(
            read,
            PendingIo {
                start_ns: 10,
                tid: 41,
                op: 0,
            },
        );
        pending.insert(
            write,
            PendingIo {
                start_ns: 20,
                tid: 42,
                op: 1,
            },
        );
        pending.insert(
            flush_a,
            PendingIo {
                start_ns: 30,
                tid: 41,
                op: 2,
            },
        );
        pending.insert(
            flush_b,
            PendingIo {
                start_ns: 40,
                tid: 42,
                op: 2,
            },
        );

        let completed_write = pending.remove(&write).unwrap();
        assert_eq!((completed_write.tid, completed_write.op), (42, 1));
        let completed_flush_b = pending.remove(&flush_b).unwrap();
        assert_eq!(
            (
                completed_flush_b.start_ns,
                completed_flush_b.tid,
                completed_flush_b.op
            ),
            (40, 42, 2)
        );
        let completed_read = pending.remove(&read).unwrap();
        assert_eq!((completed_read.tid, completed_read.op), (41, 0));
        let completed_flush_a = pending.remove(&flush_a).unwrap();
        assert_eq!(
            (
                completed_flush_a.start_ns,
                completed_flush_a.tid,
                completed_flush_a.op
            ),
            (30, 41, 2)
        );
        assert!(pending.remove(&non_target).is_none());
    }

    #[test]
    fn rejects_malformed_btf_and_missing_request_fields() {
        assert!(ParsedBtf::parse(&[0; 24]).is_err());
        let mut fixture = fixture_btf();
        let btf = ParsedBtf::parse(&fixture).unwrap();
        let (_, alias) = btf
            .find_type("btf_trace_block_rq_issue", KIND_TYPEDEF)
            .unwrap();
        let (_, callback) = btf.resolve_type(alias.size_or_type).unwrap();
        let (_, prototype) = btf.resolve_type(callback.size_or_type).unwrap();
        let request_argument_type = prototype.payload_offset + 12;
        drop(btf);
        fixture[request_argument_type..request_argument_type + 4]
            .copy_from_slice(&1u32.to_le_bytes());
        assert!(request_layout_from_btf(&fixture).is_err());
    }
}
