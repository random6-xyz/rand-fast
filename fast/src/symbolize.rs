//! Stack symbolization shared by the collectors that report hot stacks.
//!
//! Both `fast cpu` and `fast off-cpu` capture stack ids and then have to turn
//! them back into something readable. The rules are the same for each: kernel
//! frames resolve through the running kernel's kallsyms, user frames through
//! the target process' live `/proc/<pid>` state, and a frame that cannot be
//! resolved keeps its raw instruction pointer rather than being dropped.
//!
//! Keeping this in one place matters because the two reports are read
//! side by side when diagnosing: a thread that is hot on CPU and also waiting
//! off CPU should show the same function names in both.

use std::path::Path;

use anyhow::{Context, Result};
use aya::{
    Ebpf,
    maps::{MapData, stack_trace::StackTraceMap},
};
use blazesym::symbolize::{
    Input, Symbolizer,
    source::{self, Source},
};

use crate::process;

/// One stack frame prepared for the report: symbolized when possible, raw
/// instruction pointer otherwise.
#[derive(Debug, PartialEq, Eq)]
pub struct Frame {
    /// `name+0xoff` when the frame resolved to a symbol.
    pub symbol: Option<String>,
    /// Module (executable or shared object) the symbol came from, if known.
    pub module: Option<String>,
    /// Raw instruction pointer, always available for display.
    pub ip: u64,
    /// True for kernel-space frames.
    pub kernel: bool,
}

impl Frame {
    /// Renders the frame for a report line, prefixed to mark kernel frames.
    pub fn render(&self) -> String {
        let prefix = if self.kernel { "[k] " } else { "" };
        let location = match (&self.symbol, &self.module) {
            (Some(symbol), Some(module)) => format!("{symbol} ({module})"),
            (Some(symbol), None) => symbol.clone(),
            (None, _) => format!("{:#x}", self.ip),
        };
        format!("{prefix}{location}")
    }

    /// The symbol name without the module suffix, for matching a frame
    /// against a known wait reason.
    pub fn symbol_name(&self) -> Option<&str> {
        self.symbol.as_deref().map(|symbol| {
            // render() appends "+0xoff" to a resolved symbol; the bare name is
            // what reason matching wants to compare against.
            symbol.split('+').next().unwrap_or(symbol)
        })
    }
}

/// Renders a blazesym result into a [`Frame`], keeping the raw ip as fallback.
fn frame_from_sym(ip: u64, kernel: bool, sym: &blazesym::symbolize::Sym) -> Frame {
    let offset = sym.offset;
    let mut symbol = sym.name.to_string();
    if offset > 0 {
        symbol.push_str(&format!("+{offset:#x}"));
    }
    let module = sym
        .module
        .as_ref()
        .map(|module| {
            Path::new(module)
                .file_name()
                .map(|name| name.to_string_lossy().into_owned())
                .unwrap_or_else(|| module.to_string_lossy().into_owned())
        })
        .filter(|name| !name.is_empty());
    Frame {
        symbol: Some(symbol),
        module,
        ip,
        kernel,
    }
}

/// Best-effort stack symbolizer: kernel frames via the running kernel's
/// kallsyms (through blazesym's kernel source), user frames via the target
/// process' live `/proc/<pid>` state.
pub struct StackSymbolizer {
    symbolizer: Symbolizer,
    kernel: Source<'static>,
    user: Option<Source<'static>>,
}

impl StackSymbolizer {
    /// Builds the symbolizer for the observed process. `user` is `None` when
    /// the process has already exited; its user stacks then stay unresolved.
    pub fn new(pid: u32) -> Self {
        let kernel = Source::Kernel(source::Kernel::default());
        let user = if process::is_alive(pid).unwrap_or(false) {
            let mut process = source::Process::new(blazesym::Pid::from(pid));
            // Symbolic /proc/<pid>/maps paths instead of /proc/<pid>/map_files:
            // map_files requires SYS_ADMIN even when CAP_BPF/CAP_PERFMON are
            // held, and symbolic paths suffice for still-running binaries.
            process.map_files = false;
            Some(Source::Process(process))
        } else {
            None
        };
        Self {
            symbolizer: Symbolizer::new(),
            kernel,
            user,
        }
    }

    /// Symbolizes kernel-space instruction pointers, best effort.
    pub fn kernel_frames(&mut self, ips: &[u64]) -> Vec<Frame> {
        self.frames(ips, true)
    }

    /// Symbolizes user-space instruction pointers, best effort.
    pub fn user_frames(&mut self, ips: &[u64]) -> Vec<Frame> {
        self.frames(ips, false)
    }

    fn frames(&mut self, ips: &[u64], kernel: bool) -> Vec<Frame> {
        if ips.is_empty() {
            return Vec::new();
        }
        let source = if kernel {
            &self.kernel
        } else {
            self.user.as_ref().unwrap_or(&self.kernel)
        };
        let resolved = if !kernel && self.user.is_none() {
            Vec::new()
        } else {
            self.symbolizer
                .symbolize(source, Input::AbsAddr(ips))
                .ok()
                .unwrap_or_default()
        };
        ips.iter()
            .enumerate()
            .map(|(i, &ip)| match resolved.get(i).and_then(|s| s.as_sym()) {
                Some(sym) => frame_from_sym(ip, kernel, sym),
                None => Frame {
                    symbol: None,
                    module: None,
                    ip,
                    kernel,
                },
            })
            .collect()
    }
}

/// The kernel and user stack trace maps, taken out of the loaded eBPF object
/// after collection. Lookups take no flags: `BPF_F_USER_STACK` only affects
/// the capture side, and kernel/user stacks are separated by map.
pub struct StackMaps {
    kernel: StackTraceMap<MapData>,
    user: StackTraceMap<MapData>,
}

impl StackMaps {
    /// Takes both stack trace maps out of the loaded object.
    pub fn take(bpf: &mut Ebpf) -> Result<Self> {
        let kernel: StackTraceMap<MapData> = bpf
            .take_map("STACK_TRACES")
            .context("eBPF map STACK_TRACES is missing")?
            .try_into()
            .context("STACK_TRACES has an unexpected map type or layout")?;
        let user: StackTraceMap<MapData> = bpf
            .take_map("STACK_TRACES_USER")
            .context("eBPF map STACK_TRACES_USER is missing")?
            .try_into()
            .context("STACK_TRACES_USER has an unexpected map type or layout")?;
        Ok(Self { kernel, user })
    }

    /// Reads the raw instruction pointers stored under one stack id.
    pub fn read(&self, stack_id: i64, user: bool) -> Result<Vec<u64>> {
        let Some(id) = stack_id_to_key(stack_id) else {
            return Ok(Vec::new());
        };
        let map = if user { &self.user } else { &self.kernel };
        let trace = map
            .get(&id, 0)
            .with_context(|| format!("failed to read stack {stack_id} from the stack trace map"))?;
        Ok(trace.frames().iter().map(|frame| frame.ip).collect())
    }
}

/// Converts a stack id into a map key, rejecting the negative values a failed
/// `bpf_get_stackid` returns.
///
/// The rejection has to happen before the cast: a negative id turned into an
/// unsigned key would address an unrelated entry and report a wrong stack as
/// if it were real.
fn stack_id_to_key(stack_id: i64) -> Option<u32> {
    if stack_id < 0 {
        return None;
    }
    u32::try_from(stack_id).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn renders_unresolved_frame_as_raw_pointer() {
        let frame = Frame {
            symbol: None,
            module: None,
            ip: 0xdead_beef,
            kernel: true,
        };
        assert_eq!(frame.render(), "[k] 0xdeadbeef");
    }

    #[test]
    fn renders_resolved_frame_with_module() {
        let frame = Frame {
            symbol: Some("futex_wait+0x12".to_string()),
            module: Some("vmlinux".to_string()),
            ip: 0x1000,
            kernel: true,
        };
        assert_eq!(frame.render(), "[k] futex_wait+0x12 (vmlinux)");
    }

    #[test]
    fn marks_user_frames_without_a_prefix() {
        let frame = Frame {
            symbol: Some("main".to_string()),
            module: None,
            ip: 0x2000,
            kernel: false,
        };
        assert_eq!(frame.render(), "main");
    }

    #[test]
    fn symbol_name_drops_the_offset() {
        let frame = Frame {
            symbol: Some("do_futex+0x8c".to_string()),
            module: Some("vmlinux".to_string()),
            ip: 0x3000,
            kernel: true,
        };
        assert_eq!(frame.symbol_name(), Some("do_futex"));
    }

    #[test]
    fn negative_stack_ids_never_reach_the_map() {
        // A failed bpf_get_stackid returns a negative value. Casting one into
        // an unsigned key would address an unrelated entry, so the conversion
        // has to reject it.
        assert_eq!(stack_id_to_key(-1), None);
        assert_eq!(stack_id_to_key(i64::MIN), None);
        assert_eq!(stack_id_to_key(0), Some(0));
        assert_eq!(stack_id_to_key(4095), Some(4095));
        // Beyond the map's capacity, which is a u32 range mismatch rather
        // than a negative id.
        assert_eq!(stack_id_to_key(i64::from(u32::MAX) + 1), None);
    }
}
