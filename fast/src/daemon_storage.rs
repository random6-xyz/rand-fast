//! Incident storage operations. The effective user is the trust boundary.
use anyhow::{Context, Result, bail};
use std::{
    collections::HashSet,
    ffi::{CString, OsStr},
    fs::{self, File},
    io::{Read, Write},
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::{ffi::OsStrExt, fs::MetadataExt},
    },
    path::{Component, Path},
};

const MARKER: &str = ".rand-fast-incident";
const CONTENT: &str = "rand-fast incident bundle v1\n";
const FILES: &[&str] = &[
    MARKER,
    "manifest.json",
    "intervals.json",
    "slow-samples.json",
    "diagnosis.json",
    "summary.txt",
    "complete.json",
];

fn cstr(name: &OsStr) -> Result<CString> {
    Ok(CString::new(name.as_bytes())?)
}
fn openat(dir: &File, name: &OsStr, flags: i32) -> Result<File> {
    let name = cstr(name)?;
    let fd = unsafe {
        libc::openat(
            dir.as_raw_fd(),
            name.as_ptr(),
            flags | libc::O_CLOEXEC | libc::O_NOFOLLOW,
            0o600,
        )
    };
    if fd < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(unsafe { File::from_raw_fd(fd) })
}
fn mkdirat(dir: &File, name: &OsStr) -> std::io::Result<()> {
    let name = CString::new(name.as_bytes())
        .map_err(|_| std::io::Error::from(std::io::ErrorKind::InvalidInput))?;
    if unsafe { libc::mkdirat(dir.as_raw_fd(), name.as_ptr(), 0o700) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}
fn unlinkat(dir: &File, name: &OsStr, flags: i32) -> Result<()> {
    let name = cstr(name)?;
    if unsafe { libc::unlinkat(dir.as_raw_fd(), name.as_ptr(), flags) } != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(())
}
fn open_dir(dir: &File, name: &OsStr) -> Result<File> {
    openat(dir, name, libc::O_RDONLY | libc::O_DIRECTORY)
}
fn trusted(dir: &File) -> Result<()> {
    trusted_for(dir, unsafe { libc::geteuid() })
}
fn trusted_for(dir: &File, uid: u32) -> Result<()> {
    let m = dir.metadata()?;
    if !m.is_dir() || m.uid() != uid || m.mode() & 0o022 != 0 {
        bail!(
            "incident directory must be owned by the effective user and not writable by group or others"
        );
    }
    Ok(())
}
fn trusted_parent(dir: &File) -> Result<()> {
    trusted_parent_for(dir, unsafe { libc::geteuid() })
}
fn trusted_parent_for(dir: &File, uid: u32) -> Result<()> {
    let m = dir.metadata()?;
    // A sticky directory owned by root or this user protects entries owned by
    // this user from other users, as in /tmp. The parent owner is trusted.
    if !m.is_dir()
        || (m.uid() != uid && m.uid() != 0)
        || (m.mode() & 0o022 != 0 && m.mode() & libc::S_ISVTX == 0)
    {
        bail!("untrusted ancestor in incident output path");
    }
    Ok(())
}
fn entries(dir: &File) -> Result<Vec<std::ffi::OsString>> {
    // This procfs link refers only to our already-open directory, not to a user path.
    let path = format!("/proc/self/fd/{}", dir.as_raw_fd());
    fs::read_dir(path)?.map(|e| Ok(e?.file_name())).collect()
}

/// A lower bound when an entry cannot be safely inspected.
#[derive(Default)]
struct MeasuredSize {
    bytes: u64,
    unknown: bool,
}

fn measure_entry(
    dir: &File,
    name: &OsStr,
    visited: &mut HashSet<(u64, u64)>,
    depth: usize,
) -> MeasuredSize {
    let mut result = MeasuredSize::default();
    let Ok(handle) = openat(dir, name, libc::O_PATH) else {
        result.unknown = true;
        return result;
    };
    let Ok(metadata) = handle.metadata() else {
        result.unknown = true;
        return result;
    };
    if metadata.is_file() {
        result.bytes = metadata.len();
    } else if metadata.is_dir() {
        if depth >= 128 || !visited.insert((metadata.dev(), metadata.ino())) {
            result.unknown = true;
            return result;
        }
        let Ok(child) = open_dir(dir, name) else {
            result.unknown = true;
            return result;
        };
        // Reject a directory replaced between the no-follow metadata and open.
        if !child
            .metadata()
            .is_ok_and(|m| m.dev() == metadata.dev() && m.ino() == metadata.ino())
        {
            result.unknown = true;
            return result;
        }
        match entries(&child) {
            Ok(names) => {
                for name in names {
                    let part = measure_entry(&child, &name, visited, depth + 1);
                    match result.bytes.checked_add(part.bytes) {
                        Some(bytes) => result.bytes = bytes,
                        None => {
                            result.bytes = u64::MAX;
                            result.unknown = true;
                        }
                    }
                    result.unknown |= part.unknown;
                }
            }
            Err(_) => result.unknown = true,
        }
    } else {
        // Do not follow links or estimate the size of special files.
        result.unknown = true;
    }
    result
}

pub(super) struct Output {
    dir: File,
}
impl Output {
    pub(super) fn open(path: &Path) -> Result<Self> {
        let mut dir = File::open(if path.is_absolute() { "/" } else { "." })?;
        trusted_parent(&dir)?;
        for component in path.components() {
            let name = match component {
                Component::RootDir | Component::CurDir => continue,
                Component::Normal(name) => name,
                _ => bail!("parent components are not allowed in incident output"),
            };
            match open_dir(&dir, name) {
                Ok(next) => dir = next,
                Err(e)
                    if e.downcast_ref::<std::io::Error>()
                        .is_some_and(|e| e.kind() == std::io::ErrorKind::NotFound) =>
                {
                    match mkdirat(&dir, name) {
                        Ok(()) => (),
                        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => (),
                        Err(e) => return Err(e.into()),
                    }
                    dir = open_dir(&dir, name)?;
                }
                Err(e) => return Err(e).context("open incident output without following links"),
            }
            trusted_parent(&dir)?;
        }
        trusted(&dir)?;
        Ok(Self { dir })
    }
    pub(super) fn create(&self, stamp: &str) -> Result<Bundle> {
        for suffix in 1..=1000 {
            let name = if suffix == 1 {
                format!("incident-{stamp}")
            } else {
                format!("incident-{stamp}-{suffix}")
            };
            match mkdirat(&self.dir, OsStr::new(&name)) {
                Ok(()) => {
                    let dir = open_dir(&self.dir, OsStr::new(&name))?;
                    trusted(&dir)?;
                    let bundle = Bundle { dir, name };
                    bundle.write(MARKER, CONTENT)?;
                    return Ok(bundle);
                }
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(e) => return Err(e.into()),
            }
        }
        bail!("too many incidents within one second")
    }
    // Size accounting is independent of deletion eligibility. Inaccessible
    // entries and links leave the total as a lower bound, never as zero.
    pub(super) fn rotate(&self, max: u64, current: &str) -> Result<Rotation> {
        self.rotate_with(max, current, |_| {}, |name| self.remove(name))
    }
    fn rotate_with(
        &self,
        max: u64,
        current: &str,
        mut before_remove: impl FnMut(&OsStr),
        mut remove: impl FnMut(&OsStr) -> Result<()>,
    ) -> Result<Rotation> {
        let mut names = entries(&self.dir)?;
        names.sort();
        let mut bundles = Vec::new();
        let mut unknown = false;
        let mut total = 0u64;
        let mut visited = HashSet::new();
        for name in names {
            let measured = measure_entry(&self.dir, &name, &mut visited, 0);
            total = total
                .checked_add(measured.bytes)
                .context("incident size overflow")?;
            unknown |= measured.unknown;
            if let Ok(Some(size)) = self.inspect(&name) {
                bundles.push((name, size));
            }
        }
        for (name, size) in bundles {
            if total <= max {
                break;
            }
            if name == OsStr::new(current) {
                continue;
            }
            before_remove(&name);
            if let Err(error) = remove(&name) {
                eprintln!("warning: failed to remove incident {:?}: {error:#}", name);
                unknown = true;
                continue;
            }
            total = total.saturating_sub(size);
        }
        Ok(Rotation { total, unknown })
    }
    fn inspect(&self, name: &OsStr) -> Result<Option<u64>> {
        let Some(name_str) = name.to_str() else {
            return Ok(None);
        };
        if !valid_name(name_str) {
            return Ok(None);
        }
        let dir = open_dir(&self.dir, name)?;
        trusted(&dir)?;
        let mut marker = false;
        let mut total = 0u64;
        for name in entries(&dir)? {
            let Some(s) = name.to_str() else {
                return Ok(None);
            };
            if !FILES.contains(&s) {
                return Ok(None);
            }
            let file = openat(&dir, &name, libc::O_RDONLY | libc::O_NONBLOCK)?;
            let m = file.metadata()?;
            if !m.is_file() || m.uid() != unsafe { libc::geteuid() } || m.mode() & 0o022 != 0 {
                return Ok(None);
            }
            total = total
                .checked_add(m.len())
                .context("incident size overflow")?;
            if s == MARKER {
                let mut contents = String::new();
                file.take(128).read_to_string(&mut contents)?;
                marker = contents == CONTENT;
            }
        }
        Ok(marker.then_some(total))
    }
    fn remove(&self, name: &OsStr) -> Result<()> {
        if self.inspect(name)?.is_none() {
            bail!("bundle changed before deletion");
        }
        let dir = open_dir(&self.dir, name)?;
        trusted(&dir)?;
        // Never recurse. If an unexpected entry is added, rmdir fails closed.
        for name in entries(&dir)? {
            let Some(s) = name.to_str() else {
                bail!("unknown bundle entry")
            };
            if !FILES.contains(&s) {
                bail!("unknown bundle entry");
            }
            let file = openat(&dir, &name, libc::O_RDONLY | libc::O_NONBLOCK)?;
            let m = file.metadata()?;
            if !m.is_file() || m.uid() != unsafe { libc::geteuid() } || m.mode() & 0o022 != 0 {
                bail!("untrusted bundle entry");
            }
            unlinkat(&dir, &name, 0)?;
        }
        unlinkat(&self.dir, name, libc::AT_REMOVEDIR)
    }
    pub(super) fn read_latest(&self, max_bytes: u64) -> Result<Option<String>> {
        let mut names = entries(&self.dir)?;
        names.sort();
        for name in names.into_iter().rev() {
            let Ok(dir) = open_dir(&self.dir, &name) else {
                continue;
            };
            if trusted(&dir).is_err() {
                continue;
            }
            if openat(
                &dir,
                OsStr::new("complete.json"),
                libc::O_RDONLY | libc::O_NONBLOCK,
            )
            .and_then(|f| {
                if f.metadata()?.is_file() {
                    Ok(f)
                } else {
                    bail!("not a regular file")
                }
            })
            .is_err()
            {
                continue;
            }
            let Ok(file) = openat(
                &dir,
                OsStr::new("intervals.json"),
                libc::O_RDONLY | libc::O_NONBLOCK,
            ) else {
                continue;
            };
            if !file.metadata()?.is_file() {
                continue;
            }
            let mut text = String::new();
            file.take(max_bytes.saturating_add(1))
                .read_to_string(&mut text)?;
            if text.len() as u64 > max_bytes {
                anyhow::bail!("restored interval history exceeds {max_bytes} bytes");
            }
            return Ok(Some(text));
        }
        Ok(None)
    }
}
fn valid_name(name: &str) -> bool {
    let Some((digits, suffix)) = name
        .strip_prefix("incident-")
        .and_then(|s| s.split_once('s'))
    else {
        return false;
    };
    digits.len() >= 12
        && digits.bytes().all(|b| b.is_ascii_digit())
        && (suffix.is_empty()
            || suffix
                .strip_prefix('-')
                .is_some_and(|s| !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit())))
}
pub(super) struct Rotation {
    pub total: u64,
    pub unknown: bool,
}
pub(super) struct Bundle {
    dir: File,
    name: String,
}
impl Bundle {
    pub(super) fn name(&self) -> &str {
        &self.name
    }
    pub(super) fn write(&self, name: &str, text: &str) -> Result<()> {
        let mut file = openat(
            &self.dir,
            OsStr::new(name),
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL,
        )?;
        file.write_all(text.as_bytes())?;
        Ok(())
    }
    pub(super) fn json(&self, name: &str, value: &serde_json::Value) -> Result<()> {
        self.write(name, &serde_json::to_string_pretty(value)?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        os::unix::fs::{PermissionsExt, symlink},
        sync::atomic::{AtomicU64, Ordering},
    };
    static NEXT: AtomicU64 = AtomicU64::new(0);
    struct Temp(std::path::PathBuf);
    impl Temp {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!(
                "fast-storage-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir(&path).unwrap();
            fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
            Self(path)
        }
    }
    impl Drop for Temp {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn output_rejects_shared_directories_and_symlink_components() {
        let t = Temp::new();
        let shared = t.0.join("shared");
        fs::create_dir(&shared).unwrap();
        fs::set_permissions(&shared, fs::Permissions::from_mode(0o777)).unwrap();
        assert!(Output::open(&shared).is_err());
        assert!(Output::open(&shared.join("new")).is_err());
        assert!(!shared.join("new").exists());
        symlink(&shared, t.0.join("link")).unwrap();
        assert!(Output::open(&t.0.join("link/new")).is_err());
        assert!(!shared.join("new").exists());
    }

    #[test]
    fn ownership_must_match_effective_user() {
        let t = Temp::new();
        let output = Output::open(&t.0).unwrap();
        let owner = output.dir.metadata().unwrap().uid();
        assert!(trusted_for(&output.dir, owner).is_ok());
        assert!(trusted_for(&output.dir, owner.wrapping_add(1)).is_err());
    }

    #[test]
    fn sudo_style_user_owned_cwd_is_not_a_trusted_root_ancestor() {
        let t = Temp::new();
        let cwd = File::open(&t.0).unwrap();
        let owner = cwd.metadata().unwrap().uid();
        if owner != 0 {
            assert!(trusted_parent_for(&cwd, 0).is_err());
            assert!(trusted_parent_for(&cwd, owner).is_ok());
        }
    }

    #[test]
    fn creation_never_overwrites_existing_bundle_files() {
        let t = Temp::new();
        let output = Output::open(&t.0).unwrap();
        let bundle = output.create("000000001000s").unwrap();
        bundle.write("summary.txt", "first").unwrap();
        assert!(bundle.write("summary.txt", "second").is_err());
        assert_eq!(
            fs::read_to_string(t.0.join(bundle.name()).join("summary.txt")).unwrap(),
            "first"
        );
    }

    #[test]
    fn pinned_bundle_does_not_follow_replacement_symlink() {
        let t = Temp::new();
        let outside = Temp::new();
        let output = Output::open(&t.0).unwrap();
        let bundle = output.create("000000001000s").unwrap();
        fs::write(outside.0.join("summary.txt"), "keep").unwrap();
        fs::rename(t.0.join(bundle.name()), t.0.join("moved")).unwrap();
        symlink(&outside.0, t.0.join(bundle.name())).unwrap();
        bundle.write("summary.txt", "incident").unwrap();
        assert_eq!(
            fs::read_to_string(outside.0.join("summary.txt")).unwrap(),
            "keep"
        );
        assert_eq!(
            fs::read_to_string(t.0.join("moved/summary.txt")).unwrap(),
            "incident"
        );
    }

    #[test]
    fn rotation_preserves_unrecognized_nested_legacy_and_symlink_data() {
        let t = Temp::new();
        let outside = Temp::new();
        fs::write(outside.0.join("data"), "keep").unwrap();
        let output = Output::open(&t.0).unwrap();
        let partial = output.create("000000001000s").unwrap();
        partial.write("manifest.json", "partial").unwrap();
        let legacy = t.0.join("incident-000000002000s");
        fs::create_dir(&legacy).unwrap();
        fs::write(legacy.join("complete.json"), "{}").unwrap();
        let nested = output.create("000000003000s").unwrap();
        fs::create_dir(t.0.join(nested.name()).join("user-data")).unwrap();
        fs::write(t.0.join(nested.name()).join("user-data/file"), "keep").unwrap();
        symlink(&outside.0, t.0.join("incident-000000004000s")).unwrap();
        let link = output.create("000000005000s").unwrap();
        symlink(
            outside.0.join("data"),
            t.0.join(link.name()).join("summary.txt"),
        )
        .unwrap();
        let result = output.rotate(0, "current").unwrap();
        assert!(result.unknown);
        assert!(!t.0.join(partial.name()).exists());
        assert!(legacy.exists() && t.0.join(nested.name()).join("user-data/file").exists());
        assert!(t.0.join(link.name()).exists() && outside.0.join("data").exists());
    }

    #[test]
    fn rotation_counts_legacy_and_user_files_without_deleting_them() {
        let t = Temp::new();
        let output = Output::open(&t.0).unwrap();
        let legacy = t.0.join("incident-000000000500s");
        fs::create_dir(&legacy).unwrap();
        fs::set_permissions(&legacy, fs::Permissions::from_mode(0o700)).unwrap();
        fs::write(legacy.join("complete.json"), "{}").unwrap();
        fs::write(legacy.join("intervals.json"), "[]").unwrap();
        fs::write(legacy.join("old-data"), vec![7; 100]).unwrap();
        let unrelated = t.0.join("notes");
        fs::create_dir(&unrelated).unwrap();
        fs::write(unrelated.join("data"), vec![1; 80]).unwrap();
        let old = output.create("000000001000s").unwrap();
        old.write("summary.txt", &"x".repeat(50)).unwrap();
        let current = output.create("000000002000s").unwrap();
        current.write("summary.txt", &"y".repeat(20)).unwrap();
        assert_eq!(output.read_latest(1024).unwrap(), Some("[]".to_string()));
        let old_size = output.inspect(OsStr::new(old.name())).unwrap().unwrap();
        let current_size = output.inspect(OsStr::new(current.name())).unwrap().unwrap();
        let retained = 104 + 80 + current_size;
        let result = output.rotate(retained, current.name()).unwrap();
        assert!(!result.unknown);
        assert_eq!(result.total, retained);
        assert!(old_size > 0 && !t.0.join(old.name()).exists());
        assert!(legacy.join("old-data").exists());
        assert!(unrelated.join("data").exists());
        assert!(t.0.join(current.name()).exists());
    }

    #[test]
    fn rotation_counts_unreadable_regular_files_without_opening_contents() {
        let t = Temp::new();
        let output = Output::open(&t.0).unwrap();
        let file = t.0.join("private-user-data");
        fs::write(&file, vec![0; 512]).unwrap();
        fs::set_permissions(&file, fs::Permissions::from_mode(0o000)).unwrap();
        let old = output.create("000000001000s").unwrap();
        let current = output.create("000000002000s").unwrap();
        let state = output
            .rotate(512 + CONTENT.len() as u64, current.name())
            .unwrap();
        assert!(!state.unknown);
        assert_eq!(state.total, 512 + CONTENT.len() as u64);
        assert!(!t.0.join(old.name()).exists());
        assert!(file.exists());
        fs::set_permissions(file, fs::Permissions::from_mode(0o600)).unwrap();
    }

    #[test]
    fn rotation_reports_known_overage_when_only_preserved_data_remains() {
        let t = Temp::new();
        let output = Output::open(&t.0).unwrap();
        fs::write(t.0.join("user-file"), vec![1; 1024]).unwrap();
        let current = output.create("000000002000s").unwrap();
        let state = output.rotate(10, current.name()).unwrap();
        assert!(!state.unknown);
        assert!(state.total >= 1024);
        assert!(t.0.join("user-file").exists());
        assert!(t.0.join(current.name()).exists());
    }

    #[test]
    fn rotation_rechecks_after_concurrent_insertion() {
        let t = Temp::new();
        let output = Output::open(&t.0).unwrap();
        let bundle = output.create("000000001000s").unwrap();
        bundle.write("summary.txt", "keep").unwrap();
        let result = output
            .rotate_with(
                0,
                "current",
                |name| {
                    fs::write(t.0.join(name).join("user-file"), "keep").unwrap();
                },
                |name| output.remove(name),
            )
            .unwrap();
        assert!(result.unknown && result.total > 0);
        assert_eq!(
            fs::read_to_string(t.0.join(bundle.name()).join("user-file")).unwrap(),
            "keep"
        );
        assert!(t.0.join(bundle.name()).join("summary.txt").exists());
    }

    #[test]
    fn rotation_failure_and_unreadable_unrelated_data_leave_cap_unknown() {
        let t = Temp::new();
        let output = Output::open(&t.0).unwrap();
        let bundle = output.create("000000001000s").unwrap();
        let unrelated = t.0.join("unrelated");
        fs::create_dir(&unrelated).unwrap();
        fs::set_permissions(&unrelated, fs::Permissions::from_mode(0o000)).unwrap();
        let result = output
            .rotate_with(
                0,
                "current",
                |_| {},
                |_| Err(std::io::Error::from(std::io::ErrorKind::PermissionDenied).into()),
            )
            .unwrap();
        assert!(result.unknown && result.total > 0);
        assert!(t.0.join(bundle.name()).exists());
        fs::set_permissions(unrelated, fs::Permissions::from_mode(0o700)).unwrap();
    }
}
