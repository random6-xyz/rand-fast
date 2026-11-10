//! Read-only access to incident bundles.
//!
//! The daemon's writer in [`crate::daemon_storage`] owns the layout and the
//! deletion rules. Readers are a different trust problem: they may be a
//! different user, running `fast incidents` against a directory they do not
//! own, and the bundles they open may have been damaged by a full disk or
//! edited by someone else. So this module never writes, never follows a
//! symlink, and never trusts a length: every read is bounded, every entry is
//! opened relative to an already-open directory with `O_NOFOLLOW`, and the
//! bundle marker decides what a bundle is.
//!
//! # What a reader does not enforce
//!
//! Ownership equality and "not group/other writable" are writer rules. A
//! reader that applied them could not read root's `/var/lib/rand-fast` as
//! root, which is the normal way to inspect a production host. What a reader
//! does enforce is that nothing it opens can redirect it elsewhere: no
//! symlinked component, no symlinked bundle, no bundle file that is not a
//! regular file.

use anyhow::{Context, Result, bail};
use std::{
    ffi::{CString, OsStr, OsString},
    fs::{self, File},
    io::Read,
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::ffi::OsStrExt,
    },
    path::{Component, Path},
};

use crate::daemon_storage::{MARKER, MARKER_CONTENT};

/// Largest manifest, diagnosis, completion marker or summary a reader accepts.
pub(crate) const TEXT_CAP: u64 = 1024 * 1024;

/// Largest interval history or slow-sample list a reader accepts.
pub(crate) const BULK_CAP: u64 = 8 * 1024 * 1024;

/// A bundle never has more files than this. The writer produces six; anything
/// else is either damage or an attempt to make a listing allocate without end.
const MAX_FILES: usize = 64;

fn openat(dir: &File, name: &OsStr, flags: i32) -> std::io::Result<File> {
    let name = CString::new(name.as_bytes())
        .map_err(|_| std::io::Error::from(std::io::ErrorKind::InvalidInput))?;
    let fd = unsafe {
        libc::openat(
            dir.as_raw_fd(),
            name.as_ptr(),
            flags | libc::O_CLOEXEC | libc::O_NOFOLLOW,
            0,
        )
    };
    if fd < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(unsafe { File::from_raw_fd(fd) })
}

fn open_dir(dir: &File, name: &OsStr) -> std::io::Result<File> {
    openat(
        dir,
        name,
        libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NONBLOCK,
    )
}

fn is_not_found(error: &anyhow::Error) -> bool {
    error
        .downcast_ref::<std::io::Error>()
        .is_some_and(|error| error.kind() == std::io::ErrorKind::NotFound)
}

/// Describes an open failure in the terms an operator needs.
fn open_reason(error: &std::io::Error) -> String {
    match error.raw_os_error() {
        // O_NOFOLLOW on a symlink, and O_DIRECTORY on a non-directory, both
        // arrive as one of these two. The reason string must not read as a
        // filesystem failure when the entry is simply not a bundle.
        Some(libc::ELOOP) => "symlink".to_string(),
        Some(libc::ENOTDIR) => "not a directory".to_string(),
        _ => error.to_string(),
    }
}

/// The kind of thing an entry in the incident directory is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Kind {
    Directory,
    File,
    Symlink,
    /// Opened no better than "something else", or not inspectable at all.
    Other,
}

/// One entry of the incident directory, as a listing sees it.
pub(crate) struct Entry {
    pub name: OsString,
    pub kind: Kind,
}

/// An opened incident directory.
pub(crate) struct Store {
    dir: File,
}

impl Store {
    /// Opens the incident directory without following links.
    ///
    /// `Ok(None)` means the directory does not exist yet, which is a normal
    /// state: a daemon that has never triggered has nothing to read. Every
    /// other failure (a symlinked component, no permission) is an error the
    /// caller reports, because it is not the same as "no incidents".
    pub(crate) fn open_optional(path: &Path) -> Result<Option<Self>> {
        if path.as_os_str().is_empty() {
            bail!("incident directory path is empty");
        }
        let mut dir = File::open(if path.is_absolute() { "/" } else { "." })?;
        for component in path.components() {
            let name = match component {
                Component::RootDir | Component::CurDir => continue,
                Component::Normal(name) => name,
                _ => bail!("incident directory path must not contain `..`"),
            };
            match open_dir(&dir, name) {
                Ok(next) => dir = next,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
                Err(error) => {
                    return Err(error).with_context(|| {
                        format!(
                            "open incident directory {} without following links",
                            path.display()
                        )
                    });
                }
            }
        }
        Ok(Some(Self { dir }))
    }

    /// Lists the directory, classifying every entry without following links.
    pub(crate) fn entries(&self) -> Result<Vec<Entry>> {
        // This procfs link refers only to our already-open directory, not to a
        // user-supplied path.
        let path = format!("/proc/self/fd/{}", self.dir.as_raw_fd());
        let mut entries = Vec::new();
        for entry in fs::read_dir(path)? {
            let entry = entry?;
            let name = entry.file_name();
            let kind = match openat(&self.dir, &name, libc::O_PATH) {
                Ok(handle) => match handle.metadata() {
                    Ok(metadata) if metadata.is_dir() => Kind::Directory,
                    Ok(metadata) if metadata.is_file() => Kind::File,
                    Ok(metadata) if metadata.file_type().is_symlink() => Kind::Symlink,
                    Ok(_) => Kind::Other,
                    Err(_) => Kind::Other,
                },
                Err(_) => Kind::Other,
            };
            entries.push(Entry { name, kind });
        }
        entries.sort_by(|left, right| left.name.cmp(&right.name));
        Ok(entries)
    }

    /// Opens one bundle, or explains why the entry is not one.
    ///
    /// The marker is the definition: a directory named like an incident but
    /// without the marker is user data, and a reader must not interpret it as
    /// a damaged bundle just because of its name.
    pub(crate) fn open_bundle(&self, name: &OsStr) -> Result<Bundle, String> {
        // Inspect the entry itself before opening it as a directory: with
        // `O_DIRECTORY | O_NOFOLLOW` the kernel reports ENOTDIR for a symlink,
        // which would turn "this is a link" into the wrong explanation.
        let handle = openat(&self.dir, name, libc::O_PATH).map_err(|error| open_reason(&error))?;
        let metadata = handle.metadata().map_err(|error| open_reason(&error))?;
        if metadata.file_type().is_symlink() {
            return Err("symlink".to_string());
        }
        if !metadata.is_dir() {
            return Err("not a directory".to_string());
        }
        drop(handle);
        let dir = open_dir(&self.dir, name).map_err(|error| open_reason(&error))?;
        let marker = read_file(&dir, OsStr::new(MARKER), 128).map_err(|error| {
            if is_not_found(&error) {
                "no bundle marker".to_string()
            } else {
                format!("marker unreadable: {error}")
            }
        })?;
        match marker {
            None => Err("no bundle marker".to_string()),
            Some(bytes) if bytes == MARKER_CONTENT.as_bytes() => Ok(Bundle {
                name: name.to_string_lossy().into_owned(),
                dir,
            }),
            Some(_) => Err("not a rand-fast bundle marker".to_string()),
        }
    }
}

/// One opened bundle directory.
pub(crate) struct Bundle {
    name: String,
    dir: File,
}

impl Bundle {
    pub(crate) fn name(&self) -> &str {
        &self.name
    }

    /// Reads a bundle file, or `Ok(None)` when it is absent.
    ///
    /// Present-but-wrong is an error rather than an absence: a symlinked or
    /// oversized file is something an operator has to be told about, not
    /// silently skipped as if the daemon had never written it.
    pub(crate) fn read(&self, name: &str, cap: u64) -> Result<Option<Vec<u8>>> {
        read_file(&self.dir, OsStr::new(name), cap).with_context(|| format!("read {name}"))
    }

    /// Reads a bundle file as JSON.
    pub(crate) fn read_json(&self, name: &str, cap: u64) -> Result<Option<serde_json::Value>> {
        let Some(bytes) = self.read(name, cap)? else {
            return Ok(None);
        };
        let text =
            std::str::from_utf8(&bytes).with_context(|| format!("{name} is not valid UTF-8"))?;
        serde_json::from_str(text)
            .map(Some)
            .with_context(|| format!("{name} is not valid JSON"))
    }

    /// The regular files in the bundle, with their sizes.
    ///
    /// Subdirectories are not followed and are not listed: a bundle is a flat
    /// set of documents, so anything else is damage or unrelated data, and
    /// either way it is not something a reader should render.
    pub(crate) fn files(&self) -> Result<Vec<(String, u64)>> {
        let path = format!("/proc/self/fd/{}", self.dir.as_raw_fd());
        let mut files = Vec::new();
        for entry in fs::read_dir(path)? {
            let entry = entry?;
            let name = entry.file_name();
            let Ok(handle) = openat(&self.dir, &name, libc::O_PATH) else {
                continue;
            };
            let Ok(metadata) = handle.metadata() else {
                continue;
            };
            if !metadata.is_file() {
                continue;
            }
            let Some(name) = name.to_str() else {
                continue;
            };
            files.push((name.to_string(), metadata.len()));
            if files.len() > MAX_FILES {
                bail!("bundle holds more than {MAX_FILES} files");
            }
        }
        files.sort();
        Ok(files)
    }
}

fn read_file(dir: &File, name: &OsStr, cap: u64) -> Result<Option<Vec<u8>>> {
    let file = match openat(dir, name, libc::O_RDONLY | libc::O_NONBLOCK) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    let metadata = file.metadata()?;
    if !metadata.is_file() {
        bail!("not a regular file");
    }
    if metadata.len() > cap {
        bail!(
            "is {} bytes, over the {cap} byte read limit",
            metadata.len()
        );
    }
    let mut bytes = Vec::new();
    file.take(cap.saturating_add(1)).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > cap {
        bail!("grew past the {cap} byte read limit while being read");
    }
    Ok(Some(bytes))
}

/// Is this a name the daemon could have written?
///
/// The writer and the reader have to agree on this, or rotation and `latest`
/// would disagree about which directories are incidents. One definition, used
/// by both.
pub(crate) fn valid_bundle_name(name: &str) -> bool {
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

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use std::{
        os::unix::fs::{PermissionsExt, symlink},
        sync::atomic::{AtomicU64, Ordering},
    };

    static NEXT: AtomicU64 = AtomicU64::new(0);

    pub(crate) struct Temp(pub std::path::PathBuf);
    impl Temp {
        pub(crate) fn new() -> Self {
            let path = std::env::temp_dir().join(format!(
                "fast-reader-{}-{}",
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

    pub(crate) fn bundle(root: &Path, name: &str) -> std::path::PathBuf {
        let dir = root.join(name);
        fs::create_dir(&dir).unwrap();
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).unwrap();
        fs::write(dir.join(MARKER), MARKER_CONTENT).unwrap();
        dir
    }

    #[test]
    fn a_missing_directory_is_absent_not_an_error() {
        let t = Temp::new();
        assert!(Store::open_optional(&t.0.join("nope")).unwrap().is_none());
    }

    #[test]
    fn symlinked_components_are_refused() {
        let t = Temp::new();
        let real = t.0.join("real");
        fs::create_dir(&real).unwrap();
        symlink(&real, t.0.join("link")).unwrap();
        assert!(Store::open_optional(&t.0.join("link")).is_err());
        let store = Store::open_optional(&t.0).unwrap().unwrap();
        assert_eq!(store.entries().unwrap().len(), 2);
        let entry = store
            .entries()
            .unwrap()
            .into_iter()
            .find(|entry| entry.name == "link")
            .unwrap();
        assert_eq!(entry.kind, Kind::Symlink);
    }

    #[test]
    fn path_traversal_is_refused() {
        let t = Temp::new();
        assert!(Store::open_optional(&t.0.join("../..")).is_err());
    }

    #[test]
    fn the_marker_defines_a_bundle() {
        let t = Temp::new();
        let store = Store::open_optional(&t.0).unwrap().unwrap();
        fs::create_dir(t.0.join("incident-000000001000s")).unwrap();
        fs::create_dir(t.0.join("notes")).unwrap();
        fs::write(t.0.join("notes/data"), "keep").unwrap();
        assert_eq!(
            store.open_bundle(OsStr::new("notes")).err().unwrap(),
            "no bundle marker"
        );
        let dir = bundle(&t.0, "incident-000000002000s");
        assert!(
            store
                .open_bundle(OsStr::new("incident-000000002000s"))
                .is_ok()
        );
        fs::write(dir.join(MARKER), "something else").unwrap();
        assert_eq!(
            store
                .open_bundle(OsStr::new("incident-000000002000s"))
                .err()
                .unwrap(),
            "not a rand-fast bundle marker"
        );
    }

    #[test]
    fn a_symlinked_bundle_is_refused() {
        let t = Temp::new();
        let outside = Temp::new();
        fs::write(outside.0.join(MARKER), MARKER_CONTENT).unwrap();
        symlink(&outside.0, t.0.join("incident-000000001000s")).unwrap();
        let store = Store::open_optional(&t.0).unwrap().unwrap();
        assert_eq!(
            store
                .open_bundle(OsStr::new("incident-000000001000s"))
                .err()
                .unwrap(),
            "symlink"
        );
    }

    #[test]
    fn reads_are_bounded_and_refuse_non_regular_files() {
        let t = Temp::new();
        bundle(&t.0, "incident-000000001000s");
        let store = Store::open_optional(&t.0).unwrap().unwrap();
        let bundle = store
            .open_bundle(OsStr::new("incident-000000001000s"))
            .unwrap();
        fs::write(
            t.0.join("incident-000000001000s/manifest.json"),
            vec![b'x'; 2048],
        )
        .unwrap();
        let error = format!("{:#}", bundle.read("manifest.json", 1024).unwrap_err());
        assert!(error.contains("read limit"), "{error}");
        assert_eq!(bundle.read("absent.json", 1024).unwrap(), None);
        let outside = Temp::new();
        fs::write(outside.0.join("data"), "outside").unwrap();
        symlink(
            outside.0.join("data"),
            t.0.join("incident-000000001000s/diagnosis.json"),
        )
        .unwrap();
        assert!(bundle.read("diagnosis.json", 1024).is_err());
        assert_eq!(
            fs::read_to_string(outside.0.join("data")).unwrap(),
            "outside"
        );
    }

    #[test]
    fn file_listing_skips_directories_and_is_sorted() {
        let t = Temp::new();
        bundle(&t.0, "incident-000000001000s");
        let store = Store::open_optional(&t.0).unwrap().unwrap();
        let dir = t.0.join("incident-000000001000s");
        fs::write(dir.join("summary.txt"), "text").unwrap();
        fs::write(dir.join("manifest.json"), "{}").unwrap();
        fs::create_dir(dir.join("nested")).unwrap();
        let bundle = store
            .open_bundle(OsStr::new("incident-000000001000s"))
            .unwrap();
        let files = bundle.files().unwrap();
        assert_eq!(
            files
                .iter()
                .map(|(name, _)| name.as_str())
                .collect::<Vec<_>>(),
            vec![MARKER, "manifest.json", "summary.txt"]
        );
    }

    #[test]
    fn bundle_names_follow_the_writer_format() {
        assert!(valid_bundle_name("incident-000000001000s"));
        assert!(valid_bundle_name("incident-000000001000s-2"));
        assert!(!valid_bundle_name("incident-000000001000"));
        assert!(!valid_bundle_name("incident-1s"));
        assert!(!valid_bundle_name("incident-000000001000s-x"));
        assert!(!valid_bundle_name("notes"));
    }
}
