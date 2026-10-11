use std::{path::PathBuf, process::Command};

fn main() -> aya_build::Result<()> {
    aya_build::build_ebpf(
        [aya_build::Package {
            name: "fast-ebpf",
            root_dir: "../fast-ebpf",
            ..Default::default()
        }],
        aya_build::Toolchain::Nightly,
    )?;
    strip_dwarf();
    Ok(())
}

/// Removes DWARF from the built eBPF object.
///
/// The object is embedded in the userspace binary with `include_bytes_aligned!`
/// and then parsed by aya, so everything left in it is paid for twice: once as
/// bytes and again as whatever the loader builds from them. DWARF is about
/// three quarters of the object's bytes and the kernel never sees it; the
/// verifier only needs `.BTF` and `.BTF.ext`, which are left alone.
///
/// Measured on this object: 246232 bytes down to 36960, an eighty-five percent
/// reduction in what has to be shipped, read and parsed. It does not change the
/// loader's resident set, which turns out to be a fixed cost of about fifteen
/// megabytes whatever the object weighs; that is reported by the recorder
/// rather than papered over here.
///
/// A build flag would be the obvious way to do this, but aya-build sets
/// `CARGO_ENCODED_RUSTFLAGS` itself when it invokes cargo for the BPF target,
/// replacing anything inherited from the environment, so the object is
/// rewritten after the fact instead.
fn strip_dwarf() {
    let object = bpf_object_path();
    if !object.is_file() {
        // Nothing to strip is not a build failure: the object may not have
        // been produced, and aya-build's own error has already been reported.
        return;
    }
    let Some(strip) = llvm_strip() else {
        // Without llvm-strip the object is simply larger. Worth a note, since
        // the whole point is a smaller resident set.
        println!("cargo:warning=llvm-strip not found; the eBPF object keeps its DWARF");
        return;
    };

    let output = Command::new(&strip)
        .arg("--strip-debug")
        .arg("-o")
        .arg(&object)
        .arg(&object)
        .output();
    match output {
        Ok(result) if result.status.success() => {}
        Ok(result) => println!(
            "cargo:warning=llvm-strip failed ({}), the eBPF object keeps its DWARF",
            result.status
        ),
        Err(error) => println!("cargo:warning=could not run llvm-strip: {error}"),
    }
}

/// Path aya-build wrote the object to.
fn bpf_object_path() -> PathBuf {
    let out = std::env::var("OUT_DIR").expect("OUT_DIR is set for a build script");
    PathBuf::from(out)
        .join("aya-build")
        .join("target")
        .join("fast-ebpf")
        .join("bpfel-unknown-none")
        .join("release")
        .join("fast-ebpf")
}

/// Finds an llvm-strip, preferring an unversioned name and falling back to the
/// major-versioned ones distributions ship.
fn llvm_strip() -> Option<PathBuf> {
    for candidate in [
        "llvm-strip",
        "llvm-strip-19",
        "llvm-strip-18",
        "llvm-strip-17",
    ] {
        if let Ok(path) = which(candidate) {
            return Some(path);
        }
    }
    None
}

/// Locates a program on `PATH`, without a dependency on a `which` crate.
fn which(program: &str) -> Result<PathBuf, String> {
    let path = std::env::var_os("PATH").ok_or("PATH is not set")?;
    for directory in std::env::split_paths(&path) {
        let candidate = directory.join(program);
        if candidate.is_file() {
            return Ok(candidate);
        }
    }
    Err(format!("{program} not found on PATH"))
}
