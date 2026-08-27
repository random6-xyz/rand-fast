fn main() -> aya_build::Result<()> {
    aya_build::build_ebpf(
        [aya_build::Package {
            name: "fast-ebpf",
            root_dir: "../fast-ebpf",
            ..Default::default()
        }],
        aya_build::Toolchain::Nightly,
    )
}
