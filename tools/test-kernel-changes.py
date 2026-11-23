#!/usr/bin/env python3
"""Exercise the kernel matrix classifier with real Git histories."""

from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

CLASSIFIER = Path(__file__).resolve().parent / "kernel" / "changes.py"


class KernelChangesTest(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.repo = Path(directory.name)
        self.git("init", "--quiet", "--template=")
        self.write("README.md", "before\n")
        self.write("fast/src/runtime.rs", "baseline\n")
        self.base = self.commit()

    def git(self, *args):
        return subprocess.check_output(
            ["git", "-c", "user.name=Fixture", "-c", "user.email=fixture@example.org",
             "-c", "commit.gpgsign=false", *args],
            cwd=self.repo,
            text=True,
        ).strip()

    def write(self, path, content="changed\n"):
        file = self.repo / path
        file.parent.mkdir(parents=True, exist_ok=True)
        file.write_text(content, encoding="utf-8")

    def commit(self):
        self.git("add", "-A")
        self.git("commit", "--quiet", "-m", "fixture")
        return self.git("rev-parse", "HEAD")

    def classify(self, base):
        return subprocess.run(
            [sys.executable, CLASSIFIER, base, "HEAD"],
            cwd=self.repo,
            capture_output=True,
            text=True,
        )

    def expect(self, base, required):
        result = self.classify(base)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, f"{required}\n")

    def test_documentation_and_similarly_named_paths_are_not_sensitive(self):
        self.write("README.md")
        self.write("docs/fast/src/runtime.rs")
        self.write("fast-tools/runtime.rs")
        self.write("tools/rank-eval.sh.bak")
        self.write("docs/notes\nfast/src/fake.rs")
        self.commit()
        self.expect(self.base, "false")

    def test_runtime_build_and_gate_inputs_are_sensitive(self):
        base = self.base
        for path in (
            "fast/src/runtime.rs", "fast/build.rs", "fast/tests/example.rs",
            "fast-common/src/lib.rs", "fast-ebpf/src/main.rs",
            "Cargo.toml", "Cargo.lock", "rust-toolchain.toml", ".cargo/config.toml",
            "tools/kernel/kernels.tsv", "tools/qemu-smoke.sh", "tools/qemu-guest-mount.c",
            "tools/scenarios.json", "tools/scenarios.sh", "tools/scenarios-lib.sh",
            "tools/rank-eval.sh", "tools/check-qemu-results.sh",
            "tools/sched-workload/src/main.rs", "tools/fast-workload/Cargo.toml",
            "tools/fast-bench/src/main.rs", ".github/workflows/ci.yml",
            ".github/actions/run-qemu-gate/action.yml",
            ".github/actions/setup-rust-ebpf/action.yml", "fast/file with a\nnewline",
        ):
            with self.subTest(path=path):
                self.write(path)
                head = self.commit()
                self.expect(base, "true")
                base = head

    def test_deleting_a_sensitive_path(self):
        (self.repo / "fast/src/runtime.rs").unlink()
        self.commit()
        self.expect(self.base, "true")

    def test_moving_into_or_out_of_a_sensitive_path(self):
        self.git("mv", "fast/src/runtime.rs", "documented.rs")
        moved_out = self.commit()
        self.expect(self.base, "true")
        self.git("mv", "documented.rs", "fast/src/runtime.rs")
        self.commit()
        self.expect(moved_out, "true")

    def test_invalid_git_comparison_does_not_report_false(self):
        result = self.classify("missing-base")
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(result.stdout, "")
        self.assertIn("kernel changes:", result.stderr)


if __name__ == "__main__":
    unittest.main()
