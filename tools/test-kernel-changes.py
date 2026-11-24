#!/usr/bin/env python3
"""Exercise the kernel matrix classifier with real Git histories."""

from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

CLASSIFIER = Path(__file__).resolve().parent / "kernel" / "changes.py"

# One baseline file on each side of the classification: the matrix gate must
# notice the kernel-facing one and ignore the user-space one.
SENSITIVE_BASELINE = "fast/src/memory.rs"
USER_SPACE_BASELINE = "fast/src/runtime.rs"


class KernelChangesTest(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.repo = Path(directory.name)
        self.git("init", "--quiet", "--template=")
        self.write("README.md", "before\n")
        self.write(SENSITIVE_BASELINE, "baseline\n")
        self.write(USER_SPACE_BASELINE, "baseline\n")
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
        self.write("docs/fast/src/memory.rs")
        self.write("fast-tools/runtime.rs")
        self.write("tools/rank-eval.sh.bak")
        self.write("docs/notes\nfast/src/memory.rs")
        self.commit()
        self.expect(self.base, "false")

    def test_user_space_changes_keep_the_expanded_matrix_out(self):
        # Report formatting, the daemon, incidents, and the CLI cannot change
        # what a kernel does with the eBPF program.
        for path in (
            USER_SPACE_BASELINE,
            "fast/src/daemon.rs",
            "fast/src/scoring.rs",
            "fast/src/cli.rs",
            "fast/tests/example.rs",
            "tools/test-kernel-changes.py",
        ):
            with self.subTest(path=path):
                self.write(path)
                self.commit()
                self.expect(self.base, "false")

    def test_kernel_surface_paths_are_sensitive(self):
        base = self.base
        for path in (
            SENSITIVE_BASELINE, "fast/src/tcp.rs", "fast/src/network.rs",
            "fast/src/tcp_ownership.rs", "fast/src/tracepoint_layout.rs",
            "fast/src/io_request_layout.rs", "fast/build.rs", "fast/Cargo.toml",
            "fast-common/src/lib.rs", "fast-ebpf/src/main.rs",
            "Cargo.toml", "Cargo.lock", "rust-toolchain.toml", ".cargo/config.toml",
            "tools/kernel/kernels.tsv", "tools/qemu-smoke.sh", "tools/qemu-guest-mount.c",
            "tools/scenarios.json", "tools/scenarios.sh", "tools/scenarios-lib.sh",
            "tools/rank-eval.sh", "tools/check-qemu-results.sh",
            "tools/sched-workload/src/main.rs", "tools/fast-workload/Cargo.toml",
            ".github/workflows/ci.yml",
            ".github/actions/run-qemu-gate/action.yml",
            ".github/actions/setup-rust-ebpf/action.yml",
            "fast-ebpf/src/file with a\nnewline",
        ):
            with self.subTest(path=path):
                self.write(path)
                head = self.commit()
                self.expect(base, "true")
                base = head

    def test_deleting_a_sensitive_path(self):
        (self.repo / SENSITIVE_BASELINE).unlink()
        self.commit()
        self.expect(self.base, "true")

    def test_moving_into_or_out_of_a_sensitive_path(self):
        self.git("mv", SENSITIVE_BASELINE, "documented.rs")
        moved_out = self.commit()
        self.expect(self.base, "true")
        self.git("mv", "documented.rs", SENSITIVE_BASELINE)
        self.commit()
        self.expect(moved_out, "true")

    def test_invalid_git_comparison_does_not_report_false(self):
        result = self.classify("missing-base")
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(result.stdout, "")
        self.assertIn("kernel changes:", result.stderr)

    def test_the_gate_runs_for_pull_requests_the_classifier_called_user_space(self):
        # A user-space pull request skips the matrix, so the single gate cell is
        # the only real kernel the collector meets on that path. The two jobs
        # must stay complementary: if the gate stops covering user-space
        # changes, that path silently loses its only real-kernel check.
        workflow = (CLASSIFIER.parents[2] / ".github/workflows/ci.yml").read_text()
        gate = self.job(workflow, "qemu-real-kernel")
        matrix = self.job(workflow, "kernel-matrix")
        self.assertIn("outputs.kernel == 'false'", gate)
        self.assertIn("outputs.kernel != 'false'", matrix)

    def job(self, workflow, name):
        lines = workflow.splitlines()
        start = lines.index(f"  {name}:")
        block = [lines[start]]
        for line in lines[start + 1 :]:
            if line.startswith("  ") and not line.startswith("   ") and line.rstrip().endswith(":"):
                break
            block.append(line)
        return "\n".join(block)


if __name__ == "__main__":
    unittest.main()
