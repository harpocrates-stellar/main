"""Tests for the portable source-path case-collision gate (#1225)."""

from __future__ import annotations

import io
import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

# Make devx/ importable when run from the repo root or the devx/ directory.
sys.path.insert(0, str(Path(__file__).resolve().parent))

import check_case_collisions as cc


class FindCaseCollisionsTest(unittest.TestCase):
    def test_distinct_paths_produce_no_collisions(self) -> None:
        self.assertEqual(
            cc.find_case_collisions(["src/app.py", "src/lib.py", "README.md"]),
            [],
        )

    def test_detects_case_only_collision(self) -> None:
        collisions = cc.find_case_collisions(["README.md", "readme.md"])
        self.assertEqual(
            collisions,
            [{"key": "readme.md", "paths": ["README.md", "readme.md"]}],
        )

    def test_detects_nested_case_collision(self) -> None:
        collisions = cc.find_case_collisions(
            ["docs/Guide.md", "docs/guide.md", "docs/other.md"]
        )
        self.assertEqual(len(collisions), 1)
        self.assertEqual(collisions[0]["paths"], ["docs/Guide.md", "docs/guide.md"])

    def test_order_is_deterministic_regardless_of_input(self) -> None:
        paths = ["B.md", "b.md", "A.md", "a.md"]
        expected = [
            {"key": "a.md", "paths": ["A.md", "a.md"]},
            {"key": "b.md", "paths": ["B.md", "b.md"]},
        ]
        self.assertEqual(cc.find_case_collisions(paths), expected)
        self.assertEqual(cc.find_case_collisions(list(reversed(paths))), expected)

    def test_unicode_case_folding_collision(self) -> None:
        collisions = cc.find_case_collisions(["Straße.txt", "STRASSE.txt"])
        self.assertEqual(len(collisions), 1)
        self.assertEqual(collisions[0]["paths"], ["STRASSE.txt", "Straße.txt"])

    def test_decomposed_and_composed_names_collide(self) -> None:
        composed = "caf\u00e9.md"
        decomposed = "cafe\u0301.md"
        collisions = cc.find_case_collisions([composed, decomposed])
        self.assertEqual(len(collisions), 1)
        self.assertEqual(collisions[0]["paths"], sorted([composed, decomposed]))

    def test_exact_duplicates_are_one_file(self) -> None:
        self.assertEqual(cc.find_case_collisions(["a.txt", "a.txt"]), [])

    def test_empty_input_passes(self) -> None:
        self.assertEqual(cc.find_case_collisions([]), [])
        report = cc.build_report([])
        self.assertEqual(report["status"], "pass")
        self.assertEqual(report["checked_paths"], 0)


class PathListTest(unittest.TestCase):
    def test_newline_separated(self) -> None:
        self.assertEqual(cc.parse_path_list(b"a\nb\n"), ["a", "b"])

    def test_nul_separated_wins(self) -> None:
        self.assertEqual(cc.parse_path_list(b"a\0b\0"), ["a", "b"])

    def test_oversized_path_list_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "paths.txt"
            path.write_bytes(b"0123456789")
            original = cc.MAX_INPUT_BYTES
            cc.MAX_INPUT_BYTES = 4
            try:
                with self.assertRaisesRegex(cc.CollisionCheckError, "exceeds"):
                    cc.read_paths_file(path)
            finally:
                cc.MAX_INPUT_BYTES = original


class GitCollectorTest(unittest.TestCase):
    def test_reads_tracked_paths_from_the_index(self) -> None:
        if shutil.which("git") is None:
            self.skipTest("git is not installed")
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            subprocess.run(["git", "-C", str(repo), "init", "-q"], check=True)
            (repo / "README.md").write_text("upper\n", encoding="utf-8")
            (repo / "readme.md").write_text("lower\n", encoding="utf-8")
            (repo / "unique.txt").write_text("only\n", encoding="utf-8")
            subprocess.run(["git", "-C", str(repo), "add", "-A"], check=True)

            paths = cc.collect_tracked_paths(repo)

            self.assertIn("README.md", paths)
            self.assertIn("readme.md", paths)
            self.assertEqual(len(cc.find_case_collisions(paths)), 1)

    def test_untracked_files_are_ignored(self) -> None:
        if shutil.which("git") is None:
            self.skipTest("git is not installed")
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            subprocess.run(["git", "-C", str(repo), "init", "-q"], check=True)
            (repo / "tracked.txt").write_text("tracked\n", encoding="utf-8")
            subprocess.run(["git", "-C", str(repo), "add", "tracked.txt"], check=True)
            (repo / "Untracked.md").write_text("a\n", encoding="utf-8")
            (repo / "untracked.md").write_text("b\n", encoding="utf-8")

            self.assertEqual(cc.collect_tracked_paths(repo), ["tracked.txt"])

    def test_git_failure_is_a_typed_error(self) -> None:
        def failing_runner(cmd, **kwargs):
            return subprocess.CompletedProcess(
                cmd, 128, stdout=b"", stderr=b"not a repo"
            )

        with self.assertRaisesRegex(cc.CollisionCheckError, "git ls-files failed"):
            cc.collect_tracked_paths(Path("/nonexistent"), runner=failing_runner)

    def test_missing_git_is_a_typed_error(self) -> None:
        def missing_runner(cmd, **kwargs):
            raise FileNotFoundError("git")

        with self.assertRaisesRegex(cc.CollisionCheckError, "git is not installed"):
            cc.collect_tracked_paths(Path("."), runner=missing_runner)


class CommandLineTest(unittest.TestCase):
    def _run(self, argv: list[str]) -> tuple[int, dict, str]:
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            code = cc.main(argv)
        return code, json.loads(out.getvalue()), err.getvalue()

    def test_exit_zero_when_paths_are_unique(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            paths = Path(tmp) / "paths.txt"
            paths.write_text("a.txt\nb.txt\n", encoding="utf-8")
            code, report, _ = self._run(["--paths-from", str(paths)])
        self.assertEqual(code, cc.EXIT_OK)
        self.assertEqual(report["status"], "pass")
        self.assertEqual(report["checked_paths"], 2)

    def test_exit_one_and_stderr_summary_on_collision(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            paths = Path(tmp) / "paths.txt"
            paths.write_text("README.md\nreadme.md\n", encoding="utf-8")
            code, report, err = self._run(["--paths-from", str(paths)])
        self.assertEqual(code, cc.EXIT_COLLISION)
        self.assertEqual(report["status"], "fail")
        self.assertIn("README.md", err)
        self.assertIn("readme.md", err)

    def test_report_is_written_to_output(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            paths = Path(tmp) / "paths.txt"
            paths.write_text("a.txt\na.txt\n", encoding="utf-8")
            output = Path(tmp) / "report.json"
            code, _, _ = self._run(
                ["--paths-from", str(paths), "--output", str(output)]
            )
            self.assertEqual(code, cc.EXIT_OK)
            saved = json.loads(output.read_text(encoding="utf-8"))
        self.assertEqual(saved["format"], cc.FORMAT)
        self.assertEqual(saved["schema_version"], 1)

    def test_unreadable_path_source_exits_two(self) -> None:
        with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
            code = cc.main(["--paths-from", "/nonexistent/paths.txt"])
        self.assertEqual(code, cc.EXIT_USAGE)


if __name__ == "__main__":
    unittest.main()
