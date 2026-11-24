"""Tests for the offline release review bundle."""

from __future__ import annotations

import copy
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CLI = Path(__file__).resolve().parent / "release_review_bundle.py"
MANIFEST = ROOT / "release" / "compatibility-manifest.json"


class ReleaseReviewBundleTest(unittest.TestCase):
    def test_bundle_generates_and_validates(self) -> None:
        proc = subprocess.run(
            [sys.executable, str(CLI)],
            cwd=str(ROOT),
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        bundle = json.loads(proc.stdout)
        self.assertEqual(bundle["format"], "harpocrates.release-review-bundle")
        self.assertEqual(bundle["schema_version"], 1)
        self.assertEqual(bundle["release_id"], "harpocrates-1.0.0")
        self.assertIn(bundle["status"], {"pass", "fail"})
        self.assertFalse(bundle["privacy"]["includes_private_material"])
        self.assertIn("compatibility", bundle)
        self.assertIn("artifact_verification", bundle)
        self.assertIn("api_schema", bundle)
        self.assertIn("missing_evidence", bundle)
        self.assertIn("all_source_digests", bundle)

    def test_bundle_has_explicit_missing_evidence(self) -> None:
        proc = subprocess.run(
            [sys.executable, str(CLI)],
            cwd=str(ROOT),
            capture_output=True,
            text=True,
            check=False,
        )
        bundle = json.loads(proc.stdout)
        self.assertIsInstance(bundle["missing_evidence"], list)
        self.assertGreater(len(bundle["missing_evidence"]), 0)
        for item in bundle["missing_evidence"]:
            self.assertIn("check", item)
            self.assertIn("reason", item)
            self.assertIn("detail", item)

    def test_bundle_never_treats_skipped_as_pass(self) -> None:
        """Verify that a skipped/missing check never results in overall pass."""
        proc = subprocess.run(
            [sys.executable, str(CLI)],
            cwd=str(ROOT),
            capture_output=True,
            text=True,
            check=False,
        )
        bundle = json.loads(proc.stdout)
        if bundle["missing_evidence"]:
            self.assertEqual(bundle["status"], "fail")

    def test_stable_write_and_verify_roundtrip(self) -> None:
        proc = subprocess.run(
            [sys.executable, str(CLI), "--stable"],
            cwd=str(ROOT),
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        bundle = json.loads(proc.stdout)
        self.assertEqual(bundle["generated_at"], "committed")

        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "bundle.json"
            proc = subprocess.run(
                [sys.executable, str(CLI), "--stable", "--write", "--output", str(path)],
                cwd=str(ROOT),
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(proc.returncode, 0, proc.stderr)
            self.assertTrue(path.is_file())
            loaded = json.loads(path.read_text(encoding="utf-8"))
            self.assertEqual(json.dumps(loaded, sort_keys=True), json.dumps(bundle, sort_keys=True))

    def test_check_flag_fails_on_missing_evidence(self) -> None:
        proc = subprocess.run(
            [sys.executable, str(CLI), "--check", "--stable"],
            cwd=str(ROOT),
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(proc.returncode, 1)
        self.assertIn("release review bundle check failed", proc.stderr)

    def test_verify_existing_detects_stale(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "bundle.json"
            proc = subprocess.run(
                [sys.executable, str(CLI), "--stable", "--write", "--output", str(path)],
                cwd=str(ROOT),
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(proc.returncode, 0)

            stale_bundle = json.loads(path.read_text(encoding="utf-8"))
            stale_bundle["release_id"] = "harpocrates-9.9.9"
            path.write_text(json.dumps(stale_bundle, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8")

            proc = subprocess.run(
                [sys.executable, str(CLI), "--stable", "--verify-existing", "--output", str(path)],
                cwd=str(ROOT),
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(proc.returncode, 1)
            self.assertIn("stale", proc.stderr)

    def test_bundle_includes_all_source_digests(self) -> None:
        proc = subprocess.run(
            [sys.executable, str(CLI)],
            cwd=str(ROOT),
            capture_output=True,
            text=True,
            check=False,
        )
        bundle = json.loads(proc.stdout)
        digests = bundle["all_source_digests"]
        self.assertIsInstance(digests, dict)
        self.assertGreater(len(digests), 0)
        for path, digest in digests.items():
            self.assertEqual(len(digest), 64)
            self.assertTrue(all(c in "0123456789abcdef" for c in digest))

    def test_compatibility_section_structure(self) -> None:
        proc = subprocess.run(
            [sys.executable, str(CLI)],
            cwd=str(ROOT),
            capture_output=True,
            text=True,
            check=False,
        )
        bundle = json.loads(proc.stdout)
        compat = bundle["compatibility"]
        self.assertIn("report_status", compat)
        self.assertIn("layers", compat)
        self.assertIn("cross_layer", compat)
        self.assertIn("source_digests", compat)
        self.assertEqual(len(compat["layers"]), 5)

    def test_artifact_verification_section_structure(self) -> None:
        proc = subprocess.run(
            [sys.executable, str(CLI)],
            cwd=str(ROOT),
            capture_output=True,
            text=True,
            check=False,
        )
        bundle = json.loads(proc.stdout)
        av = bundle["artifact_verification"]
        self.assertIn("status", av)
        self.assertIn("message", av)
        self.assertIn("artifacts_checked", av)
        self.assertIn("artifact_digests", av)

    def test_api_schema_section_structure(self) -> None:
        proc = subprocess.run(
            [sys.executable, str(CLI)],
            cwd=str(ROOT),
            capture_output=True,
            text=True,
            check=False,
        )
        bundle = json.loads(proc.stdout)
        schema = bundle["api_schema"]
        self.assertIn("status", schema)
        self.assertIn("message", schema)
        self.assertIn("routes_count", schema)
        self.assertIn("schemas_loaded", schema)
        self.assertIn("source_digests", schema)

    def test_missing_manifest_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            missing = Path(tmp) / "missing.json"
            proc = subprocess.run(
                [sys.executable, str(CLI), "--manifest", str(missing)],
                cwd=str(ROOT),
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(proc.returncode, 1)
            self.assertIn("manifest not found", proc.stderr)


if __name__ == "__main__":
    unittest.main()