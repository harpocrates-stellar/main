"""Focused tests for devx/proof_release_evidence.py.

All inputs are synthetic JSON in temporary directories. No command is
executed, no credential is read, and no network or live fund movement occurs.
The tests pin the central honesty property: an unexecuted proving check is
``missing_evidence``, never ``pass``.
"""

from __future__ import annotations

import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path
from typing import Any

try:
    from devx import proof_release_evidence as evidence
except ImportError:  # pragma: no cover - direct `pytest devx/test_...py` invocation
    import proof_release_evidence as evidence  # type: ignore[no-redef]


DIGEST_A = "a" * 64
DIGEST_B = "b" * 64
DIGEST_C = "c" * 64


class ProofReleaseEvidenceTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        self.out = self.root / "bundle.json"

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def _write_json(self, relative: str, payload: dict[str, Any]) -> Path:
        path = self.root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(payload, sort_keys=True) + "\n", encoding="utf-8")
        return path

    def _lock(self) -> dict[str, Any]:
        return {
            "format": "harpocrates.zk-toolchain-lock",
            "version": 1,
            "toolchain": {
                "nargo": {"version": "1.0.0-beta.9"},
                "barretenberg": {"version": "0.87.0"},
                "proving_scheme": "ultra_honk",
                "oracle_hash": "keccak",
            },
        }

    def _write_inputs(self) -> None:
        self._write_json("zk/toolchain.lock.json", self._lock())
        self._write_json(
            "zk/artifacts.manifest.json",
            {
                "format": evidence.am.MANIFEST_FORMAT,
                "version": 1,
                "artifacts": [
                    {
                        "path": "zk/noir/silent_witness/target/vk",
                        "kind": "binary",
                        "role": "verification_key",
                        "raw_bytes": 1764,
                        "raw_sha256": DIGEST_A,
                        "normalized_bytes": 1764,
                        "normalized_sha256": DIGEST_A,
                    }
                ],
            },
        )
        self._write_json(
            "zk/browser.artifacts.manifest.json",
            {
                "format": evidence.am.BROWSER_MANIFEST_FORMAT,
                "version": 1,
                "artifacts": [
                    {
                        "path": "frontend/public/noir/silent_witness.json",
                        "kind": "json",
                        "role": "published_acir",
                        "raw_sha256": DIGEST_B,
                        "normalized_sha256": DIGEST_C,
                    }
                ],
            },
        )
        self._write_json(
            "zk/circuit.provenance.json",
            {
                "format": evidence.am.PROVENANCE_FORMAT,
                "version": 1,
                "provenance": {"zk/noir/silent_witness/src/main.nr": DIGEST_C},
            },
        )
        self._write_json(
            "zk/release/retention-manifest.json",
            {
                "schema": "hpx-artifact-retention/1",
                "files": [
                    {
                        "path": "src0/silent_witness.proof",
                        "sha256": DIGEST_B,
                        "size": 64,
                    }
                ],
            },
        )

    def _record(self, checks: list[dict[str, Any]]) -> Path:
        return self._write_json(
            "zk/release/validation-record.json",
            {
                "format": evidence.RECORD_FORMAT,
                "version": evidence.RECORD_VERSION,
                "checks": checks,
            },
        )

    def _run(self, *args: str) -> tuple[int, str, str]:
        stdout, stderr = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            code = evidence.main([*args, "--root", str(self.root)])
        return code, stdout.getvalue(), stderr.getvalue()

    def _bundle(self) -> dict[str, Any]:
        return json.loads(self.out.read_text(encoding="utf-8"))

    def test_unexecuted_proving_checks_are_missing_evidence_not_passes(self) -> None:
        self._write_inputs()
        # Simulate a checkout with no published build manifest or retained CI
        # proof artifacts; only the committed browser/provenance digests exist.
        (self.root / "zk" / "artifacts.manifest.json").unlink()
        (self.root / "zk" / "release" / "retention-manifest.json").unlink()
        code, _, stderr = self._run("--out", str(self.out))
        self.assertEqual(code, 0)
        self.assertIn("release_ready=false", stderr)

        bundle = self._bundle()
        outcomes = {item["id"]: item for item in bundle["validation_outcomes"]}
        for check_id in evidence.PROOF_CHECK_IDS:
            self.assertEqual(outcomes[check_id]["status"], evidence.MISSING)
        self.assertEqual(
            outcomes["toolchain.nargo_version"]["status"], evidence.MISSING
        )
        self.assertEqual(
            outcomes["digests.artifact_manifest"]["status"], evidence.MISSING
        )
        self.assertEqual(
            outcomes["digests.retention_manifest"]["status"], evidence.MISSING
        )
        self.assertFalse(bundle["summary"]["release_ready"])
        self.assertGreater(bundle["summary"][evidence.MISSING], 0)
        self.assertFalse(
            any(
                item["status"] == evidence.PASS and item["id"].startswith("proof.")
                for item in bundle["validation_outcomes"]
            )
        )

        self.assertEqual(self._run("--out", str(self.out), "--require-complete")[0], 1)

    def test_collects_versions_digests_and_executed_outcomes(self) -> None:
        self._write_inputs()
        record = self._record(
            [
                {
                    "id": "toolchain.nargo_version",
                    "status": "pass",
                    "observed": "nargo 1.0.0-beta.9",
                },
                {
                    "id": "toolchain.barretenberg_version",
                    "status": "pass",
                    "observed": "0.87.0",
                },
                {
                    "id": "proof.generate",
                    "status": "pass",
                    "evidence": "synthetic-prove",
                },
                {
                    "id": "proof.verify",
                    "status": "pass",
                    "evidence": "synthetic-verify",
                },
            ]
        )
        code, _, _ = self._run(
            "--out",
            str(self.out),
            "--validation-record",
            str(record),
            "--require-complete",
        )
        self.assertEqual(code, 0)

        bundle = self._bundle()
        self.assertTrue(bundle["summary"]["release_ready"])
        self.assertEqual(bundle["summary"][evidence.MISSING], 0)
        self.assertEqual(bundle["summary"][evidence.FAIL], 0)
        self.assertEqual(
            bundle["tool_versions"]["nargo"]["observed"], "nargo 1.0.0-beta.9"
        )
        self.assertEqual(
            bundle["tool_versions"]["barretenberg"]["status"], evidence.PASS
        )
        sources = {item["source"] for item in bundle["digests"]}
        self.assertEqual(
            sources,
            {
                "artifact_manifest",
                "browser_manifest",
                "circuit_provenance",
                "retention_manifest",
            },
        )
        self.assertTrue(
            any(
                item["path"] == "retained/src0/silent_witness.proof"
                for item in bundle["digests"]
            )
        )
        statuses = {
            item["id"]: item["status"] for item in bundle["validation_outcomes"]
        }
        self.assertEqual(statuses["proof.generate"], evidence.PASS)
        self.assertEqual(statuses["proof.verify"], evidence.PASS)

    def test_skipped_unlabelled_and_failed_checks_never_become_passes(self) -> None:
        self._write_inputs()
        record = self._record(
            [
                {"id": "proof.generate", "status": "skipped"},
                {"id": "proof.verify", "status": "pass"},
                {
                    "id": "toolchain.nargo_version",
                    "status": "pass",
                    "observed": "0.0.0",
                },
                {"id": "unrelated.check", "status": "unknown"},
            ]
        )
        code, _, _ = self._run(
            "--out", str(self.out), "--validation-record", str(record)
        )
        self.assertEqual(code, 1)

        bundle = self._bundle()
        outcomes = {item["id"]: item for item in bundle["validation_outcomes"]}
        self.assertEqual(outcomes["proof.generate"]["status"], evidence.MISSING)
        self.assertEqual(outcomes["proof.verify"]["status"], evidence.MISSING)
        self.assertEqual(outcomes["toolchain.nargo_version"]["status"], evidence.FAIL)
        self.assertNotIn("unrelated.check", outcomes)
        self.assertFalse(bundle["summary"]["release_ready"])
        self.assertEqual(bundle["summary"][evidence.FAIL], 1)

    def test_cli_tool_version_cannot_override_an_unexecuted_record(self) -> None:
        self._write_inputs()
        record = self._record([{"id": "toolchain.nargo_version", "status": "not_run"}])
        code, _, _ = self._run(
            "--out",
            str(self.out),
            "--validation-record",
            str(record),
            "--tool-version",
            "nargo=1.0.0-beta.9",
            "--tool-version",
            "barretenberg=0.87.0",
        )
        self.assertEqual(code, 0)
        bundle = self._bundle()
        self.assertEqual(bundle["tool_versions"]["nargo"]["status"], evidence.MISSING)
        self.assertEqual(
            bundle["tool_versions"]["barretenberg"]["status"], evidence.PASS
        )

    def test_sensitive_validation_record_fails_closed(self) -> None:
        self._write_inputs()
        record = self._write_json(
            "zk/release/validation-record.json",
            {
                "format": evidence.RECORD_FORMAT,
                "version": evidence.RECORD_VERSION,
                "checks": [
                    {
                        "id": "proof.generate",
                        "status": "pass",
                        "secret": "synthetic-value",
                    }
                ],
            },
        )
        code, _, stderr = self._run(
            "--out", str(self.out), "--validation-record", str(record)
        )
        self.assertEqual(code, 2)
        self.assertIn("sensitive", stderr)
        self.assertFalse(self.out.exists())

    def test_wrong_digest_document_format_is_a_fatal_input_error(self) -> None:
        self._write_inputs()
        self._write_json(
            "zk/browser.artifacts.manifest.json",
            {"format": "wrong.format", "version": 1, "artifacts": []},
        )
        code, _, stderr = self._run("--out", str(self.out))
        self.assertEqual(code, 2)
        self.assertIn("unexpected format", stderr)
        self.assertFalse(self.out.exists())

    def test_absolute_digest_path_is_rejected(self) -> None:
        self._write_inputs()
        bad = self._write_json(
            "zk/absolute.json",
            {
                "format": evidence.am.MANIFEST_FORMAT,
                "version": 1,
                "artifacts": [
                    {"path": "/etc/passwd", "kind": "binary", "raw_sha256": DIGEST_A}
                ],
            },
        )
        code, _, stderr = self._run(
            "--out", str(self.out), "--artifact-manifest", str(bad)
        )
        self.assertEqual(code, 2)
        self.assertIn("inside the checkout", stderr)
        self.assertFalse(self.out.exists())

    def test_bundle_is_deterministic(self) -> None:
        self._write_inputs()
        first = self.root / "first.json"
        second = self.root / "second.json"
        self.assertEqual(self._run("--out", str(first))[0], 0)
        self.assertEqual(self._run("--out", str(second))[0], 0)
        self.assertEqual(first.read_bytes(), second.read_bytes())

    def test_output_cannot_overwrite_an_input(self) -> None:
        self._write_inputs()
        lock = self.root / "zk" / "toolchain.lock.json"
        code, _, stderr = self._run("--out", str(lock))
        self.assertEqual(code, 2)
        self.assertIn("must not overwrite", stderr)


if __name__ == "__main__":
    unittest.main()
