from __future__ import annotations

import copy
import json
import subprocess
import sys
import unittest
from pathlib import Path

import c2pa_export


ROOT = Path(c2pa_export.__file__).resolve().parents[1]
FIXTURES = ROOT / "devx" / "fixtures"
SAMPLE_MANIFEST = FIXTURES / "proof-manifest.sample.json"
GOLDEN_EXPORT = FIXTURES / "c2pa-export.sample.v1.json"


def valid_manifest() -> dict:
    return json.loads(SAMPLE_MANIFEST.read_text(encoding="utf-8"))


class ExportPositiveTest(unittest.TestCase):
    def test_exports_required_standard_and_namespaced_assertions(self) -> None:
        exported = c2pa_export.export_manifest(valid_manifest(), media_type="video/mp4")
        labels = [assertion["label"] for assertion in exported["assertions"]]
        self.assertIn("c2pa.actions", labels)
        self.assertIn("org.harpocrates.evidence-binding", labels)
        self.assertIn("org.harpocrates.verification", labels)

    def test_valid_evidence_asserts_digital_capture(self) -> None:
        exported = c2pa_export.export_manifest(valid_manifest(), verification="valid")
        action = exported["assertions"][0]["data"]["actions"][0]
        self.assertEqual(action["action"], "c2pa.created")
        self.assertEqual(action["digitalSourceType"], c2pa_export.DIGITAL_CAPTURE_SOURCE_TYPE)
        verification = self._by_label(exported, "org.harpocrates.verification")
        self.assertEqual(verification["data"]["authenticity"], "asserted")

    def test_pending_evidence_is_exportable_but_not_asserted(self) -> None:
        exported = c2pa_export.export_manifest(valid_manifest(), verification="pending")
        action = exported["assertions"][0]["data"]["actions"][0]
        self.assertNotIn("digitalSourceType", action)
        verification = self._by_label(exported, "org.harpocrates.verification")
        self.assertEqual(verification["data"]["status"], "pending")
        self.assertEqual(verification["data"]["authenticity"], "pending")

    def test_all_tiers_are_supported(self) -> None:
        for tier in ("silent", "source", "seal"):
            manifest = valid_manifest()
            manifest["tier"] = tier
            self.assertEqual(
                c2pa_export.export_manifest(manifest)["assertions"][2]["data"]["tier"], tier
            )

    def test_hex_fields_are_normalised_to_lowercase(self) -> None:
        manifest = valid_manifest()
        manifest["proofId"] = "A" * 64
        exported = c2pa_export.export_manifest(manifest)
        binding = self._by_label(exported, "org.harpocrates.evidence-binding")
        self.assertEqual(binding["data"]["proofId"], "a" * 64)

    def test_empty_video_hash_is_exported_as_null(self) -> None:
        manifest = valid_manifest()
        manifest["videoHash"] = ""
        exported = c2pa_export.export_manifest(manifest)
        binding = self._by_label(exported, "org.harpocrates.evidence-binding")
        self.assertIsNone(binding["data"]["videoHash"])

    def test_export_is_deterministic(self) -> None:
        manifest = valid_manifest()
        first = c2pa_export.serialize_export(c2pa_export.export_manifest(manifest))
        second = c2pa_export.serialize_export(c2pa_export.export_manifest(manifest))
        self.assertEqual(first, second)

    def test_export_matches_committed_interoperability_fixture(self) -> None:
        manifest = c2pa_export.load_proof_manifest(SAMPLE_MANIFEST)
        exported = c2pa_export.export_manifest(
            manifest, title="Sample evidence", media_type="video/mp4"
        )
        expected = GOLDEN_EXPORT.read_text(encoding="utf-8").strip()
        self.assertEqual(c2pa_export.serialize_export(exported), expected)

    def test_instance_id_is_deterministic_and_prefixed(self) -> None:
        exported = c2pa_export.export_manifest(valid_manifest())
        self.assertTrue(exported["instance_id"].startswith("xmp:iid:"))
        self.assertEqual(exported["instance_id"], c2pa_export.export_manifest(valid_manifest())["instance_id"])

    def test_export_is_never_signed(self) -> None:
        exported = c2pa_export.export_manifest(valid_manifest())
        self.assertIsNone(exported["signature"])
        self.assertEqual(exported["signing"]["status"], "unsigned")

    @staticmethod
    def _by_label(exported: dict, label: str) -> dict:
        for assertion in exported["assertions"]:
            if assertion["label"] == label:
                return assertion
        raise AssertionError(f"missing assertion {label}")


class ExportNegativeTest(unittest.TestCase):
    def assertCode(self, code: str, *args, **kwargs) -> None:
        with self.assertRaises(c2pa_export.C2PAExportError) as ctx:
            c2pa_export.export_manifest(*args, **kwargs)
        self.assertEqual(ctx.exception.code, code)

    def test_rejects_non_object(self) -> None:
        self.assertCode("malformed", ["not", "an", "object"])

    def test_rejects_missing_required_field(self) -> None:
        manifest = valid_manifest()
        del manifest["proofId"]
        self.assertCode("malformed", manifest)

    def test_rejects_unsupported_protocol(self) -> None:
        manifest = valid_manifest()
        manifest["protocol"] = "other"
        self.assertCode("unsupported", manifest)

    def test_rejects_unsupported_version(self) -> None:
        manifest = valid_manifest()
        manifest["version"] = 2
        self.assertCode("unsupported", manifest)

    def test_rejects_unsupported_tier(self) -> None:
        manifest = valid_manifest()
        manifest["tier"] = "platinum"
        self.assertCode("unsupported", manifest)

    def test_rejects_malformed_hex(self) -> None:
        manifest = valid_manifest()
        manifest["sourceHash"] = "not-hex"
        self.assertCode("malformed", manifest)

    def test_rejects_malformed_timestamp(self) -> None:
        manifest = valid_manifest()
        manifest["timestamp"] = "yesterday"
        self.assertCode("malformed", manifest)

    def test_rejects_unsupported_media_type(self) -> None:
        self.assertCode("unsupported", valid_manifest(), media_type="text/plain")

    def test_rejects_expired_evidence(self) -> None:
        self.assertCode("expired", valid_manifest(), verification="expired")

    def test_rejects_revoked_evidence(self) -> None:
        self.assertCode("revoked", valid_manifest(), verification="revoked")

    def test_maps_chain_failures_to_dependency_failure(self) -> None:
        for status in (
            "not_found",
            "failed",
            "error",
            "network_mismatch",
            "contract_mismatch",
        ):
            with self.subTest(status=status):
                self.assertCode("dependency_failure", valid_manifest(), verification=status)

    def test_rejects_unknown_verification_status(self) -> None:
        self.assertCode("unsupported", valid_manifest(), verification="maybe")

    def test_rejects_sensitive_fields_at_any_depth(self) -> None:
        manifest = valid_manifest()
        manifest["privateKey"] = "0" * 64
        self.assertCode("unsupported", manifest)

        nested = valid_manifest()
        nested["extra"] = {"capture": {"nullifier": "0" * 64}}
        self.assertCode("unsupported", nested)

    def test_rejects_non_string_title(self) -> None:
        self.assertCode("malformed", valid_manifest(), title=123)

    def test_rejects_excessive_nesting(self) -> None:
        manifest = valid_manifest()
        node: dict = {}
        cursor = node
        for _ in range(40):
            cursor["child"] = {}
            cursor = cursor["child"]
        manifest["extra"] = node
        self.assertCode("malformed", manifest)


class ExportBoundaryTest(unittest.TestCase):
    def test_oversized_input_is_rejected(self) -> None:
        manifest = valid_manifest()
        manifest["pad"] = "x" * (c2pa_export.MAX_INPUT_BYTES + 1)
        with self.assertRaises(c2pa_export.C2PAExportError) as ctx:
            c2pa_export.export_manifest(manifest)
        self.assertEqual(ctx.exception.code, "oversized")

    def test_input_just_under_limit_is_accepted(self) -> None:
        manifest = valid_manifest()
        base = len(c2pa_export.canonical_json_bytes(manifest))
        filler = "x" * (c2pa_export.MAX_INPUT_BYTES - base - 64)
        manifest["pad"] = filler
        self.assertLessEqual(
            len(c2pa_export.canonical_json_bytes(manifest)),
            c2pa_export.MAX_INPUT_BYTES,
        )
        c2pa_export.export_manifest(manifest)

    def test_title_at_limit_is_accepted_and_over_limit_is_oversized(self) -> None:
        title = "t" * c2pa_export.MAX_TITLE_LENGTH
        c2pa_export.export_manifest(valid_manifest(), title=title)
        with self.assertRaises(c2pa_export.C2PAExportError) as ctx:
            c2pa_export.export_manifest(valid_manifest(), title=title + "t")
        self.assertEqual(ctx.exception.code, "oversized")

    def test_unknown_looking_media_type_is_defaulted_when_absent(self) -> None:
        exported = c2pa_export.export_manifest(valid_manifest())
        self.assertEqual(exported["format"], "application/octet-stream")


class VerifyExportTest(unittest.TestCase):
    def test_verifies_a_fresh_export(self) -> None:
        exported = c2pa_export.export_manifest(valid_manifest())
        c2pa_export.verify_export(exported)

    def test_detects_assertion_tampering(self) -> None:
        exported = c2pa_export.export_manifest(valid_manifest())
        exported["assertions"][0]["data"]["actions"][0]["when"] = "1999-01-01T00:00:00.000Z"
        with self.assertRaises(c2pa_export.C2PAExportError) as ctx:
            c2pa_export.verify_export(exported)
        self.assertEqual(ctx.exception.code, "malformed")

    def test_rejects_wrong_profile(self) -> None:
        exported = c2pa_export.export_manifest(valid_manifest())
        exported["profile"] = "other/v1"
        with self.assertRaises(c2pa_export.C2PAExportError) as ctx:
            c2pa_export.verify_export(exported)
        self.assertEqual(ctx.exception.code, "unsupported")

    def test_rejects_missing_assertion(self) -> None:
        exported = c2pa_export.export_manifest(valid_manifest())
        exported["assertions"] = [
            a for a in exported["assertions"] if a["label"] != "c2pa.actions"
        ]
        with self.assertRaises(c2pa_export.C2PAExportError) as ctx:
            c2pa_export.verify_export(exported)
        self.assertEqual(ctx.exception.code, "malformed")


class PrivacyAndRegressionTest(unittest.TestCase):
    FORBIDDEN = (
        "privateKey",
        "seed",
        "witness",
        "nullifier",
        "credential",
        "apiKey",
        "deviceKey",
        "mnemonic",
        "password",
    )

    def test_export_never_mutates_the_input(self) -> None:
        manifest = valid_manifest()
        before = copy.deepcopy(manifest)
        c2pa_export.export_manifest(manifest)
        self.assertEqual(manifest, before)

    def test_serialised_export_contains_no_secret_material(self) -> None:
        rendered = c2pa_export.serialize_export(
            c2pa_export.export_manifest(valid_manifest(), title="Public title")
        ).lower()
        for token in self.FORBIDDEN:
            self.assertNotIn(token.lower(), rendered)

    def test_error_messages_do_not_echo_input_values(self) -> None:
        secret = "SUPER-SECRET-VALUE"
        manifest = valid_manifest()
        manifest["privateKey"] = secret
        with self.assertRaises(c2pa_export.C2PAExportError) as ctx:
            c2pa_export.export_manifest(manifest)
        self.assertNotIn(secret, str(ctx.exception))

    def test_release_guard_import_remains_unaffected(self) -> None:
        import release_guard

        self.assertTrue(hasattr(release_guard, "verify"))


class CliTest(unittest.TestCase):
    def _run(self, *args: str) -> subprocess.CompletedProcess:
        return subprocess.run(
            [sys.executable, str(ROOT / "devx" / "c2pa_export.py"), *args],
            capture_output=True,
            text=True,
            check=False,
        )

    def test_cli_exports_deterministic_fixture(self) -> None:
        result = self._run(
            "--manifest",
            str(SAMPLE_MANIFEST),
            "--result",
            "valid",
            "--title",
            "Sample evidence",
            "--media-type",
            "video/mp4",
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), GOLDEN_EXPORT.read_text(encoding="utf-8").strip())

    def test_cli_fails_closed_on_revoked_evidence(self) -> None:
        result = self._run("--manifest", str(SAMPLE_MANIFEST), "--result", "revoked")
        self.assertEqual(result.returncode, 1)
        self.assertIn("revoked", result.stderr)

    def test_cli_verify_round_trip(self) -> None:
        result = self._run("--manifest", str(GOLDEN_EXPORT), "--verify")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("verified", result.stdout)


if __name__ == "__main__":
    unittest.main()
