"""
Endpoint tests for the C2PA hash-verification boundary.

Covers ``POST /api/c2pa/export`` and ``POST /api/c2pa/import``:

- both routes answer with the documented JSON envelope (the module-level c2pa
  symbols the routes depend on are imported, so neither route raises ``NameError``),
- an import without ``expected`` reports ``hashes_verified: false``,
- ``expected`` corroborates caller-submitted hashes against the binding embedded
  in the manifest,
- a submission that disagrees is rejected with a stable, privacy-safe 400,
- a manifest whose two embedded copies of the binding disagree is rejected.

``unittest.TestCase`` is used so ``python -m unittest discover`` also collects
these tests; the CI job runs both unittest discovery and pytest.
"""

from __future__ import annotations

import contextlib
import json
import os
import unittest

import app as app_module
from c2pa import export_c2pa_manifest

VALID_VIDEO_HASH = "aa" * 32
VALID_META_HASH = "bb" * 32
VALID_PROOF_ID = "cc" * 32
VALID_TIER = "silent"
VALID_NETWORK = "Test SDF Network ; September 2015"
VALID_CONTRACT = "CCKTQNMBLXZXMWVR2WG4HDDUI3QGJU5LV5NTLFPCB72UITWE5TEDK7BT"

EXPORT_PAYLOAD: dict[str, str] = {
    "video_hash": VALID_VIDEO_HASH,
    "metadata_hash": VALID_META_HASH,
    "proof_id": VALID_PROOF_ID,
    "tier": VALID_TIER,
    "network": VALID_NETWORK,
    "contract_id": VALID_CONTRACT,
}

ALL_EXPECTED: dict[str, str] = dict(EXPORT_PAYLOAD)


@contextlib.contextmanager
def _client():
    """Fresh Flask test client — no database or Noir worker required."""
    watched = ("NOIR_WORKER_ENABLED", "DATABASE_URL")
    saved = {key: os.environ.get(key) for key in watched}
    os.environ["NOIR_WORKER_ENABLED"] = "false"
    os.environ["DATABASE_URL"] = ""

    try:
        yield app_module.create_app().test_client()
    finally:
        for key, value in saved.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value


def _manifest() -> dict:
    """A freshly exported, internally consistent manifest."""
    return export_c2pa_manifest(**EXPORT_PAYLOAD).manifest


def _error_text(response) -> str:
    return json.dumps(response.get_json())


class C2paExportEndpointTest(unittest.TestCase):
    def test_export_returns_manifest_and_digest(self) -> None:
        with _client() as client:
            response = client.post("/api/c2pa/export", json=EXPORT_PAYLOAD)

        self.assertEqual(response.status_code, 200)
        body = response.get_json()
        self.assertTrue(body["ok"])
        self.assertEqual(body["trust_status"], "signature_not_checked")
        self.assertEqual(body["manifest"]["harpocrates_binding"]["video_hash"], VALID_VIDEO_HASH)
        self.assertEqual(body["manifest"]["harpocrates_binding"]["contract_id"], VALID_CONTRACT)
        self.assertRegex(body["digest"], r"^[0-9a-f]{64}$")
        self.assertIn("request_id", body)

    def test_export_manifest_is_importable(self) -> None:
        with _client() as client:
            exported = client.post("/api/c2pa/export", json=EXPORT_PAYLOAD).get_json()
            imported = client.post(
                "/api/c2pa/import",
                json={"manifest": exported["manifest"], "expected": ALL_EXPECTED},
            )

        self.assertEqual(imported.status_code, 200)
        self.assertTrue(imported.get_json()["hashes_verified"])

    def test_export_rejects_missing_required_field(self) -> None:
        payload = dict(EXPORT_PAYLOAD)
        del payload["proof_id"]
        with _client() as client:
            response = client.post("/api/c2pa/export", json=payload)

        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.get_json()["error"]["code"], "VALIDATION_ERROR")

    def test_export_rejects_malformed_hash(self) -> None:
        payload = dict(EXPORT_PAYLOAD, video_hash="zz" * 32)
        with _client() as client:
            response = client.post("/api/c2pa/export", json=payload)

        self.assertEqual(response.status_code, 400)
        self.assertIn("video_hash", response.get_json()["error"]["message"])


class C2paImportHashVerificationTest(unittest.TestCase):
    def test_import_without_expected_reports_unverified(self) -> None:
        with _client() as client:
            response = client.post("/api/c2pa/import", json={"manifest": _manifest()})

        self.assertEqual(response.status_code, 200)
        body = response.get_json()
        self.assertTrue(body["ok"])
        self.assertIs(body["hashes_verified"], False)
        self.assertEqual(body["hashes_compared"], [])
        self.assertEqual(body["binding"]["video_hash"], VALID_VIDEO_HASH)

    def test_import_accepts_raw_json_string_manifest(self) -> None:
        raw = json.dumps(_manifest(), separators=(",", ":"))
        with _client() as client:
            response = client.post("/api/c2pa/import", json={"manifest": raw})

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json()["binding"]["proof_id"], VALID_PROOF_ID)

    def test_matching_expected_verifies_all_compared_fields(self) -> None:
        with _client() as client:
            response = client.post(
                "/api/c2pa/import",
                json={"manifest": _manifest(), "expected": ALL_EXPECTED},
            )

        self.assertEqual(response.status_code, 200)
        body = response.get_json()
        self.assertIs(body["hashes_verified"], True)
        self.assertEqual(
            sorted(body["hashes_compared"]),
            sorted(["video_hash", "metadata_hash", "proof_id", "tier", "network", "contract_id"]),
        )

    def test_partial_expected_verifies_only_supplied_fields(self) -> None:
        with _client() as client:
            response = client.post(
                "/api/c2pa/import",
                json={
                    "manifest": _manifest(),
                    "expected": {"video_hash": VALID_VIDEO_HASH.upper()},
                },
            )

        self.assertEqual(response.status_code, 200)
        body = response.get_json()
        self.assertIs(body["hashes_verified"], True)
        self.assertEqual(body["hashes_compared"], ["video_hash"])

    def test_mismatched_submitted_hash_is_rejected_privacy_safely(self) -> None:
        submitted = "dd" * 32
        with _client() as client:
            response = client.post(
                "/api/c2pa/import",
                json={"manifest": _manifest(), "expected": {"video_hash": submitted}},
            )

        self.assertEqual(response.status_code, 400)
        error = response.get_json()["error"]
        self.assertEqual(error["code"], "VALIDATION_ERROR")
        self.assertEqual(error["field"], "video_hash")
        rendered = _error_text(response)
        self.assertNotIn(submitted, rendered)
        self.assertNotIn(VALID_VIDEO_HASH, rendered)

    def test_mismatched_text_field_is_rejected(self) -> None:
        with _client() as client:
            response = client.post(
                "/api/c2pa/import",
                json={
                    "manifest": _manifest(),
                    "expected": {"network": "Public Global Stellar Network ; September 2015"},
                },
            )

        self.assertEqual(response.status_code, 400)
        error = response.get_json()["error"]
        self.assertEqual(error["field"], "network")
        self.assertIn("network", error["message"])

    def test_first_mismatch_in_fixed_order_is_reported(self) -> None:
        with _client() as client:
            response = client.post(
                "/api/c2pa/import",
                json={
                    "manifest": _manifest(),
                    "expected": {"proof_id": "dd" * 32, "video_hash": "dd" * 32},
                },
            )

        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.get_json()["error"]["field"], "video_hash")

    def test_malformed_submitted_hash_is_rejected_without_echo(self) -> None:
        submitted = "zz" * 32
        with _client() as client:
            response = client.post(
                "/api/c2pa/import",
                json={"manifest": _manifest(), "expected": {"video_hash": submitted}},
            )

        self.assertEqual(response.status_code, 400)
        error = response.get_json()["error"]
        self.assertIn("video_hash", error["message"])
        self.assertNotIn(submitted, _error_text(response))

    def test_non_object_expected_is_rejected(self) -> None:
        with _client() as client:
            response = client.post(
                "/api/c2pa/import",
                json={"manifest": _manifest(), "expected": "video_hash"},
            )

        self.assertEqual(response.status_code, 400)
        self.assertIn("expected", response.get_json()["error"]["message"])

    def test_unknown_expected_keys_are_ignored(self) -> None:
        with _client() as client:
            response = client.post(
                "/api/c2pa/import",
                json={
                    "manifest": _manifest(),
                    "expected": {"video_hash": VALID_VIDEO_HASH, "comment": "ignored"},
                },
            )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json()["hashes_compared"], ["video_hash"])

    def test_manifest_with_disagreeing_embedded_copies_is_rejected(self) -> None:
        manifest = _manifest()
        manifest["assertions"][0]["data"]["video_hash"] = "dd" * 32
        with _client() as client:
            response = client.post("/api/c2pa/import", json={"manifest": manifest})

        self.assertEqual(response.status_code, 400)
        error = response.get_json()["error"]
        self.assertEqual(error["code"], "VALIDATION_ERROR")
        self.assertIn("embedded_binding_mismatch", error["message"])
        self.assertIn("video_hash", error["message"])

    def test_manifest_with_disagreeing_embedded_text_copies_is_rejected(self) -> None:
        manifest = _manifest()
        manifest["assertions"][0]["data"]["tier"] = "seal"
        with _client() as client:
            response = client.post("/api/c2pa/import", json={"manifest": manifest})

        self.assertEqual(response.status_code, 400)
        self.assertIn("embedded_binding_mismatch", response.get_json()["error"]["message"])

    def test_unknown_assertions_are_preserved(self) -> None:
        manifest = _manifest()
        manifest["assertions"].append({"label": "c2pa.actions", "data": {"actions": []}})
        with _client() as client:
            response = client.post("/api/c2pa/import", json={"manifest": manifest})

        self.assertEqual(response.status_code, 200)
        unknown = response.get_json()["unknown_assertions"]
        self.assertEqual(len(unknown), 1)
        self.assertEqual(unknown[0]["label"], "c2pa.actions")
        self.assertIs(unknown[0]["unsupported_semantics"], True)

    def test_missing_manifest_field_is_rejected(self) -> None:
        with _client() as client:
            response = client.post("/api/c2pa/import", json={"expected": ALL_EXPECTED})

        self.assertEqual(response.status_code, 400)
        self.assertIn("manifest", response.get_json()["error"]["message"])

    def test_malformed_manifest_is_rejected_with_reason_code_only(self) -> None:
        with _client() as client:
            response = client.post("/api/c2pa/import", json={"manifest": "{not json"})

        self.assertEqual(response.status_code, 400)
        error = response.get_json()["error"]
        self.assertEqual(error["code"], "VALIDATION_ERROR")
        self.assertIn("not_json", error["message"])

    def test_import_does_not_promote_trust_status(self) -> None:
        with _client() as client:
            response = client.post(
                "/api/c2pa/import",
                json={"manifest": _manifest(), "expected": ALL_EXPECTED},
            )

        body = response.get_json()
        self.assertEqual(body["trust_status"], "signature_not_checked")
        self.assertNotIn("verified", json.dumps(body["trust_status"]).lower())
