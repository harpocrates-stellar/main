"""Focused tests for offline failed upload session integrity reports (issue #1041)."""

from __future__ import annotations

import base64
import hashlib
import io
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent))

import app as app_module  # noqa: E402
from admission import AdmissionController, require_capacity  # noqa: E402
from flask import Flask, jsonify  # noqa: E402
from streaming_upload import (  # noqa: E402
    DIGEST_STATUS_EMPTY,
    DIGEST_STATUS_MATCHED,
    DIGEST_STATUS_MISMATCH,
    DIGEST_STATUS_UNVERIFIED,
    FAILED_UPLOAD_INTEGRITY_SCHEMA,
    build_failed_session_integrity_report,
    init_upload_session_metadata,
    record_failed_upload_session,
    resolve_session_dir,
)

_VALID_METADATA = {
    "protocol": "harpocrates",
    "version": 1,
    "tier": "silent",
    "sourceHash": "11" * 32,
    "proofId": "22" * 32,
    "timestamp": "2026-06-18T00:00:00.000Z",
    "fileName": "private-confidential-witness.mp4",
}


class FailedUploadSessionIntegrityReportTest(unittest.TestCase):
    def test_offline_report_records_byte_counts_and_digest_statuses_without_media_or_filenames(self) -> None:
        media_sentinel = b"SYNTHETIC_MEDIA_PAYLOAD_DO_NOT_INCLUDE_9012"
        filename_sentinel = "private-confidential-witness.mp4"
        full_payload = media_sentinel + b"_TAIL_BYTES"
        full_sha = hashlib.sha256(full_payload).hexdigest()

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)

            # 1. Truncated/mismatch session
            mismatch_dir = resolve_session_dir("sess-mismatch", session_root=root)
            init_upload_session_metadata(
                mismatch_dir,
                session_id="sess-mismatch",
                expected_bytes=len(full_payload),
                expected_sha256=full_sha,
            )
            (mismatch_dir / "chunk-0").write_bytes(media_sentinel)
            record_failed_upload_session(
                mismatch_dir,
                session_id="sess-mismatch",
                failure_reason="digest_mismatch",
            )

            # 2. Matched digest session that failed later (e.g. quarantine rejection)
            matched_dir = resolve_session_dir("sess-matched", session_root=root)
            init_upload_session_metadata(
                matched_dir,
                session_id="sess-matched",
                expected_bytes=len(full_payload),
                expected_sha256=full_sha,
            )
            (matched_dir / "chunk-0").write_bytes(media_sentinel)
            (matched_dir / "chunk-1").write_bytes(b"_TAIL_BYTES")
            record_failed_upload_session(
                matched_dir,
                session_id="sess-matched",
                failure_reason="quarantine_rejected",
            )

            # 3. Unverified session (no expected digest declared)
            unverified_dir = resolve_session_dir("sess-unverified", session_root=root)
            init_upload_session_metadata(unverified_dir, session_id="sess-unverified")
            (unverified_dir / "chunk-0").write_bytes(b"ABCD")
            record_failed_upload_session(
                unverified_dir,
                session_id="sess-unverified",
                failure_reason="chunk_limit_exceeded",
            )

            # 4. Empty session commit failure
            empty_dir = resolve_session_dir("sess-empty", session_root=root)
            init_upload_session_metadata(
                empty_dir, session_id="sess-empty", expected_bytes=64
            )
            record_failed_upload_session(
                empty_dir,
                session_id="sess-empty",
                failure_reason="empty_commit",
            )

            report = build_failed_session_integrity_report(root)
            self.assertEqual(report["schema"], FAILED_UPLOAD_INTEGRITY_SCHEMA)
            self.assertEqual(report["total_failed_sessions"], 4)
            self.assertEqual(
                report["total_expected_bytes"],
                len(full_payload) * 2 + 64,
            )
            self.assertEqual(
                report["total_observed_bytes"],
                len(media_sentinel) + len(full_payload) + 4,
            )
            self.assertEqual(
                report["by_digest_status"],
                {
                    DIGEST_STATUS_MATCHED: 1,
                    DIGEST_STATUS_MISMATCH: 1,
                    DIGEST_STATUS_UNVERIFIED: 1,
                    DIGEST_STATUS_EMPTY: 1,
                },
            )

            by_id = {entry["session_id"]: entry for entry in report["sessions"]}
            self.assertEqual(by_id["sess-mismatch"]["expected_bytes"], len(full_payload))
            self.assertEqual(by_id["sess-mismatch"]["observed_bytes"], len(media_sentinel))
            self.assertEqual(
                by_id["sess-mismatch"]["byte_delta"],
                len(media_sentinel) - len(full_payload),
            )
            self.assertEqual(by_id["sess-mismatch"]["digest_status"], DIGEST_STATUS_MISMATCH)
            self.assertEqual(by_id["sess-matched"]["byte_delta"], 0)
            self.assertEqual(by_id["sess-matched"]["chunk_count"], 2)
            self.assertEqual(by_id["sess-matched"]["digest_status"], DIGEST_STATUS_MATCHED)
            self.assertEqual(by_id["sess-unverified"]["digest_status"], DIGEST_STATUS_UNVERIFIED)
            self.assertEqual(by_id["sess-empty"]["digest_status"], DIGEST_STATUS_EMPTY)

            serialized = json.dumps(report)
            self.assertNotIn(media_sentinel.decode("ascii"), serialized)
            self.assertNotIn(media_sentinel.hex(), serialized)
            self.assertNotIn(base64.b64encode(media_sentinel).decode("ascii"), serialized)
            self.assertNotIn(filename_sentinel, serialized)
            self.assertNotIn(str(root), serialized)

    def test_http_session_failures_and_admission_rejection_populate_offline_report(self) -> None:
        media_bytes = b"SYNTHETIC_NON_VIDEO_BYTES_FOR_QUARANTINE_TEST"
        expected_sha = hashlib.sha256(media_bytes + b"_MISSING").hexdigest()

        with tempfile.TemporaryDirectory() as tmp:
            env = {
                "APP_ENV": "testing",
                "DATABASE_URL": "",
                "NOIR_WORKER_ENABLED": "false",
                "RATELIMIT_ENABLED": "false",
                "UPLOAD_TEMP_DIR": tmp,
            }
            with patch.dict(os.environ, env, clear=False):
                flask_app = app_module.create_app()
                client = flask_app.test_client()

                created = client.post(
                    "/api/stego/upload-session",
                    json={
                        "expectedBytes": len(media_bytes) + 8,
                        "expectedSha256": expected_sha,
                    },
                )
                self.assertEqual(created.status_code, 200)
                session_id = created.get_json()["sessionId"]

                put_resp = client.put(
                    f"/api/stego/upload-session/{session_id}/chunk/0",
                    data={"chunk": (io.BytesIO(media_bytes), "secret-source-name.mov")},
                    content_type="multipart/form-data",
                )
                self.assertEqual(put_resp.status_code, 200)

                commit_resp = client.post(
                    f"/api/stego/upload-session/{session_id}/commit",
                    data={"metadata": json.dumps(_VALID_METADATA)},
                    content_type="multipart/form-data",
                )
                self.assertEqual(commit_resp.status_code, 400)

                http_report = client.get("/api/stego/upload-sessions/integrity-report")
                self.assertEqual(http_report.status_code, 200)
                report = http_report.get_json()
                self.assertEqual(report["total_failed_sessions"], 1)
                entry = report["sessions"][0]
                self.assertEqual(entry["session_id"], session_id)
                self.assertEqual(entry["expected_bytes"], len(media_bytes) + 8)
                self.assertEqual(entry["observed_bytes"], len(media_bytes))
                self.assertEqual(entry["digest_status"], DIGEST_STATUS_MISMATCH)
                raw_text = http_report.get_data(as_text=True)
                self.assertNotIn("SYNTHETIC_NON_VIDEO_BYTES_FOR_QUARANTINE_TEST", raw_text)
                self.assertNotIn("secret-source-name.mov", raw_text)
                self.assertNotIn("private-confidential-witness.mp4", raw_text)
                self.assertNotIn(tmp, raw_text)

                # Admission rejection on session commit also records offline integrity state
                adm_dir = resolve_session_dir("sess-adm-429", session_root=tmp)
                init_upload_session_metadata(adm_dir, session_id="sess-adm-429", expected_bytes=5)
                (adm_dir / "chunk-0").write_bytes(b"12345")

                mini_app = Flask(__name__)
                saturated = AdmissionController(
                    max_concurrent=1,
                    max_queue=0,
                    max_per_identity=0,
                    timeout_seconds=0.05,
                )

                @mini_app.post("/commit/<session_id>")
                @require_capacity(saturated)
                def _commit(session_id: str):
                    return jsonify({"session_id": session_id})

                adm_resp = mini_app.test_client().post("/commit/sess-adm-429")
                self.assertEqual(adm_resp.status_code, 429)

                offline_after_adm = build_failed_session_integrity_report(tmp)
                adm_records = [
                    s for s in offline_after_adm["sessions"] if s["session_id"] == "sess-adm-429"
                ]
                self.assertEqual(len(adm_records), 1)
                self.assertEqual(adm_records[0]["failure_reason"], "admission_rejected")
                self.assertEqual(adm_records[0]["observed_bytes"], 5)
                self.assertEqual(adm_records[0]["byte_delta"], 0)


if __name__ == "__main__":
    unittest.main(verbosity=2)
