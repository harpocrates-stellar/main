"""Focused coverage for offline upload integrity reports on failed sessions."""

from __future__ import annotations

import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from streaming_upload import (
    BYTE_COUNT_STATUS_MATCHED,
    BYTE_COUNT_STATUS_OVERFLOW,
    BYTE_COUNT_STATUS_UNDERFLOW,
    BYTE_COUNT_STATUS_UNKNOWN,
    DIGEST_STATUS_MATCHED,
    DIGEST_STATUS_MISMATCH,
    DIGEST_STATUS_UNAVAILABLE,
    DIGEST_STATUS_UNVERIFIED,
    INTEGRITY_REPORT_SCHEMA_VERSION,
    build_upload_integrity_report,
    inspect_failed_upload_session,
    write_upload_integrity_report,
)


class TestOfflineUploadIntegrityReport(unittest.TestCase):
    def test_verified_multi_chunk_session_records_counts_and_digest(self):
        part0 = b"synthetic-chunk-zero-"
        part1 = b"synthetic-chunk-one"
        combined = part0 + part1
        expected_digest = hashlib.sha256(combined).hexdigest()

        with tempfile.TemporaryDirectory() as tmp:
            session_dir = Path(tmp) / "harpocrates-session-abc123"
            session_dir.mkdir()
            (session_dir / "chunk-0").write_bytes(part0)
            (session_dir / "chunk-1").write_bytes(part1)

            report = inspect_failed_upload_session(
                session_dir,
                session_id="abc123",
                expected_bytes=len(combined),
                expected_digest=expected_digest.upper(),
                expected_chunks=2,
                chunk_expectations={
                    0: (len(part0), hashlib.sha256(part0).hexdigest()),
                    1: (len(part1), hashlib.sha256(part1).hexdigest()),
                },
                chunk_size=8,
            )

            self.assertEqual(report.schema_version, INTEGRITY_REPORT_SCHEMA_VERSION)
            self.assertEqual(report.session_id, "abc123")
            self.assertEqual(report.status, "verified")
            self.assertIsNone(report.failure_reason)
            self.assertEqual(report.expected_bytes, len(combined))
            self.assertEqual(report.observed_bytes, len(combined))
            self.assertEqual(report.byte_count_status, BYTE_COUNT_STATUS_MATCHED)
            self.assertEqual(report.expected_digest, expected_digest)
            self.assertEqual(report.observed_digest, expected_digest)
            self.assertEqual(report.digest_status, DIGEST_STATUS_MATCHED)
            self.assertEqual(report.chunk_count, 2)
            self.assertEqual(report.missing_chunk_indices, ())
            self.assertEqual(len(report.chunks), 2)
            self.assertEqual(report.chunks[0].digest_status, DIGEST_STATUS_MATCHED)
            self.assertEqual(report.chunks[1].byte_count_status, BYTE_COUNT_STATUS_MATCHED)

    def test_truncated_session_reports_underflow_and_digest_mismatch(self):
        full_payload = b"A" * 64
        truncated = full_payload[:20]

        with tempfile.TemporaryDirectory() as tmp:
            session_dir = Path(tmp) / "session-trunc"
            session_dir.mkdir()
            (session_dir / "chunk-0").write_bytes(truncated)

            report = inspect_failed_upload_session(
                session_dir,
                session_id="sess-trunc-1",
                expected_bytes=len(full_payload),
                expected_digest=hashlib.sha256(full_payload).hexdigest(),
                chunk_size=8,
            )

            self.assertEqual(report.status, "failed")
            self.assertEqual(report.failure_reason, "byte_count_mismatch")
            self.assertEqual(report.expected_bytes, 64)
            self.assertEqual(report.observed_bytes, 20)
            self.assertEqual(report.byte_count_status, BYTE_COUNT_STATUS_UNDERFLOW)
            self.assertEqual(report.digest_status, DIGEST_STATUS_MISMATCH)
            self.assertEqual(report.observed_digest, hashlib.sha256(truncated).hexdigest())

    def test_digest_mismatch_with_matching_byte_count(self):
        expected_payload = b"expected-bytes-01"
        corrupted_payload = b"corruptd-bytes-01"
        self.assertEqual(len(expected_payload), len(corrupted_payload))

        with tempfile.TemporaryDirectory() as tmp:
            session_dir = Path(tmp) / "session-corrupt"
            session_dir.mkdir()
            (session_dir / "chunk-0").write_bytes(corrupted_payload)

            report = inspect_failed_upload_session(
                session_dir,
                session_id="sess-corrupt",
                expected_bytes=len(expected_payload),
                expected_digest=hashlib.sha256(expected_payload).hexdigest(),
            )

            self.assertEqual(report.status, "failed")
            self.assertEqual(report.failure_reason, "digest_mismatch")
            self.assertEqual(report.byte_count_status, BYTE_COUNT_STATUS_MATCHED)
            self.assertEqual(report.digest_status, DIGEST_STATUS_MISMATCH)

    def test_chunk_gap_and_trailing_missing_chunks(self):
        with tempfile.TemporaryDirectory() as tmp:
            session_dir = Path(tmp) / "session-gap"
            session_dir.mkdir()
            (session_dir / "chunk-0").write_bytes(b"part0")
            (session_dir / "chunk-2").write_bytes(b"part2")

            report = inspect_failed_upload_session(
                session_dir,
                session_id="sess-gap",
                expected_chunks=4,
            )

            self.assertEqual(report.status, "failed")
            self.assertEqual(report.failure_reason, "chunk_gap")
            self.assertEqual(report.chunk_count, 2)
            self.assertEqual(report.missing_chunk_indices, (1, 3))
            self.assertEqual(report.byte_count_status, BYTE_COUNT_STATUS_UNKNOWN)
            self.assertEqual(report.digest_status, DIGEST_STATUS_UNVERIFIED)

    def test_oversized_session_exceeds_max_size_and_expected_bytes(self):
        payload = b"Z" * 128

        with tempfile.TemporaryDirectory() as tmp:
            session_dir = Path(tmp) / "session-over"
            session_dir.mkdir()
            (session_dir / "chunk-0").write_bytes(payload)

            report = inspect_failed_upload_session(
                session_dir,
                session_id="sess-over",
                expected_bytes=64,
                max_size=100,
            )

            self.assertEqual(report.status, "failed")
            self.assertEqual(report.failure_reason, "size_limit_exceeded")
            self.assertEqual(report.byte_count_status, BYTE_COUNT_STATUS_OVERFLOW)
            self.assertEqual(report.observed_bytes, 128)

    def test_missing_and_empty_session_directories(self):
        with tempfile.TemporaryDirectory() as tmp:
            missing_dir = Path(tmp) / "does-not-exist"
            missing_report = inspect_failed_upload_session(
                missing_dir,
                session_id="sess-missing",
                expected_bytes=100,
                expected_digest="a" * 64,
            )
            self.assertEqual(missing_report.status, "failed")
            self.assertEqual(missing_report.failure_reason, "missing_session")
            self.assertEqual(missing_report.observed_bytes, 0)
            self.assertEqual(missing_report.digest_status, DIGEST_STATUS_UNAVAILABLE)
            self.assertIsNone(missing_report.observed_digest)

            empty_dir = Path(tmp) / "empty-session"
            empty_dir.mkdir()
            empty_report = inspect_failed_upload_session(
                empty_dir,
                session_id="sess-empty",
                expected_chunks=2,
            )
            self.assertEqual(empty_report.status, "failed")
            self.assertEqual(empty_report.failure_reason, "empty_session")
            self.assertEqual(empty_report.observed_bytes, 0)
            self.assertEqual(empty_report.digest_status, DIGEST_STATUS_UNAVAILABLE)
            self.assertEqual(empty_report.missing_chunk_indices, (0, 1))

    def test_excludes_uploaded_media_bytes_and_private_filenames(self):
        canary_bytes = b"CANARY_SECRET_WITNESS_MEDIA_BYTES_987654321"
        private_filename = "witness_interview_confidential_2026.mp4"
        private_dir_marker = "private-witness-folder-xyz"

        with tempfile.TemporaryDirectory() as tmp:
            session_dir = Path(tmp) / private_dir_marker
            session_dir.mkdir()
            (session_dir / "chunk-0").write_bytes(canary_bytes)
            # Stray file with a private filename must be ignored and never echoed.
            (session_dir / private_filename).write_bytes(b"PRIVATE_STRAY_PAYLOAD")

            # Path-like session_id must be rejected/stripped (fail-closed).
            report = inspect_failed_upload_session(
                session_dir,
                session_id=f"../{private_filename}",
                expected_bytes=len(canary_bytes) + 10,
            )
            serialized = report.to_json()

            self.assertIsNone(report.session_id)
            self.assertNotIn(canary_bytes.decode("ascii"), serialized)
            self.assertNotIn("PRIVATE_STRAY_PAYLOAD", serialized)
            self.assertNotIn(private_filename, serialized)
            self.assertNotIn(private_dir_marker, serialized)
            self.assertNotIn(str(session_dir), serialized)
            self.assertEqual(report.observed_bytes, len(canary_bytes))
            self.assertEqual(report.chunk_count, 1)

    def test_build_report_for_admission_rejection_and_write_to_disk(self):
        report = build_upload_integrity_report(
            session_id="sess-admit-1",
            expected_bytes=2048,
            observed_bytes=0,
            expected_digest="b" * 64,
            observed_digest=None,
            failure_reason="queue_full",
        )
        self.assertEqual(report.status, "failed")
        self.assertEqual(report.failure_reason, "queue_full")
        self.assertEqual(report.byte_count_status, BYTE_COUNT_STATUS_UNDERFLOW)
        self.assertEqual(report.digest_status, DIGEST_STATUS_UNAVAILABLE)

        with tempfile.TemporaryDirectory() as tmp:
            out_path = Path(tmp) / "reports" / "integrity.json"
            written = write_upload_integrity_report(report, out_path)
            self.assertEqual(written, out_path)
            parsed = json.loads(out_path.read_text(encoding="utf-8"))
            self.assertEqual(parsed["session_id"], "sess-admit-1")
            self.assertEqual(parsed["expected_bytes"], 2048)
            self.assertEqual(parsed["observed_bytes"], 0)
            self.assertEqual(parsed["digest_status"], DIGEST_STATUS_UNAVAILABLE)
            self.assertEqual(parsed["failure_reason"], "queue_full")


if __name__ == "__main__":
    unittest.main(verbosity=2)
