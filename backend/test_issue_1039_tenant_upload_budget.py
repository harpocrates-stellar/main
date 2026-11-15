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

from werkzeug.exceptions import ClientDisconnected

sys.path.insert(0, str(Path(__file__).resolve().parent))

import app as app_module  # noqa: E402
import strkey  # noqa: E402
from admission import (  # noqa: E402
    TenantUploadBudgetExceededError,
    TenantUploadBudgetManager,
)
from streaming_upload import hash_stream_to_path  # noqa: E402


def _synthetic_g_address(seed: int) -> str:
    body = bytes([6 << 3]) + bytes([seed & 0xFF]) * 32
    crc = strkey._crc16_xmodem(body)
    return base64.b32encode(body + crc.to_bytes(2, "big")).decode("ascii")


OWNER_A = _synthetic_g_address(0x11)
OWNER_B = _synthetic_g_address(0x22)
TOKEN_A = "synthetic-tenant-token-alpha"
TOKEN_B = "synthetic-tenant-token-beta"


class _SpyStream:
    """WSGI input stream wrapper that counts read() calls and can simulate disconnects."""

    def __init__(self, payload: bytes, *, disconnect_after_reads: int | None = None) -> None:
        self._buf = io.BytesIO(payload)
        self.read_calls = 0
        self._disconnect_after = disconnect_after_reads

    def read(self, size: int = -1) -> bytes:
        self.read_calls += 1
        if self._disconnect_after is not None and self.read_calls > self._disconnect_after:
            raise ClientDisconnected("synthetic client disconnect")
        return self._buf.read(size)

    def readline(self, size: int = -1) -> bytes:
        self.read_calls += 1
        if self._disconnect_after is not None and self.read_calls > self._disconnect_after:
            raise ClientDisconnected("synthetic client disconnect")
        return self._buf.readline(size)


def _multipart_body(boundary: str, field_name: str, filename: str, content: bytes) -> bytes:
    return (
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="{field_name}"; filename="{filename}"\r\n'
        f"Content-Type: application/octet-stream\r\n\r\n"
    ).encode("utf-8") + content + f"\r\n--{boundary}--\r\n".encode("utf-8")


class TenantUploadBudgetUnitTests(unittest.TestCase):
    def test_reserve_grow_and_idempotent_release(self) -> None:
        budget = TenantUploadBudgetManager(budget_bytes=1024)
        with budget.reserve("tenant:alpha", 400) as res:
            self.assertEqual(budget.reserved_bytes("tenant:alpha"), 400)
            res.ensure_reserved(900)
            self.assertEqual(budget.reserved_bytes("tenant:alpha"), 900)
            with self.assertRaises(TenantUploadBudgetExceededError):
                res.ensure_reserved(1025)
            # Failed growth must leave the existing reservation intact until release.
            self.assertEqual(budget.reserved_bytes("tenant:alpha"), 900)
            # Other tenants remain unaffected.
            with budget.reserve("tenant:beta", 800):
                self.assertEqual(budget.reserved_bytes("tenant:beta"), 800)

        self.assertEqual(budget.reserved_bytes("tenant:alpha"), 0)
        self.assertEqual(budget.reserved_bytes("tenant:beta"), 0)
        self.assertEqual(budget.active_tenant_count(), 0)
        self.assertEqual(res.release(), 0)

    def test_stream_growth_exceeding_budget_aborts_and_cleans_destination(self) -> None:
        budget = TenantUploadBudgetManager(budget_bytes=512)
        with tempfile.TemporaryDirectory() as tmp_dir:
            dest = Path(tmp_dir) / "artifact.bin"
            with self.assertRaises(TenantUploadBudgetExceededError):
                with budget.reserve("tenant:stream", 0) as res:
                    hash_stream_to_path(
                        io.BytesIO(b"x" * 1024),
                        dest,
                        chunk_size=128,
                        temp_dir=tmp_dir,
                        budget_reservation=res,
                    )
            self.assertFalse(dest.exists())
            self.assertEqual(list(Path(tmp_dir).iterdir()), [])
        self.assertEqual(budget.reserved_bytes("tenant:stream"), 0)


class TenantUploadBudgetRouteTests(unittest.TestCase):
    def _build_app(self, extra_env: dict[str, str] | None = None):
        env = {
            "RATELIMIT_ENABLED": "false",
            "UPLOAD_TENANT_BUDGET_BYTES": "2048",
            "UPLOAD_STREAM_THRESHOLD_BYTES": "64",
        }
        if extra_env:
            env.update(extra_env)
        with patch.dict(os.environ, env, clear=False):
            return app_module.create_app()

    def test_reserves_before_reading_large_body_and_isolates_tenants(self) -> None:
        flask_app = self._build_app({"UPLOAD_TENANT_BUDGET_BYTES": "1024"})
        budget: TenantUploadBudgetManager = flask_app.extensions["tenant_upload_budget"]
        client = flask_app.test_client()

        # Hold 700 bytes for tenant-alpha so a 500-byte upload exceeds 1024 bytes.
        held = budget.reserve("tenant:alpha", 700)
        try:
            boundary = "----HarpocratesBoundary1039"
            body = _multipart_body(boundary, "video", "clip.mp4", b"a" * 500)
            spy = _SpyStream(body)
            resp = client.open(
                "/api/stego/embed",
                method="POST",
                headers={
                    "X-Tenant-ID": "alpha",
                    "Content-Type": f"multipart/form-data; boundary={boundary}",
                    "Content-Length": str(len(body)),
                },
                environ_overrides={
                    "wsgi.input": spy,
                    "CONTENT_LENGTH": str(len(body)),
                },
            )
            self.assertEqual(resp.status_code, 429)
            payload = resp.get_json()
            self.assertFalse(payload["ok"])
            self.assertEqual(payload["error"]["code"], "UPLOAD_TENANT_BUDGET_EXCEEDED")
            # Crucial acceptance check: body stream was NEVER read prior to rejection.
            self.assertEqual(spy.read_calls, 0)
            self.assertEqual(budget.reserved_bytes("tenant:alpha"), 700)

            # Tenant-beta has its own independent 1024-byte budget and is NOT throttled by alpha.
            resp_beta = client.post(
                "/api/stego/embed",
                headers={"X-Tenant-ID": "beta"},
                data={"video": (io.BytesIO(b"b" * 200), "clip.mp4")},
                content_type="multipart/form-data",
            )
            # Missing metadata returns 400 validation error (not 429), and releases beta's budget.
            self.assertEqual(resp_beta.status_code, 400)
            self.assertEqual(budget.reserved_bytes("tenant:beta"), 0)
        finally:
            held.release()
        self.assertEqual(budget.reserved_bytes("tenant:alpha"), 0)

    def test_releases_reservation_on_rejection_disconnect_and_session_commit(self) -> None:
        digest_a = hashlib.sha256(TOKEN_A.encode("utf-8")).hexdigest()
        digest_b = hashlib.sha256(TOKEN_B.encode("utf-8")).hexdigest()
        flask_app = self._build_app(
            {
                "UPLOAD_TENANT_BUDGET_BYTES": "2048",
                "MAX_CONCURRENT_PER_IDENTITY": "1",
                "REGISTER_SCOPED_KEYS": f"{OWNER_A}:{digest_a},{OWNER_B}:{digest_b}",
            }
        )
        budget: TenantUploadBudgetManager = flask_app.extensions["tenant_upload_budget"]
        client = flask_app.test_client()

        # 1. Disconnect mid-body releases the pre-body reservation deterministically.
        boundary = "----HarpocratesDisconnect1039"
        raw_body = _multipart_body(boundary, "video", "clip.mp4", b"z" * 600)
        disconnect_stream = _SpyStream(raw_body, disconnect_after_reads=1)
        resp_disc = client.open(
            "/api/stego/embed",
            method="POST",
            headers={
                "Authorization": f"Bearer {TOKEN_A}",
                "X-Tenant-ID": "spoofed-other-tenant",
                "Content-Type": f"multipart/form-data; boundary={boundary}",
                "Content-Length": str(len(raw_body)),
            },
            environ_overrides={
                "wsgi.input": disconnect_stream,
                "CONTENT_LENGTH": str(len(raw_body)),
            },
        )
        self.assertGreaterEqual(resp_disc.status_code, 400)
        self.assertEqual(budget.reserved_bytes(f"principal:{OWNER_A}"), 0)
        self.assertEqual(budget.reserved_bytes("tenant:spoofed-other-tenant"), 0)

        # 2. Session chunks retain exact staged bytes until commit cleans the session dir.
        create_resp = client.post("/api/stego/upload-session")
        self.assertEqual(create_resp.status_code, 200)
        session_id = create_resp.get_json()["sessionId"]

        chunk_resp = client.put(
            f"/api/stego/upload-session/{session_id}/chunk/0",
            headers={"Authorization": f"Bearer {TOKEN_A}"},
            data={"chunk": (io.BytesIO(b"\x00\x00\x00\x18ftypmp42" + b"m" * 300), "part0")},
            content_type="multipart/form-data",
        )
        self.assertEqual(chunk_resp.status_code, 200)
        self.assertEqual(budget.reserved_bytes(f"principal:{OWNER_A}"), 312)

        def _fake_embed(_src, dst, _meta):
            Path(dst).write_bytes(b"synthetic-embedded-mp4")

        valid_meta = {
            "version": 2,
            "proofId": "proof-1039",
            "tier": "verified",
            "timestamp": "2026-11-15T00:00:00Z",
        }
        with (
            patch.object(app_module, "sniff_media_type_path", return_value="video/mp4"),
            patch.object(app_module, "embed_metadata", side_effect=_fake_embed),
            patch.object(app_module, "validate_embed_metadata", return_value=None),
            patch.object(app_module, "insert_proof_event", return_value={"id": 1}),
        ):
            commit_resp = client.post(
                f"/api/stego/upload-session/{session_id}/commit",
                headers={"Authorization": f"Bearer {TOKEN_A}"},
                data={"metadata": json.dumps(valid_meta)},
                content_type="multipart/form-data",
            )
        self.assertEqual(commit_resp.status_code, 200)
        self.assertEqual(budget.reserved_bytes(f"principal:{OWNER_A}"), 0)


if __name__ == "__main__":
    unittest.main()
