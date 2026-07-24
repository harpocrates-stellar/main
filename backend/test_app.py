from __future__ import annotations

import contextlib
import io
import json
import os
import unittest

import app as _app_module


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

VALID_VIDEO_HASH = "aa" * 32
VALID_METADATA_HASH = "bb" * 32
VALID_PROOF_ID = "cc" * 32

VALID_REGISTER_PAYLOAD: dict[str, object] = {
    "fileName": "evidence.mp4",
    "videoHash": VALID_VIDEO_HASH,
    "metadataHash": VALID_METADATA_HASH,
    "proofId": VALID_PROOF_ID,
    "tier": "source",
    "txHash": "deadbeef",
    "txStatus": "PENDING",
    "sourceAddress": "GDVRSXIO4SK2KSMUKJTQHMDDHBBFC7NGZZ6WLVOPKAG47GYPYAZCZR7G",
    "contractId": "CCKTQNMBLXZXMWVR2WG4HDDUI3QGJU5LV5NTLFPCB72UITWE5TEDK7BT",
}

TEST_API_KEY = "test-secret-key-for-registration"


# ---------------------------------------------------------------------------
# Context manager: spin up a fresh Flask app with specific env vars
# ---------------------------------------------------------------------------

@contextlib.contextmanager
def _app_env(extra: dict[str, str], clear: list[str] | None = None):
    """Temporarily set *extra* env vars, optionally clearing *clear* keys,
    then create a fresh Flask test client.  Restores the environment on exit.
    """
    clear = clear or []
    saved = {k: os.environ.get(k) for k in list(extra) + clear}

    for k in clear:
        os.environ.pop(k, None)
    os.environ.update(extra)

    try:
        fresh = _app_module.create_app()
        yield fresh.test_client()
    finally:
        for k, v in saved.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v


def _client_no_key():
    """Fresh test client with no REGISTER_API_KEY configured."""
    return _app_env({}, clear=["REGISTER_API_KEY", "REGISTER_API_KEY_EXPIRES"])


def _client_with_key(key: str, expires: str | None = None):
    """Fresh test client with the given API key (and optional expiry)."""
    extra: dict[str, str] = {"REGISTER_API_KEY": key}
    if expires:
        extra["REGISTER_API_KEY_EXPIRES"] = expires
    clear = [] if expires else ["REGISTER_API_KEY_EXPIRES"]
    return _app_env(extra, clear=clear)


# ---------------------------------------------------------------------------
# Helper: POST /api/proofs/register
# ---------------------------------------------------------------------------

def _post_register(
    client,
    *,
    token: str | None = None,
    auth_header: str | None = None,
    payload: dict | None = None,
):
    headers = {"Content-Type": "application/json"}
    if auth_header is not None:
        headers["Authorization"] = auth_header
    elif token is not None:
        headers["Authorization"] = f"Bearer {token}"
    return client.post(
        "/api/proofs/register",
        data=json.dumps(payload or VALID_REGISTER_PAYLOAD),
        headers=headers,
    )


# ---------------------------------------------------------------------------
# General hardening tests (pre-existing)
# ---------------------------------------------------------------------------

class AppHardeningTest(unittest.TestCase):
    def setUp(self) -> None:
        self.client = _app_module.app.test_client()

    def test_health_sets_security_headers(self) -> None:
        response = self.client.get("/health")

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.headers["X-Content-Type-Options"], "nosniff")
        self.assertEqual(response.headers["Referrer-Policy"], "no-referrer")
        self.assertEqual(response.headers["Cache-Control"], "no-store")

    def test_ready_endpoint_reports_service_dependencies(self) -> None:
        response = self.client.get("/ready")

        self.assertIn(response.status_code, {200, 503})
        self.assertIn("video_tools", response.json)
        self.assertIn("database", response.json)

    def test_embed_rejects_non_video_upload(self) -> None:
        response = self.client.post(
            "/api/stego/embed",
            data={
                "metadata": json.dumps(valid_metadata()),
                "video": (io.BytesIO(b"not a video"), "note.txt"),
            },
            content_type="multipart/form-data",
        )

        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json["error"], "video upload must use a video content type")

    def test_embed_rejects_missing_metadata_fields(self) -> None:
        response = self.client.post(
            "/api/stego/embed",
            data={
                "metadata": json.dumps({"protocol": "harpocrates"}),
                "video": (io.BytesIO(b"video bytes"), "evidence.mp4", "video/mp4"),
            },
            content_type="multipart/form-data",
        )

        self.assertEqual(response.status_code, 400)
        self.assertIn("metadata missing required field", response.json["error"])


# ---------------------------------------------------------------------------
# Registration authentication tests
# ---------------------------------------------------------------------------

class RegisterProofAuthTest(unittest.TestCase):
    """Positive and negative tests for /api/proofs/register authentication."""

    # --- Positive: open endpoint (no key configured) ---------------------

    def test_open_when_no_key_configured(self) -> None:
        """When REGISTER_API_KEY is not set the endpoint accepts any request."""
        with _client_no_key() as client:
            resp = _post_register(client)
        # 200 if DB available, 500 if DATABASE_URL absent – both indicate auth
        # was not the reason for failure.
        self.assertIn(resp.status_code, {200, 500})

    # --- Positive: valid Bearer token, no expiry -------------------------

    def test_accepts_valid_bearer_token(self) -> None:
        with _client_with_key(TEST_API_KEY) as client:
            resp = _post_register(client, token=TEST_API_KEY)
        self.assertIn(resp.status_code, {200, 500})

    # --- Positive: valid Bearer token, future expiry ---------------------

    def test_accepts_valid_token_with_future_expiry(self) -> None:
        with _client_with_key(TEST_API_KEY, expires="2099-12-31T23:59:59Z") as client:
            resp = _post_register(client, token=TEST_API_KEY)
        self.assertIn(resp.status_code, {200, 500})

    # --- Negative: missing Authorization header --------------------------

    def test_rejects_missing_auth_header(self) -> None:
        with _client_with_key(TEST_API_KEY) as client:
            resp = _post_register(client, token=None)
        self.assertEqual(resp.status_code, 401)
        self.assertIn("Authorization", resp.json["error"])

    # --- Negative: wrong token -------------------------------------------

    def test_rejects_wrong_token(self) -> None:
        with _client_with_key(TEST_API_KEY) as client:
            resp = _post_register(client, token="definitely-wrong")
        self.assertEqual(resp.status_code, 401)
        self.assertIn("Invalid", resp.json["error"])

    # --- Negative: non-Bearer auth scheme --------------------------------

    def test_rejects_non_bearer_scheme(self) -> None:
        with _client_with_key(TEST_API_KEY) as client:
            resp = _post_register(client, auth_header=f"Basic {TEST_API_KEY}")
        self.assertEqual(resp.status_code, 401)

    # --- Negative: expired key -------------------------------------------

    def test_rejects_expired_key(self) -> None:
        with _client_with_key(TEST_API_KEY, expires="2000-06-01T00:00:00Z") as client:
            resp = _post_register(client, token=TEST_API_KEY)
        self.assertEqual(resp.status_code, 401)
        self.assertIn("expired", resp.json["error"])

    # --- Negative: empty Bearer value ------------------------------------

    def test_rejects_empty_bearer_value(self) -> None:
        with _client_with_key(TEST_API_KEY) as client:
            resp = _post_register(client, auth_header="Bearer ")
        self.assertEqual(resp.status_code, 401)

    # --- Negative: wrong token, future expiry ----------------------------

    def test_rejects_wrong_token_with_future_expiry(self) -> None:
        with _client_with_key(TEST_API_KEY, expires="2099-01-01T00:00:00Z") as client:
            resp = _post_register(client, token="not-the-right-key")
        self.assertEqual(resp.status_code, 401)

    # --- Negative: expired even with correct token -----------------------

    def test_rejects_correct_token_when_expired(self) -> None:
        """Expiry check runs before token comparison; correct key still rejected."""
        with _client_with_key(TEST_API_KEY, expires="2000-01-01T00:00:00Z") as client:
            resp = _post_register(client, token=TEST_API_KEY)
        self.assertEqual(resp.status_code, 401)
        self.assertIn("expired", resp.json["error"])


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

def valid_metadata() -> dict[str, object]:
    return {
        "protocol": "harpocrates",
        "version": 1,
        "tier": "silent",
        "sourceHash": "11" * 32,
        "proofId": "22" * 32,
        "timestamp": "2026-06-18T00:00:00.000Z",
    }


if __name__ == "__main__":
    unittest.main()
