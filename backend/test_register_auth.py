"""Ownership-scoped registration auth (``POST /api/proofs/register``).

Covers the pure credential logic (``register_auth``) and the Flask boundary:
scoped keys may only register their own ``sourceAddress``, may not take over a
proof another address owns, keep the legacy unscoped key working, and never let
an idempotency replay bypass authorization. All addresses, keys and hashes are
synthetic.
"""

from __future__ import annotations

import contextlib
import hashlib
import logging
import os
import unittest
from datetime import datetime, timezone
from unittest.mock import patch

import app as app_module
import idempotency
import register_auth
from register_auth import (
    MAX_SCOPED_KEYS,
    MAX_TOKEN_CHARS,
    RegistrationPrincipal,
    ScopedKey,
    authenticate,
    parse_scoped_keys,
    scope_allows,
    token_digest,
)
from strkey import make_strkey

G_VERSION = 6 << 3
C_VERSION = 2 << 3

OWNER_A = make_strkey(G_VERSION, bytes([1]) * 32)
OWNER_B = make_strkey(G_VERSION, bytes([2]) * 32)
CONTRACT_ID = make_strkey(C_VERSION, bytes([3]) * 32)

TOKEN_A = "synthetic-scoped-token-a"
TOKEN_B = "synthetic-scoped-token-b"
LEGACY_TOKEN = "synthetic-legacy-token"

REGISTER_ENV = (
    "REGISTER_API_KEY",
    "REGISTER_API_KEY_EXPIRES",
    "REGISTER_SCOPED_KEYS",
    "MAX_JSON_BYTES",
    "RATELIMIT_ENABLED",
)


def hexdigest(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def scoped_env(*pairs: tuple[str, str]) -> str:
    return ",".join(f"{owner}:{hexdigest(token)}" for owner, token in pairs)


@contextlib.contextmanager
def client_with(**env: str):
    """Fresh app + test client with exactly the given registration env."""
    saved = {name: os.environ.get(name) for name in REGISTER_ENV}
    for name in REGISTER_ENV:
        os.environ.pop(name, None)
    os.environ["RATELIMIT_ENABLED"] = "false"
    os.environ.update(env)
    try:
        yield app_module.create_app().test_client()
    finally:
        for name, value in saved.items():
            if value is None:
                os.environ.pop(name, None)
            else:
                os.environ[name] = value


def payload(**overrides) -> dict[str, object]:
    base: dict[str, object] = {
        "fileName": "evidence.mp4",
        "videoHash": "aa" * 32,
        "metadataHash": "bb" * 32,
        "proofId": "cc" * 32,
        "tier": "source",
        "sourceAddress": OWNER_A,
        "contractId": CONTRACT_ID,
    }
    base.update(overrides)
    return base


def stored_row(body: dict[str, object]) -> dict[str, object]:
    return {
        "id": 1,
        "video_hash": body["videoHash"],
        "metadata_hash": body["metadataHash"],
        "proof_id": body["proofId"],
        "tier": body["tier"],
        "source_address": body.get("sourceAddress"),
        "contract_id": body.get("contractId"),
    }


def post(client, body: dict[str, object] | None = None, token: str | None = None, header: str | None = None):
    headers = {}
    if header is not None:
        headers["Authorization"] = header
    elif token is not None:
        headers["Authorization"] = f"Bearer {token}"
    return client.post("/api/proofs/register", json=body if body is not None else payload(), headers=headers)


class UpsertStub:
    """Patch the persistence boundary and record whether a write happened."""

    def __init__(self) -> None:
        self._patch = patch.object(app_module, "upsert_register_event", side_effect=self._upsert)
        # A created event fans out to webhooks; keep the tests off the database.
        self._webhooks = patch.object(app_module, "queue_webhook_deliveries")
        self.calls = 0

    def _upsert(self, **kwargs):
        self.calls += 1
        return stored_row(
            {
                "videoHash": kwargs["video_hash"],
                "metadataHash": kwargs["metadata_hash"],
                "proofId": kwargs["proof_id"],
                "tier": kwargs["tier"],
                "sourceAddress": kwargs["source_address"],
                "contractId": kwargs["contract_id"],
            }
        ), True

    def __enter__(self) -> "UpsertStub":
        self._patch.start()
        self._webhooks.start()
        return self

    def __exit__(self, *exc) -> None:
        self._webhooks.stop()
        self._patch.stop()


# ---------------------------------------------------------------------------
# Pure credential logic
# ---------------------------------------------------------------------------


class ParseScopedKeysTest(unittest.TestCase):
    def test_empty_and_unset_mean_no_scoped_keys(self) -> None:
        self.assertEqual(parse_scoped_keys(None), ())
        self.assertEqual(parse_scoped_keys(""), ())
        self.assertEqual(parse_scoped_keys("   "), ())

    def test_parses_entries_and_normalizes_case_and_whitespace(self) -> None:
        raw = f" {OWNER_A.lower()} : {hexdigest(TOKEN_A).upper()} , {OWNER_B}:{hexdigest(TOKEN_B)} "
        keys = parse_scoped_keys(raw)
        self.assertEqual([k.owner for k in keys], [OWNER_A, OWNER_B])
        self.assertEqual(keys[0].digest, token_digest(TOKEN_A))

    def test_rejects_malformed_entries_without_leaking_contents(self) -> None:
        digest = hexdigest(TOKEN_A)
        bad = {
            "missing separator": OWNER_A,
            "bad address": f"GNOTAVALIDADDRESS:{digest}",
            "contract id is not an owner": f"{CONTRACT_ID}:{digest}",
            "short digest": f"{OWNER_A}:{digest[:-2]}",
            "non-hex digest": f"{OWNER_A}:{'z' * 64}",
            "empty digest": f"{OWNER_A}:",
        }
        for label, raw in bad.items():
            with self.subTest(label):
                with self.assertRaises(RuntimeError) as caught:
                    parse_scoped_keys(raw)
                message = str(caught.exception)
                self.assertIn("REGISTER_SCOPED_KEYS entry 1", message)
                self.assertNotIn(digest, message)
                self.assertNotIn(OWNER_A, message)

    def test_rejects_a_digest_shared_by_two_owners(self) -> None:
        raw = scoped_env((OWNER_A, TOKEN_A), (OWNER_B, TOKEN_A))
        with self.assertRaisesRegex(RuntimeError, "entry 2 reuses"):
            parse_scoped_keys(raw)

    def test_entry_count_boundary(self) -> None:
        def entry(index: int) -> str:
            owner = make_strkey(G_VERSION, index.to_bytes(32, "big"))
            return f"{owner}:{hexdigest(f'token-{index}')}"

        at_limit = ",".join(entry(i) for i in range(1, MAX_SCOPED_KEYS + 1))
        self.assertEqual(len(parse_scoped_keys(at_limit)), MAX_SCOPED_KEYS)
        with self.assertRaisesRegex(RuntimeError, "at most"):
            parse_scoped_keys(at_limit + "," + entry(MAX_SCOPED_KEYS + 1))


class AuthenticateTest(unittest.TestCase):
    def setUp(self) -> None:
        self.keys = parse_scoped_keys(scoped_env((OWNER_A, TOKEN_A), (OWNER_B, TOKEN_B)))

    def test_scoped_token_resolves_to_its_owner(self) -> None:
        principal = authenticate(TOKEN_B, legacy_key=None, scoped_keys=self.keys)
        self.assertEqual(principal, RegistrationPrincipal(owner=OWNER_B))
        self.assertTrue(principal.is_scoped)

    def test_legacy_token_is_unscoped(self) -> None:
        principal = authenticate(LEGACY_TOKEN, legacy_key=LEGACY_TOKEN, scoped_keys=self.keys)
        self.assertEqual(principal, RegistrationPrincipal(owner=None))
        self.assertFalse(principal.is_scoped)

    def test_unknown_and_empty_tokens_match_nothing(self) -> None:
        for token in ("nope", "", TOKEN_A + "x", TOKEN_A[:-1]):
            with self.subTest(token=token):
                self.assertIsNone(authenticate(token, legacy_key=LEGACY_TOKEN, scoped_keys=self.keys))

    def test_scoped_keys_alone_do_not_accept_the_legacy_token(self) -> None:
        self.assertIsNone(authenticate(LEGACY_TOKEN, legacy_key=None, scoped_keys=self.keys))

    def test_token_length_boundary(self) -> None:
        at_limit = "k" * MAX_TOKEN_CHARS
        self.assertEqual(
            authenticate(at_limit, legacy_key=at_limit, scoped_keys=()),
            RegistrationPrincipal(owner=None),
        )
        over = "k" * (MAX_TOKEN_CHARS + 1)
        self.assertIsNone(authenticate(over, legacy_key=over, scoped_keys=()))

    def test_non_ascii_token_is_rejected_cleanly(self) -> None:
        self.assertIsNone(authenticate("töken", legacy_key=LEGACY_TOKEN, scoped_keys=self.keys))

    def test_every_credential_is_compared_even_after_a_match(self) -> None:
        real = register_auth.hmac.compare_digest
        with patch.object(register_auth.hmac, "compare_digest", wraps=real) as spy:
            authenticate(TOKEN_A, legacy_key=LEGACY_TOKEN, scoped_keys=self.keys)
        # Two scoped digests plus the legacy key: no early exit on the first hit.
        self.assertEqual(spy.call_count, len(self.keys) + 1)


class ScopeAllowsTest(unittest.TestCase):
    def test_unscoped_principal_is_unrestricted(self) -> None:
        legacy = RegistrationPrincipal(owner=None)
        self.assertTrue(scope_allows(legacy, OWNER_A))
        self.assertTrue(scope_allows(legacy, None))

    def test_scoped_principal_must_name_its_own_address(self) -> None:
        scoped = RegistrationPrincipal(owner=OWNER_A)
        self.assertTrue(scope_allows(scoped, OWNER_A))
        self.assertFalse(scope_allows(scoped, OWNER_B))
        self.assertFalse(scope_allows(scoped, None))


# ---------------------------------------------------------------------------
# Flask boundary
# ---------------------------------------------------------------------------


class ScopedRegistrationTest(unittest.TestCase):
    def setUp(self) -> None:
        self.scoped = scoped_env((OWNER_A, TOKEN_A), (OWNER_B, TOKEN_B))

    def test_scoped_key_registers_its_own_address(self) -> None:
        with client_with(REGISTER_SCOPED_KEYS=self.scoped) as client, UpsertStub() as upsert:
            response = post(client, token=TOKEN_A)
        self.assertEqual(response.status_code, 201)
        self.assertTrue(response.get_json()["created"])
        self.assertEqual(upsert.calls, 1)

    def test_scoped_key_cannot_register_another_address(self) -> None:
        with client_with(REGISTER_SCOPED_KEYS=self.scoped) as client, UpsertStub() as upsert:
            response = post(client, payload(sourceAddress=OWNER_B), token=TOKEN_A)
        self.assertEqual(response.status_code, 403)
        error = response.get_json()["error"]
        self.assertEqual((error["code"], error["field"]), ("FORBIDDEN", "sourceAddress"))
        self.assertEqual(upsert.calls, 0)

    def test_scoped_key_cannot_register_without_an_owner(self) -> None:
        body = payload()
        del body["sourceAddress"]
        for variant in (body, payload(sourceAddress=None)):
            with self.subTest(variant=sorted(variant)):
                with client_with(REGISTER_SCOPED_KEYS=self.scoped) as client, UpsertStub() as upsert:
                    response = post(client, variant, token=TOKEN_A)
                self.assertEqual(response.status_code, 403)
                self.assertEqual(upsert.calls, 0)

    def test_malformed_source_address_is_a_validation_error_not_a_scope_leak(self) -> None:
        with client_with(REGISTER_SCOPED_KEYS=self.scoped) as client, UpsertStub() as upsert:
            response = post(client, payload(sourceAddress="not-an-address"), token=TOKEN_A)
        self.assertEqual(response.status_code, 400)
        self.assertEqual(upsert.calls, 0)

    def test_source_address_matching_is_case_insensitive(self) -> None:
        with client_with(REGISTER_SCOPED_KEYS=self.scoped) as client, UpsertStub():
            response = post(client, payload(sourceAddress=OWNER_A.lower()), token=TOKEN_A)
        self.assertEqual(response.status_code, 201)

    def test_missing_wrong_and_malformed_credentials_are_401(self) -> None:
        cases = {
            "missing header": {},
            "wrong token": {"token": "wrong"},
            "non-bearer scheme": {"header": f"Basic {TOKEN_A}"},
            "empty bearer": {"header": "Bearer "},
            "oversized token": {"token": "k" * (MAX_TOKEN_CHARS + 1)},
        }
        for label, kwargs in cases.items():
            with self.subTest(label):
                with client_with(REGISTER_SCOPED_KEYS=self.scoped) as client, UpsertStub() as upsert:
                    response = post(client, **kwargs)
                self.assertEqual(response.status_code, 401)
                self.assertEqual(upsert.calls, 0)

    def test_stable_401_messages(self) -> None:
        with client_with(REGISTER_SCOPED_KEYS=self.scoped) as client:
            self.assertIn("Authorization", post(client).get_json()["error"])
            self.assertEqual(post(client, token="wrong").get_json()["error"], "Invalid API key")

    def test_expiry_applies_to_scoped_keys(self) -> None:
        with client_with(
            REGISTER_SCOPED_KEYS=self.scoped, REGISTER_API_KEY_EXPIRES="2000-01-01T00:00:00Z"
        ) as client, UpsertStub() as upsert:
            response = post(client, token=TOKEN_A)
        self.assertEqual(response.status_code, 401)
        self.assertIn("expired", response.get_json()["error"])
        self.assertEqual(upsert.calls, 0)

    def test_future_expiry_still_accepts(self) -> None:
        with client_with(
            REGISTER_SCOPED_KEYS=self.scoped, REGISTER_API_KEY_EXPIRES="2099-12-31T23:59:59Z"
        ) as client, UpsertStub():
            self.assertEqual(post(client, token=TOKEN_A).status_code, 201)

    def test_oversized_body_is_rejected_before_the_owner_check(self) -> None:
        with client_with(REGISTER_SCOPED_KEYS=self.scoped, MAX_JSON_BYTES="64") as client, UpsertStub() as upsert:
            response = post(client, token=TOKEN_A)
        self.assertEqual(response.status_code, 413)
        self.assertEqual(upsert.calls, 0)

    def test_non_object_body_falls_through_to_the_handler_400(self) -> None:
        with client_with(REGISTER_SCOPED_KEYS=self.scoped) as client:
            response = client.post(
                "/api/proofs/register", json=["not", "an", "object"],
                headers={"Authorization": f"Bearer {TOKEN_A}"},
            )
        self.assertEqual(response.status_code, 400)


class LegacyCompatibilityTest(unittest.TestCase):
    def test_legacy_key_alone_behaves_as_before(self) -> None:
        with client_with(REGISTER_API_KEY=LEGACY_TOKEN) as client, UpsertStub():
            self.assertEqual(post(client, token=LEGACY_TOKEN).status_code, 201)
            self.assertEqual(post(client).status_code, 401)
            self.assertEqual(post(client, token="wrong").status_code, 401)

    def test_legacy_key_registers_any_address_and_may_omit_it(self) -> None:
        body = payload()
        del body["sourceAddress"]
        with client_with(REGISTER_API_KEY=LEGACY_TOKEN) as client, UpsertStub():
            self.assertEqual(post(client, payload(sourceAddress=OWNER_B), token=LEGACY_TOKEN).status_code, 201)
            self.assertEqual(post(client, body, token=LEGACY_TOKEN).status_code, 201)

    def test_legacy_and_scoped_keys_coexist(self) -> None:
        with client_with(
            REGISTER_API_KEY=LEGACY_TOKEN, REGISTER_SCOPED_KEYS=scoped_env((OWNER_A, TOKEN_A))
        ) as client, UpsertStub():
            self.assertEqual(post(client, payload(sourceAddress=OWNER_B), token=LEGACY_TOKEN).status_code, 201)
            self.assertEqual(post(client, token=TOKEN_A).status_code, 201)
            self.assertEqual(post(client, payload(sourceAddress=OWNER_B), token=TOKEN_A).status_code, 403)

    def test_no_credentials_configured_stays_open(self) -> None:
        with client_with() as client, UpsertStub():
            self.assertEqual(post(client).status_code, 201)

    def test_legacy_key_skips_the_ownership_lookup(self) -> None:
        with client_with(REGISTER_API_KEY=LEGACY_TOKEN) as client, UpsertStub(), patch.object(
            app_module, "find_proof_owner"
        ) as lookup:
            post(client, token=LEGACY_TOKEN)
        lookup.assert_not_called()


class ProofOwnershipTest(unittest.TestCase):
    def setUp(self) -> None:
        self.scoped = scoped_env((OWNER_A, TOKEN_A), (OWNER_B, TOKEN_B))

    def register(self, owner_lookup):
        with client_with(REGISTER_SCOPED_KEYS=self.scoped) as client, UpsertStub() as upsert, patch.object(
            app_module, "find_proof_owner", **owner_lookup
        ):
            return post(client, token=TOKEN_A), upsert

    def test_unknown_proof_can_be_registered(self) -> None:
        response, upsert = self.register({"return_value": None})
        self.assertEqual(response.status_code, 201)
        self.assertEqual(upsert.calls, 1)

    def test_owner_may_re_register_their_own_proof(self) -> None:
        response, upsert = self.register({"return_value": OWNER_A})
        self.assertEqual(response.status_code, 201)
        self.assertEqual(upsert.calls, 1)

    def test_another_owners_proof_is_refused_without_naming_the_owner(self) -> None:
        response, upsert = self.register({"return_value": OWNER_B})
        self.assertEqual(response.status_code, 403)
        error = response.get_json()["error"]
        self.assertEqual((error["code"], error["field"]), ("FORBIDDEN", "proofId"))
        self.assertNotIn(OWNER_B, response.get_data(as_text=True))
        self.assertEqual(upsert.calls, 0)

    def test_lookup_failure_fails_closed_without_leaking_the_cause(self) -> None:
        response, upsert = self.register({"side_effect": RuntimeError("postgres://user:hunter2@host/db")})
        self.assertEqual(response.status_code, 503)
        self.assertEqual(response.get_json()["error"]["code"], "DEPENDENCY_UNAVAILABLE")
        self.assertNotIn("hunter2", response.get_data(as_text=True))
        self.assertEqual(upsert.calls, 0)


class IdempotencyReplayTest(unittest.TestCase):
    """Replays are keyed on the body alone, so auth must run before them."""

    REPLAY = {
        "status": "COMPLETED",
        "response_payload": {"body": {"ok": True, "replayed": True}, "status": 201},
    }

    def replaying(self):
        return patch.multiple(
            idempotency,
            _db_available=lambda: True,
            get_idempotency_record=lambda *_: dict(self.REPLAY),
        )

    def test_replay_is_not_served_to_an_unauthenticated_caller(self) -> None:
        scoped = scoped_env((OWNER_A, TOKEN_A))
        with client_with(REGISTER_SCOPED_KEYS=scoped) as client, self.replaying():
            response = post(client)
        self.assertEqual(response.status_code, 401)
        self.assertNotIn("replayed", response.get_data(as_text=True))

    def test_replay_is_not_served_across_owners(self) -> None:
        scoped = scoped_env((OWNER_A, TOKEN_A), (OWNER_B, TOKEN_B))
        with client_with(REGISTER_SCOPED_KEYS=scoped) as client, self.replaying():
            # Owner B replays owner A's exact body.
            response = post(client, payload(sourceAddress=OWNER_A), token=TOKEN_B)
        self.assertEqual(response.status_code, 403)
        self.assertNotIn("replayed", response.get_data(as_text=True))

    def test_replay_still_works_for_the_authorized_owner(self) -> None:
        scoped = scoped_env((OWNER_A, TOKEN_A))
        with client_with(REGISTER_SCOPED_KEYS=scoped) as client, self.replaying():
            response = post(client, token=TOKEN_A)
        self.assertEqual(response.status_code, 201)
        self.assertTrue(response.get_json()["replayed"])


class PrivacyAndConfigTest(unittest.TestCase):
    def test_rejections_log_reason_codes_only(self) -> None:
        scoped = scoped_env((OWNER_A, TOKEN_A))
        with client_with(REGISTER_SCOPED_KEYS=scoped) as client, self.assertLogs(
            "harpocrates.requests", level=logging.WARNING
        ) as logs:
            post(client, token="a-guess-that-must-not-be-logged")
            post(client, payload(sourceAddress=OWNER_B), token=TOKEN_A)
            post(client)
        text = "\n".join(logs.output)
        for reason in ("invalid", "scope_mismatch", "missing"):
            self.assertIn(f'"reason":"{reason}"', text)
        for secret in ("a-guess-that-must-not-be-logged", TOKEN_A, hexdigest(TOKEN_A), OWNER_A, OWNER_B):
            self.assertNotIn(secret, text)

    def test_invalid_scoped_key_config_fails_startup_without_leaking_it(self) -> None:
        raw = f"{OWNER_A}:{'g' * 64}"
        with self.assertRaises(RuntimeError) as caught:
            with client_with(REGISTER_SCOPED_KEYS=raw):
                pass
        self.assertNotIn(OWNER_A, str(caught.exception))

    def test_invalid_expiry_config_fails_startup(self) -> None:
        with self.assertRaisesRegex(RuntimeError, "REGISTER_API_KEY_EXPIRES"):
            with client_with(REGISTER_API_KEY=LEGACY_TOKEN, REGISTER_API_KEY_EXPIRES="tomorrow"):
                pass

    def test_naive_expiry_is_treated_as_utc(self) -> None:
        with client_with(REGISTER_API_KEY=LEGACY_TOKEN, REGISTER_API_KEY_EXPIRES="2099-01-01T00:00:00"):
            from config import load_config

            expires = load_config().register_api_key_expires
        self.assertEqual(expires, datetime(2099, 1, 1, tzinfo=timezone.utc))


if __name__ == "__main__":
    unittest.main()
