"""Focused tests: bounded registration conflict quarantine.

Verifies:
- Quarantine records are stored when a ConflictError is raised.
- Per-key cap is enforced (excess conflicts are silently dropped).
- Safe public identifiers are retained; private hash values are not.
- Tier enum value is stored only when tier is the conflicting field.
- Quarantine storage failures never propagate to the caller (409 is still returned).
- Expired records can be purged (purge_expired_conflicts).
- record_registration_conflict returns True on insert, False at cap.
- The 409 response body never contains private evidence metadata.

All tests use the in-memory stub (no DATABASE_URL required).
Synthetic fixtures only; no production credentials or live fund movement.
"""

from __future__ import annotations

import logging
from unittest.mock import patch

import pytest

from db import (
    ConflictError,
    _REGISTRATION_CONFLICTS,
    get_registration_conflicts,
    insert_registration_conflict,
    purge_expired_conflicts,
)
from registration_quarantine import (
    _safe_tier,
    quarantine_per_key_max,
    quarantine_ttl_days,
    record_registration_conflict,
)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

KEY_A = "a" * 64
KEY_B = "b" * 64
PROOF_1 = "11" * 32
VIDEO_1 = "22" * 32
TX_1 = "33" * 32
ADDR_1 = "GADMIN000000000000000000000000000000000000000000000000000"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _clear_quarantine() -> None:
    _REGISTRATION_CONFLICTS.clear()


def _make_conflict(
    *,
    idempotency_key: str = KEY_A,
    field: str = "metadata_hash",
    existing_value: object = "old" * 16,
    incoming_value: object = "new" * 16,
    proof_id: str | None = PROOF_1,
    video_hash: str | None = VIDEO_1,
    source_address: str | None = ADDR_1,
) -> ConflictError:
    exc = ConflictError(
        idempotency_key=idempotency_key,
        field=field,
        existing_value=existing_value,
        incoming_value=incoming_value,
    )
    exc._proof_id = proof_id  # type: ignore[attr-defined]
    exc._video_hash = video_hash  # type: ignore[attr-defined]
    exc._source_address = source_address  # type: ignore[attr-defined]
    return exc


# ---------------------------------------------------------------------------
# 1. insert_registration_conflict — basic storage
# ---------------------------------------------------------------------------


class TestInsertRegistrationConflict:
    def setup_method(self):
        _clear_quarantine()

    def test_stores_conflict_record_and_returns_true(self):
        stored = insert_registration_conflict(
            idempotency_key=KEY_A,
            conflict_field="metadata_hash",
            proof_id=PROOF_1,
            video_hash=VIDEO_1,
            source_address=ADDR_1,
            tx_hash=TX_1,
        )
        assert stored is True
        records = get_registration_conflicts(KEY_A)
        assert len(records) == 1
        assert records[0]["idempotency_key"] == KEY_A
        assert records[0]["conflict_field"] == "metadata_hash"
        assert records[0]["proof_id"] == PROOF_1
        assert records[0]["video_hash"] == VIDEO_1
        assert records[0]["source_address"] == ADDR_1
        assert records[0]["tx_hash"] == TX_1

    def test_returns_false_when_per_key_cap_reached(self):
        cap = 3
        for i in range(cap):
            stored = insert_registration_conflict(
                idempotency_key=KEY_A,
                conflict_field="tier",
                per_key_max=cap,
            )
            assert stored is True, f"insertion {i} should succeed"

        # Cap reached — next insert must be silently rejected
        overflow = insert_registration_conflict(
            idempotency_key=KEY_A,
            conflict_field="tier",
            per_key_max=cap,
        )
        assert overflow is False
        assert len(get_registration_conflicts(KEY_A)) == cap

    def test_cap_is_per_key_not_global(self):
        cap = 2
        insert_registration_conflict(idempotency_key=KEY_A, conflict_field="tier", per_key_max=cap)
        insert_registration_conflict(idempotency_key=KEY_A, conflict_field="tier", per_key_max=cap)
        # KEY_A is at cap; KEY_B should still accept insertions
        stored = insert_registration_conflict(idempotency_key=KEY_B, conflict_field="source_address", per_key_max=cap)
        assert stored is True
        assert len(get_registration_conflicts(KEY_A)) == cap
        assert len(get_registration_conflicts(KEY_B)) == 1

    def test_no_record_stored_for_unknown_key(self):
        records = get_registration_conflicts("nonexistent" * 4)
        assert records == []

    def test_tier_incoming_stored_when_tier_is_conflict_field(self):
        insert_registration_conflict(
            idempotency_key=KEY_A,
            conflict_field="tier",
            conflict_tier_incoming="seal",
        )
        records = get_registration_conflicts(KEY_A)
        assert records[0]["conflict_tier_incoming"] == "seal"

    def test_tier_incoming_none_when_other_field_conflicts(self):
        insert_registration_conflict(
            idempotency_key=KEY_A,
            conflict_field="metadata_hash",
            conflict_tier_incoming=None,
        )
        records = get_registration_conflicts(KEY_A)
        assert records[0]["conflict_tier_incoming"] is None

    def test_records_are_ordered_by_insertion(self):
        for field in ("tier", "source_address", "metadata_hash"):
            insert_registration_conflict(idempotency_key=KEY_A, conflict_field=field)
        records = get_registration_conflicts(KEY_A)
        assert [r["conflict_field"] for r in records] == ["tier", "source_address", "metadata_hash"]


# ---------------------------------------------------------------------------
# 2. record_registration_conflict — the public quarantine entry-point
# ---------------------------------------------------------------------------


class TestRecordRegistrationConflict:
    def setup_method(self):
        _clear_quarantine()

    def test_returns_true_on_first_conflict(self):
        exc = _make_conflict(field="metadata_hash")
        result = record_registration_conflict(exc, tx_hash=TX_1)
        assert result is True
        records = get_registration_conflicts(KEY_A)
        assert len(records) == 1

    def test_returns_false_at_cap(self):
        cap = 2
        with patch("registration_quarantine.quarantine_per_key_max", return_value=cap):
            exc = _make_conflict()
            record_registration_conflict(exc)
            record_registration_conflict(exc)
            result = record_registration_conflict(exc)
        assert result is False

    def test_proof_id_stored_when_not_the_conflicting_field(self):
        exc = _make_conflict(field="metadata_hash", proof_id=PROOF_1)
        record_registration_conflict(exc)
        records = get_registration_conflicts(KEY_A)
        assert records[0]["proof_id"] == PROOF_1

    def test_proof_id_not_stored_when_proof_id_is_conflicting_field(self):
        """When proof_id IS the conflicting field, we must not store the
        incoming proof_id value as a 'safe identifier' because it is the
        payload value under dispute."""
        exc = _make_conflict(field="proof_id", proof_id=PROOF_1)
        record_registration_conflict(exc)
        records = get_registration_conflicts(KEY_A)
        # proof_id must be None in the quarantine record
        assert records[0]["proof_id"] is None

    def test_video_hash_not_stored_when_video_hash_is_conflicting_field(self):
        exc = _make_conflict(field="video_hash", video_hash=VIDEO_1)
        record_registration_conflict(exc)
        records = get_registration_conflicts(KEY_A)
        assert records[0]["video_hash"] is None

    def test_source_address_not_stored_when_source_address_is_conflicting_field(self):
        exc = _make_conflict(field="source_address", source_address=ADDR_1)
        record_registration_conflict(exc)
        records = get_registration_conflicts(KEY_A)
        assert records[0]["source_address"] is None

    def test_conflict_field_name_always_stored(self):
        for field in ("metadata_hash", "tier", "source_address", "proof_id", "video_hash", "contract_id"):
            _clear_quarantine()
            exc = _make_conflict(field=field)
            record_registration_conflict(exc)
            records = get_registration_conflicts(KEY_A)
            assert records[0]["conflict_field"] == field

    def test_tier_incoming_stored_for_safe_tier_values(self):
        for tier in ("silent", "source", "seal"):
            _clear_quarantine()
            exc = _make_conflict(field="tier", incoming_value=tier)
            exc._proof_id = None  # type: ignore[attr-defined]
            exc._video_hash = None  # type: ignore[attr-defined]
            exc._source_address = None  # type: ignore[attr-defined]
            record_registration_conflict(exc)
            records = get_registration_conflicts(KEY_A)
            assert records[0]["conflict_tier_incoming"] == tier, f"tier={tier}"

    def test_tier_incoming_none_for_unknown_tier_value(self):
        exc = _make_conflict(field="tier", incoming_value="unknown_tier")
        record_registration_conflict(exc)
        records = get_registration_conflicts(KEY_A)
        assert records[0]["conflict_tier_incoming"] is None

    def test_storage_failure_does_not_propagate(self):
        """A database failure in quarantine storage must be swallowed so the
        caller's 409 response is unaffected."""
        exc = _make_conflict()
        with patch("registration_quarantine.insert_registration_conflict", side_effect=RuntimeError("db error")):
            result = record_registration_conflict(exc)
        assert result is False  # failure swallowed, False returned

    def test_no_private_metadata_in_stored_record(self):
        """Confirm that the stored record does not contain the raw
        existing_value or incoming_value from the ConflictError when the
        conflicting field is metadata_hash."""
        raw_hash = "ff" * 32
        exc = _make_conflict(
            field="metadata_hash",
            existing_value=raw_hash,
            incoming_value="ee" * 32,
        )
        record_registration_conflict(exc)
        records = get_registration_conflicts(KEY_A)
        record = records[0]
        # The raw hash values must not appear anywhere in the stored record
        record_values = [str(v) for v in record.values() if v is not None]
        for v in record_values:
            assert raw_hash not in v, (
                f"private hash value leaked into quarantine field value: {v}"
            )


# ---------------------------------------------------------------------------
# 3. purge_expired_conflicts — TTL-based cleanup
# ---------------------------------------------------------------------------


class TestPurgeExpiredConflicts:
    def setup_method(self):
        _clear_quarantine()

    def test_purge_is_noop_in_memory_stub(self):
        """The in-memory stub does not enforce TTL; purge returns 0."""
        insert_registration_conflict(idempotency_key=KEY_A, conflict_field="tier")
        deleted = purge_expired_conflicts()
        assert deleted == 0
        # Record still present
        assert len(get_registration_conflicts(KEY_A)) == 1


# ---------------------------------------------------------------------------
# 4. _safe_tier helper
# ---------------------------------------------------------------------------


class TestSafeTier:
    def test_returns_valid_tier_values(self):
        assert _safe_tier("silent") == "silent"
        assert _safe_tier("source") == "source"
        assert _safe_tier("seal") == "seal"

    def test_returns_none_for_unknown_strings(self):
        assert _safe_tier("admin") is None
        assert _safe_tier("") is None
        assert _safe_tier("SILENT") is None  # case-sensitive

    def test_returns_none_for_non_strings(self):
        assert _safe_tier(None) is None
        assert _safe_tier(1) is None
        assert _safe_tier(["silent"]) is None


# ---------------------------------------------------------------------------
# 5. Environment variable configuration
# ---------------------------------------------------------------------------


class TestEnvConfig:
    def test_default_per_key_max(self):
        with patch.dict("os.environ", {}, clear=False):
            # Remove the env var if set
            import os
            os.environ.pop("CONFLICT_QUARANTINE_PER_KEY_MAX", None)
            assert quarantine_per_key_max() == 10

    def test_custom_per_key_max(self):
        with patch.dict("os.environ", {"CONFLICT_QUARANTINE_PER_KEY_MAX": "5"}):
            assert quarantine_per_key_max() == 5

    def test_default_ttl_days(self):
        import os
        os.environ.pop("CONFLICT_QUARANTINE_TTL_DAYS", None)
        assert quarantine_ttl_days() == 30

    def test_custom_ttl_days(self):
        with patch.dict("os.environ", {"CONFLICT_QUARANTINE_TTL_DAYS": "7"}):
            assert quarantine_ttl_days() == 7

    def test_invalid_per_key_max_falls_back_to_default(self):
        with patch.dict("os.environ", {"CONFLICT_QUARANTINE_PER_KEY_MAX": "not_a_number"}):
            assert quarantine_per_key_max() == 10

    def test_zero_per_key_max_falls_back_to_default(self):
        with patch.dict("os.environ", {"CONFLICT_QUARANTINE_PER_KEY_MAX": "0"}):
            assert quarantine_per_key_max() == 10


# ---------------------------------------------------------------------------
# 6. Integration: ConflictError in register route quarantines without leaking
# ---------------------------------------------------------------------------


class TestRegisterRouteQuarantine:
    """End-to-end: the /api/proofs/register route quarantines the conflict
    and still returns 409 with only the conflict_field name — no raw hash
    values or metadata envelopes."""

    def setup_method(self):
        _clear_quarantine()

    def test_409_response_contains_only_conflict_field_name(self):
        import app as app_module

        client = app_module.app.test_client()

        with patch("app.upsert_register_event") as mock_upsert:
            mock_upsert.side_effect = ConflictError(
                idempotency_key=KEY_A,
                field="metadata_hash",
                existing_value="old" * 16,
                incoming_value="new" * 16,
            )
            response = client.post(
                "/api/proofs/register",
                json={
                    "videoHash": VIDEO_1,
                    "metadataHash": "aa" * 32,
                    "proofId": PROOF_1,
                    "txHash": TX_1,
                    "txStatus": "pending",
                    "tier": "silent",
                },
            )

        assert response.status_code == 409
        data = response.get_json()
        assert "conflict_field" in data
        assert data["conflict_field"] == "metadata_hash"
        # Private hash values must NOT appear in the response body
        assert "old" * 16 not in str(data)
        assert "new" * 16 not in str(data)
        # 'error' key should be present but no raw metadata
        assert "error" in data
        assert "metadata" not in data

    def test_409_response_does_not_include_existing_or_incoming_values(self):
        import app as app_module

        client = app_module.app.test_client()

        secret_existing = "se" * 32
        secret_incoming = "si" * 32

        with patch("app.upsert_register_event") as mock_upsert:
            mock_upsert.side_effect = ConflictError(
                idempotency_key=KEY_B,
                field="source_address",
                existing_value=secret_existing,
                incoming_value=secret_incoming,
            )
            response = client.post(
                "/api/proofs/register",
                json={
                    "videoHash": VIDEO_1,
                    "metadataHash": "aa" * 32,
                    "proofId": PROOF_1,
                    "txHash": TX_1,
                    "txStatus": "pending",
                    "tier": "silent",
                },
            )

        assert response.status_code == 409
        body_text = response.get_data(as_text=True)
        assert secret_existing not in body_text
        assert secret_incoming not in body_text

    def test_quarantine_record_stored_on_conflict(self):
        import app as app_module

        client = app_module.app.test_client()

        with patch("app.upsert_register_event") as mock_upsert, \
             patch("app.record_registration_conflict") as mock_quarantine:
            mock_upsert.side_effect = ConflictError(
                idempotency_key=KEY_A,
                field="tier",
                existing_value="silent",
                incoming_value="seal",
            )
            mock_quarantine.return_value = True

            response = client.post(
                "/api/proofs/register",
                json={
                    "videoHash": VIDEO_1,
                    "metadataHash": "aa" * 32,
                    "proofId": PROOF_1,
                    "tier": "silent",
                },
            )

        assert response.status_code == 409
        # Quarantine must have been called once
        assert mock_quarantine.call_count == 1

    def test_quarantine_storage_failure_still_returns_409(self):
        """If the quarantine call itself throws, the 409 must still be returned."""
        import app as app_module

        client = app_module.app.test_client()

        with patch("app.upsert_register_event") as mock_upsert, \
             patch("app.record_registration_conflict", side_effect=RuntimeError("quarantine down")):
            mock_upsert.side_effect = ConflictError(
                idempotency_key=KEY_A,
                field="metadata_hash",
                existing_value="old" * 16,
                incoming_value="new" * 16,
            )
            response = client.post(
                "/api/proofs/register",
                json={
                    "videoHash": VIDEO_1,
                    "metadataHash": "aa" * 32,
                    "proofId": PROOF_1,
                    "tier": "silent",
                },
            )

        assert response.status_code == 409
