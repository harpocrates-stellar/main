"""Analytics export completion receipts (issue #1123).

Hermetic: in-memory entries, a fresh LogProcessor per test, no network,
filesystem or shared global state.
"""

import dataclasses
import hashlib
import json
from types import SimpleNamespace

import pytest
from analytics.analytics_engine import AnalyticsEngine
from analytics.config import AnalyticsConfig
from analytics.consent import CONSENT_SCHEMA_VERSION
from analytics.export_manager import (
    EXPORT_RECEIPT_VERSION,
    ExportManager,
    ExportPolicy,
    export_policy_revision,
)
from analytics.log_processor import LogEntry, LogProcessor

RECEIPT_KEYS = {
    "receipt_version",
    "artifact_id",
    "completed_at_epoch_seconds",
    "scope",
    "policy_revision",
    "consent_policy_revision",
    "consent_schema_version",
    "redaction_version",
    "format_version",
    "output_digest",
    "payload_bytes",
}
SCOPE_KEYS = {
    "entry_source",
    "requested_max_entries",
    "candidate_count",
    "exported_count",
    "max_entries",
    "max_bytes",
    "include_sampled_out_events",
    "export_token_verified",
    "compress",
    "rollout_phase",
}

# Distinctive private values carried by the exported events.
PRIVATE_VALUES = (
    "entry-private-7f3a",
    "acct-tag-91c2",
    "sess-tag-55de",
    "corr-tag-0b1e",
    "checkout_started_private",
    "summary mentions order 4417",
    "label-value-zz9",
)


def _entry(entry_id: str, ts: float = 1.0, **kw) -> LogEntry:
    kw.setdefault("event_name", "evt")
    kw.setdefault("message_summary", "ok")
    return LogEntry(
        entry_id=entry_id,
        timestamp_epoch_seconds=ts,
        export_safe=True,
        export_signature="sig-v1:abc",
        **kw,
    )


def _private_entry() -> LogEntry:
    return _entry(
        PRIVATE_VALUES[0],
        account_id_tag=PRIVATE_VALUES[1],
        session_id_tag=PRIVATE_VALUES[2],
        correlation_id_tag=PRIVATE_VALUES[3],
        event_name=PRIVATE_VALUES[4],
        message_summary=PRIVATE_VALUES[5],
        labels={"category": PRIVATE_VALUES[6]},
        counters={"items": 3},
    )


def _manager(**policy_kw) -> ExportManager:
    return ExportManager(policy=ExportPolicy(**policy_kw), processor=LogProcessor())


def _export(mgr, entries, **kw):
    kw.setdefault("export_token_verified", True)
    return mgr.create_export(entries=entries, **kw)


# --------------------------------------------------------------- recorded data


def test_receipt_records_scope_policy_revision_and_output_digest():
    mgr = _manager(max_artifacts_per_export=2)
    entries = [_entry("a"), _entry("b", ts=2.0), _entry("c", ts=3.0)]
    art, serialized, count = _export(mgr, entries, rollout_phase="canary")

    receipt = art.receipt
    assert set(receipt) == RECEIPT_KEYS
    assert set(receipt["scope"]) == SCOPE_KEYS
    assert receipt["receipt_version"] == EXPORT_RECEIPT_VERSION
    assert receipt["artifact_id"] == art.artifact_id
    assert receipt["completed_at_epoch_seconds"] == art.generated_at_epoch_seconds
    assert receipt["scope"] == {
        "entry_source": "explicit",
        "requested_max_entries": None,
        "candidate_count": 3,
        "exported_count": 2,
        "max_entries": 2,
        "max_bytes": mgr._policy.max_artifact_bytes,
        "include_sampled_out_events": False,
        "export_token_verified": True,
        "compress": False,
        "rollout_phase": "canary",
    }
    assert receipt["policy_revision"] == export_policy_revision(mgr._policy)
    assert receipt["consent_schema_version"] == CONSENT_SCHEMA_VERSION
    assert receipt["redaction_version"] == art.redaction_version
    assert receipt["format_version"] == art.schema_version
    assert receipt["payload_bytes"] == len(serialized.encode("utf-8"))
    assert count == 2


@pytest.mark.parametrize(
    ("include_revision", "expected_revision"),
    [(True, "consent-policy-v7"), (False, None)],
)
def test_receipt_records_the_configured_collection_consent_revision(
    include_revision, expected_revision
):
    config = AnalyticsConfig(consent_policy_revision="consent-policy-v7")
    config.export.include_consent_policy_revision = include_revision
    engine = AnalyticsEngine(config=config)
    entry = engine.log_processor.sanitize_error_context(ValueError("safe error"))

    art, _, _ = _export(_manager(), [entry])

    assert entry.consent_policy_revision == expected_revision
    assert art.receipt["consent_policy_revision"] == expected_revision


def test_receipt_revision_only_covers_entries_kept_by_the_entry_limit():
    mgr = _manager(max_artifacts_per_export=1)
    entries = [
        _entry("first", ts=1.0, consent_policy_revision="rev-a"),
        _entry("second", ts=2.0, consent_policy_revision="rev-b"),
    ]

    art, serialized, count = _export(mgr, entries)

    assert count == 1
    assert "rev-b" not in serialized
    assert art.consent_policy_revision == "rev-a"
    assert art.receipt["consent_policy_revision"] == "rev-a"


def test_receipt_revision_only_covers_entries_kept_by_the_byte_limit():
    first = _entry("first", ts=1.0, consent_policy_revision="rev-a")
    second = _entry("second", ts=2.0, consent_policy_revision="rev-b")
    _, single_entry_payload, _ = _export(_manager(), [first])
    mgr = _manager(max_artifact_bytes=len(single_entry_payload.encode("utf-8")))

    art, serialized, count = _export(mgr, [first, second])

    assert count == 1
    assert "rev-b" not in serialized
    assert art.consent_policy_revision == "rev-a"
    assert art.receipt["consent_policy_revision"] == "rev-a"


def test_output_digest_matches_the_exported_output():
    mgr = _manager()
    art, serialized, _ = _export(mgr, [_entry("a"), _entry("b", ts=2.0)])

    expected = hashlib.sha256(serialized.encode("utf-8")).hexdigest()
    assert art.receipt["output_digest"] == "sha256:" + expected
    # Consistent with the existing short checksum.
    assert expected.startswith(art.checksum_sha256_prefix16)


def test_output_digest_covers_the_compressed_output_as_returned():
    mgr = _manager()
    art, serialized, _ = _export(mgr, [_entry("a")], compress=True)

    assert art.receipt["scope"]["compress"] is True
    assert art.receipt["output_digest"] == "sha256:" + hashlib.sha256(serialized.encode("utf-8")).hexdigest()


def test_digest_changes_when_the_output_changes():
    mgr = _manager()
    first, _, _ = _export(mgr, [_entry("a")])
    second, _, _ = _export(mgr, [_entry("b")])

    assert first.receipt["output_digest"] != second.receipt["output_digest"]


def test_processor_entries_are_reported_as_the_selected_source():
    processor = LogProcessor()
    processor._entries.extend([_entry("a"), _entry("b", ts=2.0)])
    mgr = ExportManager(policy=ExportPolicy(), processor=processor)

    art, _, _ = mgr.create_export(entries=None, export_token_verified=True)

    assert art.receipt["scope"]["entry_source"] == "processor"
    assert art.receipt["scope"]["candidate_count"] == 2


def test_requested_limit_is_recorded_as_part_of_the_selected_scope():
    mgr = _manager()
    art, _, _ = _export(mgr, [_entry("a")], requested_max_entries=5)
    assert art.receipt["scope"]["requested_max_entries"] == 5

    for invalid in (True, "5", 2.5):
        art, _, _ = _export(mgr, [_entry("a")], requested_max_entries=invalid)
        assert art.receipt["scope"]["requested_max_entries"] is None


# ------------------------------------------------------------- policy revision


def test_policy_revision_is_stable_for_equal_settings():
    assert export_policy_revision(ExportPolicy()) == export_policy_revision(ExportPolicy())


@pytest.mark.parametrize(
    "change",
    [
        {"max_artifacts_per_export": 63},
        {"include_sampled_out_events": True},
        {"compress_default": True},
        {"require_safety_signature": False},
    ],
)
def test_policy_revision_changes_when_any_setting_changes(change):
    assert export_policy_revision(ExportPolicy(**change)) != export_policy_revision(ExportPolicy())


def test_duck_typed_policy_still_exports_with_a_revision():
    policy = SimpleNamespace(**dataclasses.asdict(ExportPolicy()))
    mgr = ExportManager(policy=policy, processor=LogProcessor())

    art, _, count = _export(mgr, [_entry("a")])

    assert count == 1
    assert art.receipt["policy_revision"].startswith("pol-v1:")
    assert art.receipt["policy_revision"] == export_policy_revision(ExportPolicy())


def test_receipts_from_different_policies_carry_different_revisions():
    strict, _, _ = _export(_manager(), [_entry("a")])
    relaxed, _, _ = _export(_manager(include_sampled_out_events=True), [_entry("a")])

    assert strict.receipt["policy_revision"] != relaxed.receipt["policy_revision"]
    assert relaxed.receipt["scope"]["include_sampled_out_events"] is True


# --------------------------------------------------------------------- privacy


def test_receipt_never_contains_raw_private_events():
    mgr = _manager()
    art, serialized, count = _export(mgr, [_private_entry(), _entry("plain", ts=2.0)])

    # The export itself carries the private event...
    assert count == 2
    assert PRIVATE_VALUES[1] in serialized
    # ...but its receipt holds none of its values or fields.
    blob = json.dumps(art.receipt, sort_keys=True)
    for value in PRIVATE_VALUES:
        assert value not in blob
    for field_name in ("entry_id", "account_id_tag", "session_id_tag", "message_summary", "labels"):
        assert field_name not in blob


def test_receipt_holds_no_private_data_even_for_compressed_exports():
    mgr = _manager()
    art, serialized, _ = _export(mgr, [_private_entry()], compress=True)

    blob = json.dumps(art.receipt, sort_keys=True)
    for value in PRIVATE_VALUES:
        assert value not in blob
    # The digest is a fixed-size hash, not an encoding of the output.
    assert len(art.receipt["output_digest"]) == len("sha256:") + 64
    assert serialized not in blob


# ------------------------------------------------------ failure / boundary cases


@pytest.mark.parametrize("candidate_count", [0, 1, 4])
def test_unverified_shadow_receipt_does_not_reveal_candidate_data(candidate_count):
    mgr = _manager()
    entries = [
        _entry(str(index), consent_policy_revision=f"consent-policy-{index}")
        for index in range(candidate_count)
    ]
    art, serialized, count = mgr.create_export(entries=entries, export_token_verified=False)

    assert count == 0
    scope = art.receipt["scope"]
    assert (scope["candidate_count"], scope["exported_count"], scope["export_token_verified"]) == (None, 0, False)
    assert art.receipt["consent_policy_revision"] is None
    assert art.receipt["output_digest"] == "sha256:" + hashlib.sha256(serialized.encode("utf-8")).hexdigest()
    blob = json.dumps(art.receipt)
    for entry in entries:
        assert entry.consent_policy_revision not in blob


def test_rejected_export_produces_no_receipt():
    mgr = _manager(allow_unauthenticated_export_shadow_mode=False)
    art, serialized, count = mgr.create_export(entries=[_entry("a")], export_token_verified=False)

    assert (art, serialized, count) == (None, "export_token_required", 0)
    assert mgr.list_artifacts() == []


def test_empty_export_receipt():
    mgr = _manager()
    art, serialized, count = _export(mgr, [])

    assert count == 0
    assert art.receipt["scope"]["candidate_count"] == 0
    assert art.receipt["scope"]["exported_count"] == 0
    assert art.receipt["output_digest"] == "sha256:" + hashlib.sha256(serialized.encode("utf-8")).hexdigest()


def test_excluded_unsafe_entries_are_only_counted():
    mgr = _manager()
    unsafe = LogEntry(
        entry_id="unsafe-entry-x1",
        event_name="evt",
        message_summary="ok",
        timestamp_epoch_seconds=1.0,
        export_safe=False,
    )
    art, _, count = _export(mgr, [unsafe, _entry("a")])

    assert count == 1
    assert (art.receipt["scope"]["candidate_count"], art.receipt["scope"]["exported_count"]) == (2, 1)
    assert "unsafe-entry-x1" not in json.dumps(art.receipt)


def test_receipt_is_kept_with_the_stored_artifact():
    mgr = _manager()
    art, _, _ = _export(mgr, [_entry("a")])

    assert mgr.get_artifact(art.artifact_id).receipt == art.receipt


# ---------------------------------------------------------------------- routes


def _client(processor_entries):
    flask = pytest.importorskip("flask")
    from analytics.routes import register_analytics_routes

    processor = LogProcessor()
    processor._entries.extend(processor_entries)
    engine = SimpleNamespace(
        export_mgr=ExportManager(policy=ExportPolicy(), processor=processor),
        log_processor=processor,
        config=None,
    )
    app = flask.Flask("receipts-test")
    register_analytics_routes(
        app,
        engine=engine,
        enable_health_endpoints=False,
        enable_safety_signal_endpoints=False,
    )
    return app.test_client()


def test_export_endpoints_return_the_receipt_without_private_values():
    client = _client([_private_entry()])

    created = client.post("/analytics/export", json={"export_token": "token-123456", "max_entries": 7})
    assert created.status_code == 200
    body = created.get_json()
    assert set(body["receipt"]) == RECEIPT_KEYS
    assert body["receipt"]["scope"]["requested_max_entries"] == 7
    assert body["receipt"]["artifact_id"] == body["artifact_id"]

    fetched = client.get(f"/analytics/export/{body['artifact_id']}")
    assert fetched.status_code == 200
    assert fetched.get_json()["receipt"] == body["receipt"]

    for response in (created, fetched):
        text = response.get_data(as_text=True)
        receipt_text = json.dumps(response.get_json()["receipt"])
        for value in PRIVATE_VALUES:
            assert value not in receipt_text
        assert PRIVATE_VALUES[1] not in text  # the endpoints never return the export body
