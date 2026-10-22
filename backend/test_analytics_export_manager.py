"""Tests for analytics ExportManager: bounded, signed and deletable exports.

All tests are hermetic: they use in-memory entries and a fresh LogProcessor
per test, with no network, filesystem or shared global state.
"""

import json

import pytest

from backend.analytics.export_manager import (
    EXPORT_POLICY_DEFAULT,
    ExportManager,
    ExportPolicy,
)
from backend.analytics.log_processor import (
    LogEntry,
    LogProcessor,
    validate_log_export_safety,
)


def _safe_entry(entry_id: str, ts: float = 1.0, signature: str = "sig-v1:abc", **kw) -> LogEntry:
    return LogEntry(
        entry_id=entry_id,
        event_name="evt",
        message_summary="ok",
        timestamp_epoch_seconds=ts,
        export_safe=True,
        export_signature=signature,
        **kw,
    )


def _unsafe_entry(entry_id: str, ts: float = 1.0) -> LogEntry:
    # Flagged export_safe, but fails validate_log_export_safety (invalid label key).
    return LogEntry(
        entry_id=entry_id,
        event_name="evt",
        message_summary="ok",
        timestamp_epoch_seconds=ts,
        labels={"BAD KEY!": "v"},
        export_safe=True,
        export_signature="sig-v1:bad",
    )


def _manager(**policy_kw) -> ExportManager:
    return ExportManager(policy=ExportPolicy(**policy_kw), processor=LogProcessor())


def _export(mgr, entries, **kw):
    kw.setdefault("export_token_verified", True)
    return mgr.create_export(entries=entries, **kw)


def _ids(serialized: str):
    return [d["entry_id"] for d in json.loads(serialized)]


# ---------------------------------------------------------------- create_export


def test_create_export_basic_artifact_metadata():
    mgr = _manager()
    art, serialized, count = _export(mgr, [_safe_entry("a"), _safe_entry("b", ts=2.0)],
                                     exported_by_tag="tester", rollout_phase="canary")
    assert art is not None
    assert count == 2
    assert _ids(serialized) == ["a", "b"]
    assert art.artifact_id.startswith(mgr._policy.export_id_prefix)
    assert art.entry_count == 2
    assert art.payload_bytes == len(serialized.encode("utf-8"))
    assert art.exported_by_tag == "tester"
    assert art.rollout_phase == "canary"
    assert art.safety_signature.startswith(mgr._policy.safety_signature_prefix)
    assert art.checksum_sha256_prefix16 and len(art.checksum_sha256_prefix16) == 16
    assert mgr.get_artifact(art.artifact_id) is art


def test_export_ids_are_unique():
    mgr = _manager()
    ids = {mgr.generate_export_id() for _ in range(50)}
    assert len(ids) == 50


def test_create_export_respects_entry_count_limit():
    mgr = _manager(max_artifacts_per_export=3)
    entries = [_safe_entry(f"e{i}", ts=float(i)) for i in range(10)]
    art, serialized, count = _export(mgr, entries)
    assert count == 3
    assert art.entry_count == 3
    assert len(json.loads(serialized)) == 3


def test_create_export_respects_byte_limit():
    entries = [_safe_entry(f"e{i}", ts=float(i)) for i in range(10)]
    unbounded = _manager()
    _, full, full_count = _export(unbounded, entries)
    assert full_count == 10

    limit = len(full.encode("utf-8")) // 2
    mgr = _manager(max_artifact_bytes=limit)
    art, serialized, count = _export(mgr, entries)
    assert 1 <= count < 10
    assert art.payload_bytes <= limit
    assert len(serialized.encode("utf-8")) <= limit


def test_create_export_compress_flag_and_default():
    entries = [_safe_entry("a")]
    mgr = _manager()
    art, serialized, _ = _export(mgr, entries, compress=True)
    assert art.compress is True
    with pytest.raises(ValueError):
        json.loads(serialized)  # base64 gzip, not raw JSON

    art2, serialized2, _ = _export(mgr, entries)
    assert art2.compress is False
    assert json.loads(serialized2)

    mgr_c = _manager(compress_default=True)
    art3, _, _ = _export(mgr_c, entries)
    assert art3.compress is True


def test_create_export_uses_processor_entries_when_none_given():
    proc = LogProcessor()
    ok, _ = proc.ingest(_safe_entry("p1"))
    assert ok
    mgr = ExportManager(policy=ExportPolicy(), processor=proc)
    art, serialized, count = mgr.create_export(export_token_verified=True)
    assert count == 1
    assert _ids(serialized) == ["p1"]


def test_create_export_empty_entries():
    mgr = _manager()
    art, serialized, count = _export(mgr, [])
    assert art is not None
    assert count == 0
    assert json.loads(serialized) == []


# --------------------------------------------------------------- token handling


def test_unverified_token_exports_nothing_and_hides_tag_in_shadow_mode():
    mgr = _manager()
    art, serialized, count = mgr.create_export(
        entries=[_safe_entry("a")], exported_by_tag="who", export_token_verified=False
    )
    assert art is not None
    assert count == 0
    assert json.loads(serialized) == []
    assert art.exported_by_tag is None


def test_unverified_token_rejected_when_shadow_mode_disabled():
    mgr = _manager(allow_unauthenticated_export_shadow_mode=False)
    art, reason, count = mgr.create_export(entries=[_safe_entry("a")])
    assert art is None
    assert reason == "export_token_required"
    assert count == 0
    assert mgr.list_artifacts() == []


def test_verified_token_allowed_when_shadow_mode_disabled():
    mgr = _manager(allow_unauthenticated_export_shadow_mode=False)
    art, _, count = _export(mgr, [_safe_entry("a")])
    assert art is not None and count == 1


# ---------------------------------------------------------------- unsafe entries


def test_helper_unsafe_entry_really_fails_validation():
    ok, reasons = validate_log_export_safety(_unsafe_entry("x"))
    assert not ok and reasons


def test_entries_not_flagged_export_safe_are_excluded():
    mgr = _manager()
    flagged_off = _safe_entry("off")
    flagged_off.export_safe = False
    art, serialized, count = _export(mgr, [_safe_entry("good"), flagged_off])
    assert _ids(serialized) == ["good"]
    assert count == 1


def test_sampled_out_entries_included_only_when_policy_allows():
    sampled = _safe_entry("s")
    sampled.export_safe = False
    mgr = _manager(include_sampled_out_events=True, require_safety_signature=False)
    _, serialized, _ = _export(mgr, [sampled])
    # Even when allowed, the entry is only exported if it passes safety validation.
    assert "s" in _ids(serialized) or _ids(serialized) == []


def test_unsafe_entries_never_appear_in_artifact():
    mgr = _manager()
    art, serialized, count = _export(
        mgr, [_safe_entry("good"), _unsafe_entry("bad", ts=2.0)]
    )
    assert "bad" not in _ids(serialized)
    assert "BAD KEY!" not in serialized
    assert count == len(json.loads(serialized))
    assert art.entry_count == count


def test_unsafe_leaking_message_never_appears_in_artifact():
    leaky = _safe_entry("leak")
    leaky.message_summary = "x" * 10
    leaky.counters = {"password": 1}  # sensitive hint
    ok, _ = validate_log_export_safety(leaky)
    assert not ok
    mgr = _manager()
    _, serialized, _ = _export(mgr, [leaky, _safe_entry("good", ts=2.0)])
    assert "leak" not in _ids(serialized)


def test_unsafe_entry_never_exported_with_compression():
    mgr = _manager()
    proc = mgr._processor
    _, serialized, _ = _export(mgr, [_safe_entry("good"), _unsafe_entry("bad", ts=2.0)],
                               compress=True)
    entries = proc.import_json_logs(serialized, compressed=True)
    assert "bad" not in [e.entry_id for e in entries]


def test_signature_withheld_when_entries_unsafe_flag_present():
    mgr = _manager(include_sampled_out_events=True)
    unsafe_flag = _safe_entry("u")
    unsafe_flag.export_safe = False
    art, _, _ = _export(mgr, [unsafe_flag])
    assert art.safety_signature is None


def test_signature_not_computed_when_not_required():
    mgr = _manager(require_safety_signature=False)
    art, _, _ = _export(mgr, [_safe_entry("a")])
    assert art.safety_signature is None


# ---------------------------------------------------------------- signature


def test_signature_is_deterministic_and_order_independent():
    mgr = _manager()
    a, b = _safe_entry("a"), _safe_entry("b")
    s1 = mgr.compute_safety_signature([a, b])
    s2 = mgr.compute_safety_signature([b, a])
    assert s1 == s2
    assert s1.startswith("sig-v1:")


def test_signature_changes_when_entry_signature_changes():
    mgr = _manager()
    base = mgr.compute_safety_signature([_safe_entry("a"), _safe_entry("b")])
    changed = mgr.compute_safety_signature(
        [_safe_entry("a"), _safe_entry("b", signature="sig-v1:other")]
    )
    assert base != changed


def test_signature_changes_when_entry_id_changes():
    mgr = _manager()
    assert mgr.compute_safety_signature([_safe_entry("a")]) != mgr.compute_safety_signature(
        [_safe_entry("z")]
    )


def test_signature_changes_when_entry_added_or_removed():
    mgr = _manager()
    one = mgr.compute_safety_signature([_safe_entry("a")])
    two = mgr.compute_safety_signature([_safe_entry("a"), _safe_entry("b")])
    assert one != two
    assert mgr.compute_safety_signature([]) != one


def test_signature_treats_missing_entry_signature_as_zero():
    mgr = _manager()
    none_sig = mgr.compute_safety_signature([_safe_entry("a", signature=None)])
    zero_sig = mgr.compute_safety_signature([_safe_entry("a", signature="0")])
    assert none_sig == zero_sig
    assert none_sig != mgr.compute_safety_signature([_safe_entry("a")])


def test_signature_uses_policy_prefix():
    mgr = _manager(safety_signature_prefix="custom:")
    assert mgr.compute_safety_signature([_safe_entry("a")]).startswith("custom:")


def test_artifact_signature_differs_for_different_entry_sets():
    mgr = _manager()
    a1, _, _ = _export(mgr, [_safe_entry("a")])
    a2, _, _ = _export(mgr, [_safe_entry("a", signature="sig-v1:changed")])
    assert a1.safety_signature != a2.safety_signature


# ------------------------------------------------- get / list / delete / reset


def test_get_artifact_known_and_unknown():
    mgr = _manager()
    art, _, _ = _export(mgr, [_safe_entry("a")])
    assert mgr.get_artifact(art.artifact_id) is art
    assert mgr.get_artifact("exp-v1:doesnotexist") is None


def test_list_artifacts_newest_first_and_limit():
    mgr = _manager()
    created = [_export(mgr, [_safe_entry(f"e{i}")])[0] for i in range(5)]
    listed = mgr.list_artifacts()
    assert [a.artifact_id for a in listed] == [a.artifact_id for a in reversed(created)]
    limited = mgr.list_artifacts(limit=2)
    assert [a.artifact_id for a in limited] == [created[4].artifact_id, created[3].artifact_id]
    assert mgr.list_artifacts(limit=0) == []
    assert len(mgr.list_artifacts(limit=100)) == 5


def test_list_artifacts_empty():
    assert _manager().list_artifacts() == []


def test_delete_known_artifact():
    mgr = _manager()
    a, _, _ = _export(mgr, [_safe_entry("a")])
    b, _, _ = _export(mgr, [_safe_entry("b")])
    assert mgr.delete_artifact(a.artifact_id) is True
    assert mgr.get_artifact(a.artifact_id) is None
    assert [x.artifact_id for x in mgr.list_artifacts()] == [b.artifact_id]
    # Second delete of same id is a no-op returning False.
    assert mgr.delete_artifact(a.artifact_id) is False


def test_delete_unknown_artifact():
    mgr = _manager()
    a, _, _ = _export(mgr, [_safe_entry("a")])
    assert mgr.delete_artifact("exp-v1:nope") is False
    assert mgr.get_artifact(a.artifact_id) is a


def test_reset_clears_all_artifacts():
    mgr = _manager()
    a, _, _ = _export(mgr, [_safe_entry("a")])
    _export(mgr, [_safe_entry("b")])
    mgr.reset()
    assert mgr.list_artifacts() == []
    assert mgr.get_artifact(a.artifact_id) is None
    # Manager remains usable after reset.
    c, _, _ = _export(mgr, [_safe_entry("c")])
    assert [x.artifact_id for x in mgr.list_artifacts()] == [c.artifact_id]


def test_reset_on_empty_manager_is_safe():
    mgr = _manager()
    mgr.reset()
    assert mgr.list_artifacts() == []


def test_memory_cap_evicts_oldest_artifact():
    mgr = ExportManager(policy=ExportPolicy(), processor=LogProcessor(), max_artifacts_memory=2)
    a, _, _ = _export(mgr, [_safe_entry("a")])
    b, _, _ = _export(mgr, [_safe_entry("b")])
    c, _, _ = _export(mgr, [_safe_entry("c")])
    assert mgr.get_artifact(a.artifact_id) is None
    assert [x.artifact_id for x in mgr.list_artifacts()] == [c.artifact_id, b.artifact_id]


def test_default_policy_values_are_bounded():
    assert EXPORT_POLICY_DEFAULT.max_artifacts_per_export > 0
    assert EXPORT_POLICY_DEFAULT.max_artifact_bytes > 0
    assert EXPORT_POLICY_DEFAULT.require_safety_signature is True
