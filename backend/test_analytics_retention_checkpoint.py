"""Tests for bounded resumable analytics retention cleanup and audit references."""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

import pytest

_BACKEND_DIR = Path(__file__).resolve().parent
_REPO_ROOT = _BACKEND_DIR.parent
for _p in (str(_BACKEND_DIR), str(_REPO_ROOT)):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from analytics.consent import (
    ConsentDecision,
    ConsentManager,
    ConsentSource,
    ConsentStatus,
)
from analytics.export_manager import (
    CleanupPhase,
    ExportManager,
    ExportPolicy,
    RetentionCheckpoint,
    load_retention_checkpoint,
    save_retention_checkpoint,
)
from analytics.log_processor import LogEntry, LogProcessor


def _make_log_entry(entry_id: str, ts: float, summary: str = "safe summary") -> LogEntry:
    return LogEntry(
        entry_id=entry_id,
        event_name=f"evt_{entry_id}",
        message_summary=summary,
        timestamp_epoch_seconds=ts,
        export_safe=True,
        export_signature=f"sig-v1:{entry_id[:10]}",
    )


def _populate_fixture(now: float = 100_000.0) -> tuple[ConsentManager, LogProcessor, ExportManager]:
    cm = ConsentManager(grace_period_seconds=1_800.0)
    proc = LogProcessor()
    mgr = ExportManager(policy=ExportPolicy(), processor=proc, consent_manager=cm)

    # 8 aged terminal consent records + 4 active granted consent records
    for i in range(8):
        tag = f"secret_acct_old_{i:02d}"
        cm.withdraw_consent(tag)
        cm._consent_states[tag].last_modified_epoch_seconds = now - 5_000.0
        cm._consent_states[tag].consent_token = f"cst-v1:tok_{i:020d}"
    for i in range(4):
        tag = f"secret_acct_active_{i:02d}"
        cm.set_consent(
            tag,
            ConsentDecision(
                status=ConsentStatus.GRANTED,
                source=ConsentSource.USER_EXPLICIT,
                scope=["telemetry"],
                granted_at_epoch_seconds=now - 500.0,
                expires_at_epoch_seconds=now + 50_000.0,
            ),
        )

    # 7 expired log entries + 3 fresh log entries (ttl = 10_000 -> cutoff = 90_000)
    for i in range(7):
        ok, err = proc.ingest(
            _make_log_entry(f"oldlog{i:02d}", ts=now - 20_000.0 + i),
            allow_duplicate=True,
        )
        assert ok, err
    for i in range(3):
        ok, err = proc.ingest(
            _make_log_entry(f"freshlog{i:02d}", ts=now - 1_000.0 + i),
            allow_duplicate=True,
        )
        assert ok, err

    # 5 expired export artifacts + 2 fresh export artifacts
    for i in range(5):
        art, _, _ = mgr.create_export(
            entries=[_make_log_entry(f"artold{i}", ts=10.0)],
            exported_by_tag=f"sensitive_exporter_{i}",
            export_token_verified=True,
        )
        assert art is not None
        art.generated_at_epoch_seconds = now - 25_000.0 + i
    for i in range(2):
        art, _, _ = mgr.create_export(
            entries=[_make_log_entry(f"artnew{i}", ts=20.0)],
            exported_by_tag=f"fresh_exporter_{i}",
            export_token_verified=True,
        )
        assert art is not None
        art.generated_at_epoch_seconds = now - 500.0 + i

    return cm, proc, mgr


def test_bounded_batches_and_resume_until_completion(tmp_path: Path) -> None:
    now = 100_000.0
    cm, proc, mgr = _populate_fixture(now=now)
    cp_path = tmp_path / "retention_checkpoint.json"

    # Run 1: max_batches=2, batch_size=3 -> stops incomplete in CONSENT phase
    cp1 = mgr.run_retention_cleanup(
        now_epoch_seconds=now,
        retention_ttl_seconds=10_000.0,
        batch_size=3,
        max_batches=2,
        checkpoint_path=cp_path,
    )
    assert cp1.completed is False
    assert cp1.batches_completed == 2
    assert cp1.phase == CleanupPhase.CONSENT
    assert cp_path.is_file()

    # Loop bounded runs resuming exclusively from persisted checkpoint file
    runs = 1
    current = cp1
    while not current.completed:
        runs += 1
        assert runs <= 20
        current = mgr.run_retention_cleanup(
            now_epoch_seconds=now,
            retention_ttl_seconds=10_000.0,
            batch_size=3,
            max_batches=2,
            checkpoint_path=cp_path,
        )

    assert current.completed is True
    assert current.phase == CleanupPhase.COMPLETED
    assert current.consent_pruned_count == 8
    assert current.logs_deleted_count == 7
    assert current.artifacts_deleted_count == 5

    # Active/fresh data remains intact
    assert len(cm._consent_states) == 4
    assert [e.entry_id for e in proc._entries] == ["freshlog00", "freshlog01", "freshlog02"]
    assert len(mgr.list_artifacts()) == 2

    # Subsequent call on completed checkpoint is an idempotent no-op
    before_batches = current.batches_completed
    again = mgr.run_retention_cleanup(
        now_epoch_seconds=now,
        retention_ttl_seconds=10_000.0,
        batch_size=3,
        max_batches=2,
        checkpoint_path=cp_path,
    )
    assert again.completed is True
    assert again.batches_completed == before_batches


def test_interruption_via_callback_and_exception_preserves_progress_and_resumes(
    tmp_path: Path,
) -> None:
    now = 100_000.0
    cm, proc, mgr = _populate_fixture(now=now)
    cp_path = tmp_path / "interrupted_cp.json"

    # Cooperative interruption after 3 batches
    cp_coop = mgr.run_retention_cleanup(
        now_epoch_seconds=now,
        retention_ttl_seconds=10_000.0,
        batch_size=4,
        max_batches=20,
        checkpoint_path=cp_path,
        should_stop=lambda batch_idx, _cp: batch_idx >= 3,
    )
    assert cp_coop.completed is False
    assert cp_coop.batches_completed == 3
    assert cp_coop.interrupted_reason == "cooperative_stop"

    # Simulated sudden exception after 2 more batches
    def _boom_after_two(batch_idx: int, _cp: RetentionCheckpoint) -> bool:
        if batch_idx >= 2:
            raise RuntimeError("simulated worker sigterm with secret_path=/var/private")
        return False

    with pytest.raises(RuntimeError):
        mgr.run_retention_cleanup(
            now_epoch_seconds=now,
            retention_ttl_seconds=10_000.0,
            batch_size=4,
            max_batches=20,
            checkpoint_path=cp_path,
            should_stop=_boom_after_two,
        )

    persisted = load_retention_checkpoint(cp_path)
    assert persisted.completed is False
    assert persisted.batches_completed == 5
    # Exception reason records type name only, never raw exception message
    assert persisted.interrupted_reason == "exception:RuntimeError"
    assert "/var/private" not in cp_path.read_text(encoding="utf-8")

    # Final resume completes remaining work cleanly without double-counting
    final_cp = mgr.run_retention_cleanup(
        now_epoch_seconds=now,
        retention_ttl_seconds=10_000.0,
        batch_size=4,
        max_batches=20,
        checkpoint_path=cp_path,
    )
    assert final_cp.completed is True
    assert final_cp.interrupted_reason is None
    assert final_cp.consent_pruned_count == 8
    assert final_cp.logs_deleted_count == 7
    assert final_cp.artifacts_deleted_count == 5


def test_consent_and_deletion_audit_references_preserved_and_privacy_safe(
    tmp_path: Path,
) -> None:
    now = 100_000.0
    cm, _proc, mgr = _populate_fixture(now=now)
    cp_path = tmp_path / "audit_cp.json"

    cp = mgr.run_retention_cleanup(
        now_epoch_seconds=now,
        retention_ttl_seconds=10_000.0,
        batch_size=5,
        max_batches=50,
        checkpoint_path=cp_path,
    )
    assert cp.completed is True
    assert len(cp.consent_audit_ref_ids) == 8
    assert len(cp.deletion_audit_ref_ids) == 12  # 7 logs + 5 artifacts

    consent_refs = cm.list_consent_audit_references(limit=50)
    deletion_refs = mgr.list_deletion_audit_references(limit=50)
    assert len(consent_refs) == 8
    assert len(deletion_refs) == 12

    for ref_id in cp.consent_audit_ref_ids:
        ref = cm.get_consent_audit_reference(ref_id)
        assert ref is not None
        assert ref.terminal_status == ConsentStatus.WITHDRAWN
        assert len(ref.account_tag_digest) == 64
        assert "secret_acct" not in repr(ref)
        assert "cst-v1:" not in repr(ref)

    for ref_id in cp.deletion_audit_ref_ids:
        dref = mgr.get_deletion_audit_reference(ref_id)
        assert dref is not None
        assert dref.target_kind in {"log_entry", "export_artifact"}
        assert dref.reason == "retention_expired"
        assert len(dref.target_id_digest) == 64
        assert "oldlog" not in repr(dref)
        assert "sensitive_exporter" not in repr(dref)

    raw_cp_json = cp_path.read_text(encoding="utf-8")
    assert "sensitive_exporter" not in raw_cp_json
    assert "cst-v1:" not in raw_cp_json

    # Resetting export artifact cache preserves deletion audit references by default
    mgr.reset()
    assert len(mgr.list_deletion_audit_references(limit=50)) == 12


def test_checkpoint_validation_rejects_corrupted_or_invalid_inputs(tmp_path: Path) -> None:
    mgr = ExportManager(policy=ExportPolicy(), processor=LogProcessor())

    with pytest.raises(ValueError, match="batch_size"):
        mgr.run_retention_cleanup(batch_size=0)
    with pytest.raises(ValueError, match="max_batches"):
        mgr.run_retention_cleanup(max_batches=0)
    with pytest.raises(ValueError, match="retention_ttl_seconds"):
        mgr.run_retention_cleanup(retention_ttl_seconds=-1.0)

    bad_json = tmp_path / "corrupt.json"
    bad_json.write_text("{not-json", encoding="utf-8")
    with pytest.raises(ValueError, match="corrupted retention checkpoint"):
        load_retention_checkpoint(bad_json)

    bad_phase = tmp_path / "bad_phase.json"
    bad_phase.write_text(
        json.dumps(
            {
                "checkpoint_id": "rcp-v1:1234",
                "schema_version": "1.0.0",
                "phase": "unknown_phase",
                "batches_completed": 0,
                "consent_pruned_count": 0,
                "logs_deleted_count": 0,
                "artifacts_deleted_count": 0,
            }
        ),
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="phase"):
        load_retention_checkpoint(bad_phase)

    valid_cp = RetentionCheckpoint(checkpoint_id="rcp-v1:abcd1234")
    saved = save_retention_checkpoint(valid_cp, tmp_path / "ok.json")
    loaded = load_retention_checkpoint(saved)
    assert loaded.checkpoint_id == "rcp-v1:abcd1234"


def test_checkpoint_rejects_symlinks(tmp_path: Path) -> None:
    valid_cp = RetentionCheckpoint(checkpoint_id="rcp-v1:abcd1234")
    saved = save_retention_checkpoint(valid_cp, tmp_path / "ok.json")
    link_path = tmp_path / "symlink_cp.json"
    try:
        os.symlink(saved, link_path)
    except (OSError, NotImplementedError):
        pytest.skip("OS policy prevents unprivileged symlink creation")

    with pytest.raises(ValueError, match="symlink"):
        load_retention_checkpoint(link_path)
