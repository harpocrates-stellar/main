from __future__ import annotations

from datetime import datetime, timedelta, timezone
import os
from pathlib import Path
import sys

import pytest

_BACKEND_DIR = Path(__file__).resolve().parent
_REPO_ROOT = _BACKEND_DIR.parent
for _p in (str(_BACKEND_DIR), str(_REPO_ROOT)):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import db
import worker


@pytest.fixture(autouse=True)
def _isolated_jobs():
    saved = dict(db._JOBS)
    db._JOBS.clear()
    try:
        yield
    finally:
        db._JOBS.clear()
        db._JOBS.update(saved)


def test_build_recovery_plan_is_strictly_read_only_and_classifies_uncertainty(
    tmp_path: Path,
) -> None:
    fixed_now = datetime(2026, 11, 15, 12, 0, 0, tzinfo=timezone.utc)
    stale_iso = (fixed_now - timedelta(seconds=900)).isoformat()
    fresh_iso = (fixed_now - timedelta(seconds=20)).isoformat()
    stellar_seed = "S" + ("E" * 55)

    # 1. Safe-to-requeue abandoned embed lease in pre-commit stage
    j_safe = db.enqueue_job(
        "embed",
        {"filename": "private_evidence_name.mp4", "credential_secret": stellar_seed},
    )
    db._JOBS[j_safe].update(
        {
            "status": "running",
            "worker_id": "worker-dead-1",
            "leased_at": stale_iso,
            "heartbeat_at": stale_iso,
            "progress": {"phase": "embedding", "percent": 40.0},
        }
    )

    # 2. Uncertain abandoned lease interrupted during external DB recording phase
    j_recording = db.enqueue_job("embed", {"filename": "clip2.mp4"})
    db._JOBS[j_recording].update(
        {
            "status": "running",
            "worker_id": "worker-dead-2",
            "leased_at": stale_iso,
            "heartbeat_at": stale_iso,
            "progress": {"phase": "recording", "percent": None},
        }
    )

    # 3. Healthy active running lease (must NOT appear in abandoned leases)
    j_healthy = db.enqueue_job("silent_witness", {"video_hash": "aa" * 32})
    db._JOBS[j_healthy].update(
        {
            "status": "running",
            "worker_id": "worker-alive",
            "leased_at": fresh_iso,
            "heartbeat_at": fresh_iso,
            "progress": {"phase": "generating_proof", "percent": None},
        }
    )

    # 4. Pending job with intact input (input must NOT be flagged for deletion)
    j_pending = db.enqueue_job("extract", {"filename": "queued.mp4"})
    pending_in = tmp_path / f"job_{j_pending}_input"
    pending_in.write_bytes(b"valid-pending-input")

    # Partial output left by abandoned j_safe (old -> low uncertainty)
    partial_out_safe = tmp_path / f"job_{j_safe}_output"
    partial_out_safe.write_bytes(b"half-written-mp4")
    old_epoch = (fixed_now - timedelta(seconds=600)).timestamp()
    os.utime(partial_out_safe, (old_epoch, old_epoch))

    # Recently touched temp file on j_recording (recent -> uncertain active writer)
    recent_tmp = tmp_path / f"job_{j_recording}_output.part"
    recent_tmp.write_bytes(b"flushing")
    recent_epoch = (fixed_now - timedelta(seconds=10)).timestamp()
    os.utime(recent_tmp, (recent_epoch, recent_epoch))

    # Orphaned file with no job row (old -> uncertain_orphaned_without_job)
    orphan_file = tmp_path / "job_9999_output"
    orphan_file.write_bytes(b"orphan-bytes")
    os.utime(orphan_file, (old_epoch, old_epoch))

    jobs_before = {k: dict(v) for k, v in db._JOBS.items()}
    files_before = sorted(p.name for p in tmp_path.iterdir())

    plan = worker.build_worker_recovery_plan(
        storage_dir=tmp_path,
        now=fixed_now,
        lease_timeout_seconds=300.0,
        active_write_grace_seconds=60.0,
    )

    # Read-only invariant: zero job mutations and zero file deletions
    assert plan.read_only is True
    assert {k: dict(v) for k, v in db._JOBS.items()} == jobs_before
    assert sorted(p.name for p in tmp_path.iterdir()) == files_before

    # Privacy invariant: secrets and raw filenames never appear in serialized plan
    serialized = repr(plan.to_dict())
    assert stellar_seed not in serialized
    assert "private_evidence_name.mp4" not in serialized
    assert "job_9999_output" not in serialized

    lease_map = {f.job_id: f for f in plan.abandoned_leases}
    assert set(lease_map.keys()) == {j_safe, j_recording}
    assert j_healthy not in lease_map
    assert lease_map[j_safe].uncertainty == worker.UNCERTAINTY_LOW
    assert lease_map[j_safe].recommended_action == "requeue_job"
    assert lease_map[j_recording].uncertainty == worker.UNCERTAINTY_EXTERNAL_SIDE_EFFECT
    assert lease_map[j_recording].recommended_action == "inspect_before_requeue"

    art_by_job = {(f.job_id, f.artifact_role): f for f in plan.partial_artifacts}
    assert (j_safe, "output") in art_by_job
    assert art_by_job[(j_safe, "output")].uncertainty == worker.UNCERTAINTY_LOW
    assert (j_recording, "partial_temp") in art_by_job
    assert art_by_job[(j_recording, "partial_temp")].uncertainty == worker.UNCERTAINTY_ACTIVE_WRITER
    assert (9999, "output") in art_by_job
    assert art_by_job[(9999, "output")].uncertainty == worker.UNCERTAINTY_ORPHANED_ARTIFACT
    # Pending job's valid input was untouched and excluded from partial artifacts
    assert (j_pending, "input") not in art_by_job


def test_build_recovery_plan_does_not_create_missing_storage_directory(tmp_path: Path) -> None:
    nonexistent = tmp_path / "does_not_exist_yet"
    plan = worker.build_worker_recovery_plan(storage_dir=nonexistent)
    assert not nonexistent.exists()
    assert plan.abandoned_leases == ()
    assert plan.partial_artifacts == ()


def test_apply_selected_recovery_actions_enforces_bounds_and_uncertainty_gates(
    tmp_path: Path,
) -> None:
    fixed_now = datetime(2026, 11, 15, 12, 0, 0, tzinfo=timezone.utc)
    stale_iso = (fixed_now - timedelta(seconds=800)).isoformat()
    old_epoch = (fixed_now - timedelta(seconds=800)).timestamp()

    j1 = db.enqueue_job("embed", {})
    db._JOBS[j1].update({"status": "running", "worker_id": "w1", "heartbeat_at": stale_iso})
    f1 = tmp_path / f"job_{j1}_output"
    f1.write_bytes(b"partial-1")
    os.utime(f1, (old_epoch, old_epoch))

    j_uncertain = db.enqueue_job("verify_tx", {"tx_hash": "aa" * 32})
    db._JOBS[j_uncertain].update({"status": "running", "worker_id": "w2", "heartbeat_at": stale_iso})

    plan = worker.build_worker_recovery_plan(
        storage_dir=tmp_path,
        now=fixed_now,
        lease_timeout_seconds=300.0,
    )

    safe_lease_id = f"requeue_lease:{j1}"
    uncertain_lease_id = f"requeue_lease:{j_uncertain}"
    safe_art_id = plan.partial_artifacts[0].action_id

    # Reject empty, bare-string, wildcard, unknown, duplicate, and over-budget selections
    with pytest.raises(worker.RecoverySelectionError):
        worker.apply_selected_recovery_actions(plan, [])

    with pytest.raises(worker.RecoverySelectionError):
        worker.apply_selected_recovery_actions(plan, safe_lease_id)  # type: ignore[arg-type]

    with pytest.raises(worker.RecoverySelectionError):
        worker.apply_selected_recovery_actions(plan, ["*"])

    with pytest.raises(worker.RecoverySelectionError):
        worker.apply_selected_recovery_actions(plan, ["requeue_lease:999999"])

    with pytest.raises(worker.RecoverySelectionError):
        worker.apply_selected_recovery_actions(plan, [safe_lease_id, safe_lease_id])

    with pytest.raises(worker.RecoverySelectionError):
        worker.apply_selected_recovery_actions(plan, [safe_lease_id, safe_art_id], max_actions=1)

    # Selecting an uncertain action without allow_uncertain=True fails atomically before mutating safe items
    with pytest.raises(worker.RecoverySelectionError, match="uncertainty"):
        worker.apply_selected_recovery_actions(plan, [safe_lease_id, uncertain_lease_id])
    assert db.get_job(j1)["status"] == "running"
    assert f1.exists()

    # Apply ONLY bounded safe actions -> j1 requeued and f1 deleted, j_uncertain untouched!
    report = worker.apply_selected_recovery_actions(
        plan,
        [safe_lease_id, safe_art_id],
        storage_dir=tmp_path,
        max_actions=5,
    )
    assert report.requeued_jobs == 1
    assert report.removed_artifacts == 1
    assert report.applied_action_ids == (safe_lease_id, safe_art_id)
    assert db.get_job(j1)["status"] == "pending"
    assert "worker_id" not in db.get_job(j1)
    assert not f1.exists()
    assert db.get_job(j_uncertain)["status"] == "running"

    # Explicit operator override allows uncertain action when verified
    report_uncertain = worker.apply_selected_recovery_actions(
        plan,
        [uncertain_lease_id],
        allow_uncertain=True,
    )
    assert report_uncertain.requeued_jobs == 1
    assert db.get_job(j_uncertain)["status"] == "pending"


def test_max_findings_truncates_recovery_plan(tmp_path: Path) -> None:
    fixed_now = datetime(2026, 11, 15, 12, 0, 0, tzinfo=timezone.utc)
    stale_iso = (fixed_now - timedelta(seconds=900)).isoformat()
    for _ in range(5):
        jid = db.enqueue_job("embed", {})
        db._JOBS[jid].update({"status": "running", "worker_id": "w", "heartbeat_at": stale_iso})

    plan = worker.build_worker_recovery_plan(
        storage_dir=tmp_path,
        now=fixed_now,
        max_findings=3,
    )
    assert len(plan.abandoned_leases) == 3
    assert plan.truncated is True
