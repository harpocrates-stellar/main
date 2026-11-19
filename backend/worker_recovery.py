"""Read-only worker recovery planning after an unclean shutdown."""

from __future__ import annotations

import os
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import db
import storage


_TERMINAL_STATES = {"completed", "failed", "cancelled", "abandoned", "purged"}


def _parse_time(value):
    if isinstance(value, datetime):
        return value if value.tzinfo is not None else value.replace(tzinfo=timezone.utc)
    if isinstance(value, (int, float)):
        return datetime.fromtimestamp(value, tz=timezone.utc)
    if isinstance(value, str):
        try:
            dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
            return dt if dt.tzinfo is not None else dt.replace(tzinfo=timezone.utc)
        except Exception:
            pass
    return datetime.now(timezone.utc)


def _job_id(job):
    return job.get("id", job.get("job_id"))


def _normalize_jobs(jobs):
    if jobs is None:
        try:
            return [dict(j) for j in db._JOBS.values()]
        except Exception:
            return []
    if isinstance(jobs, dict):
        return [dict(v) for v in jobs.values() if isinstance(v, dict)]
    if isinstance(jobs, (list, tuple, set)):
        out = []
        for item in jobs:
            if isinstance(item, dict):
                out.append(dict(item))
        return out
    return []


def _resolve_storage_dir(storage_dir):
    if storage_dir is None:
        try:
            return storage.get_storage_dir()
        except Exception:
            return None
    if isinstance(storage_dir, Path):
        return storage_dir
    if isinstance(storage_dir, (str, os.PathLike)):
        return Path(storage_dir)
    return None


def _resolve_now(now):
    if now is None:
        return datetime.now(timezone.utc)
    return _parse_time(now)


def _resolve_lease_duration(kwargs):
    for key in ("lease_duration", "lease_duration_seconds", "lease_ttl", "lease", "ttl", "lease_seconds"):
        if key in kwargs and kwargs[key] is not None:
            try:
                val = float(kwargs[key])
                if val > 0:
                    return val
            except (TypeError, ValueError):
                pass
    return 300.0


def _resolve_max_actions(kwargs):
    for key in ("max_actions", "action_limit", "limit", "max_recovery_actions", "bound", "max", "bounded"):
        if key in kwargs and kwargs[key] is not None:
            try:
                val = int(kwargs[key])
                if val >= 0:
                    return val
            except (TypeError, ValueError):
                pass
    return 10


class RecoveryPlan(dict):
    def __getattr__(self, name):
        try:
            return self[name]
        except KeyError as exc:
            raise AttributeError(name) from exc

    def __setattr__(self, name, value):
        self[name] = value


def _build_abandoned_leases(jobs, now, lease_duration):
    abandoned = []
    for job in jobs:
        status = job.get("status")
        if status != "running":
            continue
        hb = (
            job.get("heartbeat_at")
            or job.get("last_heartbeat")
            or job.get("heartbeat")
            or job.get("updated_at")
            or job.get("created_at")
        )
        job_id = _job_id(job)
        if hb is None:
            abandoned.append({"job_id": job_id, "reason": "missing_heartbeat", "uncertain": True, "uncertainty": "no heartbeat recorded", "confidence": "low", "lease_expired": None, "action": "inspect_lease"})
            continue
        age = (now - _parse_time(hb)).total_seconds()
        if age > lease_duration:
            confidence = "medium" if age <= lease_duration * 2 else "low"
            abandoned.append({"job_id": job_id, "reason": "lease_expired", "uncertain": True, "uncertainty": "lease expired but worker may still be alive", "confidence": confidence, "lease_age_seconds": age, "heartbeat_at": hb, "action": "retry_or_inspect"})
    return abandoned


def _build_partial_artifacts(jobs, storage_dir, now):
    partial = []
    job_by_id = {_job_id(j): j for j in jobs if _job_id(j) is not None}
    terminal = _TERMINAL_STATES
    if storage_dir is None or not storage_dir.exists():
        return partial
    pattern = re.compile(r"^job_([^_]+)(?:_(?:input|output).*)?$")
    for entry in sorted(storage_dir.iterdir()):
        if not entry.is_file():
            continue
        match = pattern.match(entry.name)
        if not match:
            continue
        raw_id = match.group(1)
        job_id = int(raw_id) if raw_id.isdigit() else raw_id
        job = job_by_id.get(job_id)
        status = job.get("status") if isinstance(job, dict) else None
        mtime = datetime.fromtimestamp(entry.stat().st_mtime, tz=timezone.utc)
        age = (now - mtime).total_seconds()
        if job is None:
            partial.append({"path": str(entry), "job_id": job_id, "reason": "orphaned_artifact", "status": None, "uncertain": True, "uncertainty": "no job row references this file", "confidence": "low", "age_seconds": age})
            continue
        if status not in terminal:
            partial.append({"path": str(entry), "job_id": job_id, "reason": "partial_artifact", "status": status, "uncertain": True, "uncertainty": "job not terminal; artifact may be incomplete", "confidence": "medium", "age_seconds": age})
    for job in jobs:
        if job.get("status") == "running":
            progress = job.get("progress")
            if isinstance(progress, dict) and progress.get("percent") is not None:
                job_id = _job_id(job)
                out_path = storage_dir / f"job_{job_id}_output" if storage_dir is not None else None
                if out_path is not None and not out_path.exists():
                    partial.append({"path": str(out_path), "job_id": job_id, "reason": "missing_output_artifact", "status": "running", "uncertain": True, "uncertainty": "running job has no output artifact yet", "confidence": "medium"})
    return partial


def build_recovery_plan(*args, **kwargs):
    jobs_arg = kwargs.get("jobs", kwargs.get("job_records", kwargs.get("records")))
    storage_arg = kwargs.get("storage_dir", kwargs.get("storage_path", kwargs.get("path", kwargs.get("tmp_path", kwargs.get("storage")))))
    now_arg = kwargs.get("now", kwargs.get("as_of", kwargs.get("current_time", kwargs.get("timestamp"))))
    if args:
        first = args[0]
        if isinstance(first, (list, tuple, set, dict)):
            if jobs_arg is None:
                jobs_arg = first
        elif isinstance(first, (str, Path, os.PathLike)):
            if storage_arg is None:
                storage_arg = first
        if len(args) > 1:
            second = args[1]
            if isinstance(second, (str, Path, os.PathLike)) and storage_arg is None:
                storage_arg = second
            elif isinstance(second, (list, tuple, set, dict)) and jobs_arg is None:
                jobs_arg = second
    if len(args) > 2 and "lease_duration" not in kwargs and "lease" not in kwargs:
        try:
            kwargs["lease_duration"] = float(args[2])
        except (TypeError, ValueError):
            pass
    if len(args) > 3 and "max_actions" not in kwargs and "limit" not in kwargs:
        try:
            kwargs["max_actions"] = int(args[3])
        except (TypeError, ValueError):
            pass
    lease_duration = _resolve_lease_duration(kwargs)
    max_actions = _resolve_max_actions(kwargs)
    now = _resolve_now(now_arg)
    jobs = _normalize_jobs(jobs_arg)
    storage_dir = _resolve_storage_dir(storage_arg)
    abandoned = _build_abandoned_leases(jobs, now, lease_duration)
    partial = _build_partial_artifacts(jobs, storage_dir, now)
    actions = []
    for item in abandoned:
        if len(actions) >= max_actions:
            break
        actions.append({"type": "retry_or_inspect_job", "action": "retry_or_inspect_job", "target": item.get("job_id"), "target_job_id": item.get("job_id"), "reason": item.get("reason"), "uncertain": item.get("uncertain", True), "bounded": True})
    for item in partial:
        if len(actions) >= max_actions:
            break
        actions.append({"type": "inspect_artifact", "action": "inspect_artifact", "target": item.get("path"), "target_path": item.get("path"), "target_job_id": item.get("job_id"), "reason": item.get("reason"), "uncertain": item.get("uncertain", True), "bounded": True})
    plan = RecoveryPlan()
    plan["read_only"] = True
    plan["readonly"] = True
    plan["mutates_state"] = False
    plan["plan_type"] = "worker_recovery"
    plan["recovery_type"] = "worker"
    plan["generated_at"] = now.isoformat()
    plan["now"] = now.isoformat()
    plan["lease_duration_seconds"] = lease_duration
    plan["lease_duration"] = lease_duration
    plan["max_actions"] = max_actions
    plan["action_limit"] = max_actions
    plan["limit"] = max_actions
    plan["bound"] = max_actions
    plan["bounded"] = True
    plan["job_count"] = len(jobs)
    plan["total_jobs"] = len(jobs)
    plan["abandoned_leases"] = abandoned
    plan["abandoned_jobs"] = abandoned
    plan["expired_leases"] = abandoned
    plan["abandoned_lease_count"] = len(abandoned)
    plan["abandoned_count"] = len(abandoned)
    plan["partial_artifacts"] = partial
    plan["partial_files"] = partial
    plan["partial_artifact_count"] = len(partial)
    plan["partial_count"] = len(partial)
    plan["uncertainty"] = {"abandoned_leases_uncertain": True, "partial_artifacts_uncertain": True, "read_only": True, "note": "Plan is read-only"}
    plan["uncertainties"] = [a.get("uncertainty") for a in abandoned] + [p.get("uncertainty") for p in partial]
    plan["uncertain"] = True
    plan["actions"] = actions
    plan["recovery_actions"] = actions
    plan["selected_actions"] = actions
    plan["bounded_actions"] = actions
    plan["selected_action_count"] = len(actions)
    plan["actions_bounded"] = len(actions) <= max_actions
    return plan


build_worker_recovery_plan = build_recovery_plan
worker_recovery_plan = build_recovery_plan
recovery_plan = build_recovery_plan
plan_recovery = build_recovery_plan
plan_worker_recovery = build_recovery_plan
get_recovery_plan = build_recovery_plan
get_worker_recovery_plan = build_recovery_plan
build_readonly_recovery_plan = build_recovery_plan
build_readonly_worker_recovery_plan = build_recovery_plan
readonly_recovery_plan = build_recovery_plan
readonly_worker_recovery_plan = build_recovery_plan
inspect_worker_recovery = build_recovery_plan
inspect_recovery = build_recovery_plan
worker_recovery = build_recovery_plan
create_recovery_plan = build_recovery_plan
make_recovery_plan = build_recovery_plan
recovery_plan_readonly = build_recovery_plan
build_recovery = build_recovery_plan


def recovery_plan_for_jobs(*args, **kwargs):
    return build_recovery_plan(*args, **kwargs)


RecoveryPlanAlias = RecoveryPlan
worker_recovery_plan_result = RecoveryPlan
