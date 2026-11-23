"""Operator command-line entry point for database maintenance tasks.

Usage (run from ``backend/`` with ``DATABASE_URL`` set)::

    python manage.py [--json] migrate [--check]
    python manage.py [--json] drift
    python manage.py [--json] retention (--dry-run | --run) [--batch-size N]
    python manage.py [--json] reconcile [--limit N]
    python manage.py [--json] rebuild-index [--limit N]
    python manage.py [--json] projection-reconcile --start-ledger N --end-ledger N --contract-id ID

Exit codes:

    0  success, no problems found
    1  schema drift detected or migration checksum mismatch
    2  invalid command-line usage
    3  DATABASE_URL is not configured
    4  unexpected error (e.g. database unreachable); only the error type is shown

Privacy: output never includes connection strings, credentials, or secrets.
Every line is passed through :func:`redact` before it is written, and
unexpected exceptions are reported by type name only.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from dataclasses import asdict
from typing import Any, Callable

EXIT_OK = 0
EXIT_PROBLEMS = 1
EXIT_USAGE = 2
EXIT_NOT_CONFIGURED = 3
EXIT_ERROR = 4

REDACTED = "[REDACTED]"

# ``scheme://user:password@host`` -> ``scheme://[REDACTED]@host``
_URL_CREDENTIALS = re.compile(r"(?i)\b([a-z][a-z0-9+.\-]*://)[^\s/@]+@")
# libpq keyword/value style secrets, e.g. ``password=hunter2``.
_SECRET_PAIRS = re.compile(
    r"(?i)\b(password|passwd|pwd|secret|token|api_key|apikey|sslpassword)=\S+"
)


def redact(text: str) -> str:
    """Strip connection strings and credential-looking values from *text*."""
    url = os.getenv("DATABASE_URL")
    if url:
        text = text.replace(url, REDACTED)
    text = _URL_CREDENTIALS.sub(rf"\1{REDACTED}@", text)
    return _SECRET_PAIRS.sub(rf"\1={REDACTED}", text)


def _positive_int(raw: str) -> int:
    try:
        value = int(raw)
    except ValueError:
        raise argparse.ArgumentTypeError("must be a positive integer") from None
    if value < 1:
        raise argparse.ArgumentTypeError("must be a positive integer")
    return value


def _bounded_positive_int(maximum: int) -> Callable[[str], int]:
    def parse(raw: str) -> int:
        value = _positive_int(raw)
        if value > maximum:
            raise argparse.ArgumentTypeError(f"must be no greater than {maximum}")
        return value

    return parse


# ---------------------------------------------------------------------------
# Subcommands. Each returns ``(exit_code, payload)``; modules are imported
# lazily so a subcommand only requires the dependencies it actually uses.
# ---------------------------------------------------------------------------


def _cmd_migrate(args: argparse.Namespace) -> tuple[int, dict[str, Any]]:
    import migration

    if args.check:
        issues = [asdict(issue) for issue in migration.verify_migration_checksums()]
        applied = migration._applied_migrations()
        pending = [
            {"migration_id": m.id, "name": m.name}
            for m in migration.MIGRATIONS
            if m.id not in applied
        ]
        payload = {
            "command": "migrate",
            "check": True,
            "ok": not issues,
            "checksum_issues": issues,
            "pending": pending,
        }
        return (EXIT_PROBLEMS if issues else EXIT_OK), payload

    try:
        results = migration.run_migrations()
    except migration.MigrationChecksumError as exc:
        return EXIT_PROBLEMS, {
            "command": "migrate",
            "ok": False,
            "error": "MigrationChecksumError",
            "checksum_issues": [asdict(issue) for issue in exc.issues],
        }

    mismatched = [r for r in results if r.get("checksum_status") != "verified"]
    payload = {
        "command": "migrate",
        "ok": not mismatched,
        "applied": sum(1 for r in results if r.get("action") == "applied"),
        "migrations": results,
    }
    return (EXIT_PROBLEMS if mismatched else EXIT_OK), payload


def _cmd_drift(args: argparse.Namespace) -> tuple[int, dict[str, Any]]:
    import migration

    drifts = [asdict(entry) for entry in migration.detect_drift()]
    payload = {"command": "drift", "ok": not drifts, "drift": drifts}
    return (EXIT_PROBLEMS if drifts else EXIT_OK), payload


def _cmd_retention(args: argparse.Namespace) -> tuple[int, dict[str, Any]]:
    import db
    from streaming_upload import (
        preview_upload_session_retention,
        purge_expired_upload_sessions,
    )

    session_limit = getattr(args, "session_limit", None)

    if args.dry_run:
        preview = preview_upload_session_retention(limit=session_limit)
        return EXIT_OK, {
            "command": "retention",
            "ok": True,
            "dry_run": True,
            "expired": db.count_expired_events(),
            "upload_sessions": {
                "expired": preview.expired_count,
                "reclaimable_bytes": preview.reclaimable_bytes,
                "active_skipped": preview.active_skipped_count,
                "sessions": [
                    {
                        "session_id": s["session_id"],
                        "age_seconds": s["age_seconds"],
                        "chunk_count": s["chunk_count"],
                        "reclaimable_bytes": s["reclaimable_bytes"],
                    }
                    for s in preview.expired_sessions
                ],
            },
        }

    batch_size = args.batch_size
    if batch_size is None:
        from config import load_config

        batch_size = load_config().retention_batch_size

    deleted = 0
    batches = 0
    while True:
        receipts = db.purge_expired_events(batch_size=batch_size)
        batches += 1
        deleted += len(receipts)
        if len(receipts) < batch_size:
            break

    purged_sessions, reclaimed_bytes, active_skipped = purge_expired_upload_sessions(
        limit=session_limit
    )

    return EXIT_OK, {
        "command": "retention",
        "ok": True,
        "dry_run": False,
        "batch_size": batch_size,
        "batches": batches,
        "deleted": deleted,
        "upload_sessions": {
            "deleted": purged_sessions,
            "reclaimed_bytes": reclaimed_bytes,
            "active_skipped": active_skipped,
        },
    }


def _cmd_rebuild_index(args: argparse.Namespace) -> tuple[int, dict[str, Any]]:
    import chain_indexer

    # Dry-run only: builds a temporary projection from synthetic events and
    # reports differences against the live index without replacing it.
    report = chain_indexer.dry_run_index_rebuild(limit=args.limit)
    return (EXIT_PROBLEMS if report["differences"] else EXIT_OK), {
        "command": "rebuild-index",
        "ok": not report["differences"],
        "dry_run": True,
        "fingerprint": report["fingerprint"],
        "differences": report["differences"],
    }


def _cmd_reconcile(args: argparse.Namespace) -> tuple[int, dict[str, Any]]:
    import registration_reconcile

    report = registration_reconcile.reconcile_pending_registrations(limit=args.limit)
    return EXIT_OK, {
        "command": "reconcile",
        "ok": bool(report.get("ok", True)),
        "summary": report.get("summary", {}),
        "min_confirmations": report.get("minConfirmations"),
        "results": report.get("results", []),
    }


def _cmd_projection_reconcile(args: argparse.Namespace) -> tuple[int, dict[str, Any]]:
    import projection_reconcile

    report = projection_reconcile.reconcile_projection_range(
        start_ledger=args.start_ledger,
        end_ledger=args.end_ledger,
        contract_id=args.contract_id,
        max_events=args.limit,
        rpc_url=args.rpc_url,
    )
    return (EXIT_OK if report["ok"] else EXIT_PROBLEMS), {
        "command": "projection-reconcile",
        **report,
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="manage.py",
        description="Harpocrates database maintenance commands.",
    )
    parser.add_argument("--json", action="store_true", help="print machine-readable JSON")
    sub = parser.add_subparsers(dest="command", required=True)

    migrate = sub.add_parser("migrate", help="apply pending migrations")
    migrate.add_argument(
        "--check",
        action="store_true",
        help="verify checksums and list pending migrations without applying",
    )
    migrate.set_defaults(handler=_cmd_migrate)

    drift = sub.add_parser("drift", help="compare the live schema with the expected schema")
    drift.set_defaults(handler=_cmd_drift)

    retention = sub.add_parser("retention", help="purge expired proof events")
    mode = retention.add_mutually_exclusive_group(required=True)
    mode.add_argument("--dry-run", action="store_true", help="count expired events only")
    mode.add_argument("--run", action="store_true", help="delete expired events")
    retention.add_argument(
        "--batch-size",
        type=_positive_int,
        default=None,
        help="rows per purge batch (default: HARPOCRATES_RETENTION_BATCH_SIZE)",
    )
    retention.add_argument(
        "--session-limit",
        type=_positive_int,
        default=500,
        help="maximum expired upload sessions to preview or purge (default: 500)",
    )
    retention.set_defaults(handler=_cmd_retention)

    reconcile = sub.add_parser("reconcile", help="reconcile pending registration txs")
    reconcile.add_argument(
        "--limit",
        type=_positive_int,
        default=50,
        help="maximum pending rows to reconcile (capped at 50)",
    )
    reconcile.set_defaults(handler=_cmd_reconcile)

    rebuild = sub.add_parser(
        "rebuild-index",
        help="dry-run an index rebuild and report differences (live index untouched)",
    )
    rebuild.add_argument("--limit", type=_positive_int, default=1000)
    rebuild.set_defaults(handler=_cmd_rebuild_index)

    projection_reconcile = sub.add_parser(
        "projection-reconcile",
        help="compare chain lifecycle events with indexed proof projections (read-only)",
    )
    projection_reconcile.add_argument(
        "--start-ledger",
        type=_positive_int,
        required=True,
        help="first ledger in the inclusive range",
    )
    projection_reconcile.add_argument(
        "--end-ledger",
        type=_positive_int,
        required=True,
        help="last ledger in the inclusive range (maximum range: 10000 ledgers)",
    )
    projection_reconcile.add_argument(
        "--contract-id",
        required=True,
        help="Soroban registry contract to inspect",
    )
    projection_reconcile.add_argument(
        "--limit",
        type=_bounded_positive_int(10_000),
        default=1_000,
        help="maximum chain events to inspect (default: 1000, maximum: 10000)",
    )
    projection_reconcile.add_argument(
        "--rpc-url",
        default=None,
        help="Soroban RPC URL (default: SOROBAN_RPC_URL or STELLAR_RPC_URL)",
    )
    projection_reconcile.set_defaults(handler=_cmd_projection_reconcile)

    return parser


def _format_value(value: Any) -> str:
    if isinstance(value, dict):
        return ", ".join(f"{k}={v}" for k, v in value.items())
    return str(value)


def _render_text(payload: dict[str, Any]) -> str:
    lines: list[str] = []
    for key, value in payload.items():
        if isinstance(value, list):
            lines.append(f"{key}: {len(value)}")
            lines.extend(f"  - {_format_value(item)}" for item in value)
        elif isinstance(value, dict):
            lines.append(f"{key}:")
            for sub_k, sub_v in value.items():
                if isinstance(sub_v, list):
                    lines.append(f"  {sub_k}: {len(sub_v)}")
                    lines.extend(f"    - {_format_value(item)}" for item in sub_v)
                else:
                    lines.append(f"  {sub_k}: {_format_value(sub_v)}")
        else:
            lines.append(f"{key}: {_format_value(value)}")
    return "\n".join(lines)


def _emit(payload: dict[str, Any], as_json: bool, write: Callable[[str], Any]) -> None:
    text = json.dumps(payload, default=str, sort_keys=True) if as_json else _render_text(payload)
    write(redact(text) + "\n")


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)  # exits with EXIT_USAGE (2) on bad usage
    if args.command == "projection-reconcile":
        from projection_reconcile import MAX_LEDGER_RANGE

        if args.end_ledger < args.start_ledger:
            parser.error("--end-ledger must be greater than or equal to --start-ledger")
        if args.end_ledger - args.start_ledger + 1 > MAX_LEDGER_RANGE:
            parser.error(f"ledger range must not exceed {MAX_LEDGER_RANGE} ledgers")
    write = sys.stdout.write

    if not os.getenv("DATABASE_URL"):
        _emit(
            {"command": args.command, "ok": False, "error": "DATABASE_URL is not configured"},
            args.json,
            write,
        )
        return EXIT_NOT_CONFIGURED

    try:
        code, payload = args.handler(args)
    except Exception as exc:  # noqa: BLE001 - report type only, never the message
        _emit(
            {"command": args.command, "ok": False, "error": type(exc).__name__},
            args.json,
            write,
        )
        return EXIT_ERROR

    _emit(payload, args.json, write)
    return code


if __name__ == "__main__":
    sys.exit(main())