from __future__ import annotations

import hashlib
import os
from contextlib import contextmanager
from typing import Any, Iterator

import psycopg
from psycopg.rows import dict_row
from psycopg.types.json import Jsonb


def database_url() -> str | None:
    return os.getenv("DATABASE_URL")


@contextmanager
def get_connection() -> Iterator[psycopg.Connection]:
    url = database_url()
    if not url:
        raise RuntimeError("DATABASE_URL is not configured")

    with psycopg.connect(url, row_factory=dict_row) as connection:
        yield connection


def init_db() -> None:
    if not database_url():
        return

    with get_connection() as connection:
        with connection.cursor() as cursor:
            cursor.execute(
                """
                create table if not exists proof_events (
                    id bigserial primary key,
                    event_type text not null,
                    file_name text,
                    video_hash text,
                    metadata_hash text,
                    proof_id text,
                    tier text,
                    embedded_hash text,
                    metadata jsonb,
                    created_at timestamptz not null default now()
                );
                """
            )
            cursor.execute(
                """
                create index if not exists proof_events_video_hash_idx
                on proof_events (video_hash);
                """
            )
            cursor.execute(
                """
                create index if not exists proof_events_proof_id_idx
                on proof_events (proof_id);
                """
            )
            cursor.execute("alter table proof_events add column if not exists tx_hash text;")
            cursor.execute("alter table proof_events add column if not exists tx_status text;")
            cursor.execute("alter table proof_events add column if not exists source_address text;")
            cursor.execute("alter table proof_events add column if not exists contract_id text;")
            cursor.execute(
                """
                create index if not exists proof_events_tx_hash_idx
                on proof_events (tx_hash);
                """
            )
            # Idempotency support: unique key for register events only.
            cursor.execute("alter table proof_events add column if not exists idempotency_key text;")
            # Partial unique index: only enforced when idempotency_key is non-null
            # (i.e., only for 'register' events). embed/extract events are unaffected.
            cursor.execute(
                """
                create unique index if not exists proof_events_idempotency_key_idx
                on proof_events (idempotency_key)
                where idempotency_key is not null;
                """
            )
            
            # Queue for async jobs
            cursor.execute(
                """
                create table if not exists jobs (
                    id bigserial primary key,
                    type text not null,
                    status text not null default 'pending',
                    payload jsonb not null,
                    result jsonb,
                    error text,
                    progress float default 0.0,
                    attempts int not null default 0,
                    max_attempts int not null default 3,
                    worker_id text,
                    lease_expires_at timestamptz,
                    created_at timestamptz not null default now(),
                    updated_at timestamptz not null default now()
                );
                """
            )
            cursor.execute(
                """
                create index if not exists jobs_status_idx
                on jobs (status) where status in ('pending', 'processing');
                """
            )
            
        connection.commit()


def check_db() -> bool:
    if not database_url():
        return False

    with get_connection() as connection:
        with connection.cursor() as cursor:
            cursor.execute("select 1 as ok")
            row = cursor.fetchone()
            return bool(row and row["ok"] == 1)


def insert_proof_event(
    *,
    event_type: str,
    file_name: str | None = None,
    video_hash: str | None = None,
    metadata_hash: str | None = None,
    proof_id: str | None = None,
    tier: str | None = None,
    embedded_hash: str | None = None,
    tx_hash: str | None = None,
    tx_status: str | None = None,
    source_address: str | None = None,
    contract_id: str | None = None,
    metadata: dict[str, Any] | None = None,
) -> dict[str, Any] | None:
    if not database_url():
        return None

    with get_connection() as connection:
        with connection.cursor() as cursor:
            cursor.execute(
                """
                insert into proof_events (
                    event_type,
                    file_name,
                    video_hash,
                    metadata_hash,
                    proof_id,
                    tier,
                    embedded_hash,
                    tx_hash,
                    tx_status,
                    source_address,
                    contract_id,
                    metadata
                )
                values (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                returning id, created_at;
                """,
                (
                    event_type,
                    file_name,
                    video_hash,
                    metadata_hash,
                    proof_id,
                    tier,
                    embedded_hash,
                    tx_hash,
                    tx_status,
                    source_address,
                    contract_id,
                    Jsonb(metadata) if metadata is not None else None,
                ),
            )
            row = cursor.fetchone()
        connection.commit()
        return dict(row) if row else None


def list_proof_events(limit: int = 25) -> list[dict[str, Any]]:
    if not database_url():
        return []

    limit = max(1, min(limit, 100))
    with get_connection() as connection:
        with connection.cursor() as cursor:
            cursor.execute(
                """
                select
                    id,
                    event_type,
                    file_name,
                    video_hash,
                    metadata_hash,
                    proof_id,
                    tier,
                    embedded_hash,
                    tx_hash,
                    tx_status,
                    source_address,
                    contract_id,
                    metadata,
                    created_at
                from proof_events
                order by id desc
                limit %s;
                """,
                (limit,),
            )
            return [dict(row) for row in cursor.fetchall()]


def find_proof_events_by_video(video_hash: str) -> list[dict[str, Any]]:
    if not database_url():
        return []

    with get_connection() as connection:
        with connection.cursor() as cursor:
            cursor.execute(
                """
                select
                    id,
                    event_type,
                    file_name,
                    video_hash,
                    metadata_hash,
                    proof_id,
                    tier,
                    embedded_hash,
                    tx_hash,
                    tx_status,
                    source_address,
                    contract_id,
                    metadata,
                    created_at
                from proof_events
                where video_hash = %s
                order by id desc;
                """,
                (video_hash,),
            )
            return [dict(row) for row in cursor.fetchall()]


def make_idempotency_key(video_hash: str, proof_id: str, tx_hash: str | None) -> str:
    """Derive the idempotency key for a register event.

    Key material: ``video_hash:proof_id:tx_hash`` where ``tx_hash`` defaults
    to the empty string when absent.  Using SHA-256 keeps the stored value a
    fixed-length hex string and avoids any length-extension ambiguity.
    """
    raw = f"{video_hash}:{proof_id}:{tx_hash or ''}"
    return hashlib.sha256(raw.encode()).hexdigest()


# Fields compared when deciding whether a retry carries a conflicting payload.
_CONFLICT_FIELDS = ("video_hash", "metadata_hash", "proof_id", "tier", "source_address", "contract_id")


def upsert_register_event(
    *,
    idempotency_key: str,
    file_name: str | None = None,
    video_hash: str | None = None,
    metadata_hash: str | None = None,
    proof_id: str | None = None,
    tier: str | None = None,
    tx_hash: str | None = None,
    tx_status: str | None = None,
    source_address: str | None = None,
    contract_id: str | None = None,
    metadata: dict[str, Any] | None = None,
) -> tuple[dict[str, Any], bool]:
    """Insert a register event idempotently.

    Returns ``(row, created)`` where *created* is ``True`` when a new row was
    written and ``False`` when an existing row was found via the idempotency
    key.

    Raises ``ConflictError`` when the same idempotency key is reused with a
    payload that differs in one of the canonical proof-identity fields.

    The insert is done with ``ON CONFLICT DO NOTHING`` so that concurrent
    requests with the same key race safely: only one writer wins and the
    other falls back to the ``SELECT`` path.
    """
    if not database_url():
        # When no database is configured return a stub so the rest of the app
        # remains functional in minimal dev environments.
        stub: dict[str, Any] = {
            "id": None,
            "created_at": None,
            "video_hash": video_hash,
            "metadata_hash": metadata_hash,
            "proof_id": proof_id,
            "tier": tier,
            "source_address": source_address,
            "contract_id": contract_id,
        }
        return stub, True

    with get_connection() as connection:
        with connection.cursor() as cursor:
            # Attempt the insert; if the unique key already exists the row is
            # silently skipped and nothing is returned.
            cursor.execute(
                """
                insert into proof_events (
                    event_type,
                    file_name,
                    video_hash,
                    metadata_hash,
                    proof_id,
                    tier,
                    tx_hash,
                    tx_status,
                    source_address,
                    contract_id,
                    metadata,
                    idempotency_key
                )
                values (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                on conflict (idempotency_key)
                where idempotency_key is not null
                do nothing
                returning
                    id,
                    event_type,
                    file_name,
                    video_hash,
                    metadata_hash,
                    proof_id,
                    tier,
                    embedded_hash,
                    tx_hash,
                    tx_status,
                    source_address,
                    contract_id,
                    metadata,
                    created_at;
                """,
                (
                    "register",
                    file_name,
                    video_hash,
                    metadata_hash,
                    proof_id,
                    tier,
                    tx_hash,
                    tx_status,
                    source_address,
                    contract_id,
                    Jsonb(metadata) if metadata is not None else None,
                    idempotency_key,
                ),
            )
            row = cursor.fetchone()

            if row is not None:
                # Fresh insert – committed below.
                connection.commit()
                return dict(row), True

            # Key already existed (concurrent insert or retry): fetch the
            # previously stored row.
            cursor.execute(
                """
                select
                    id,
                    event_type,
                    file_name,
                    video_hash,
                    metadata_hash,
                    proof_id,
                    tier,
                    embedded_hash,
                    tx_hash,
                    tx_status,
                    source_address,
                    contract_id,
                    metadata,
                    created_at
                from proof_events
                where idempotency_key = %s;
                """,
                (idempotency_key,),
            )
            existing = cursor.fetchone()

        # No commit needed for the read-only fallback path; any uncommitted
        # state is just the no-op insert.
        connection.rollback()

    if existing is None:
        # Should not happen – the constraint guarantees the row is visible.
        raise RuntimeError("idempotency key collision but row not found; please retry")

    existing_row = dict(existing)

    # Check whether the caller is re-submitting with a conflicting payload.
    incoming = {
        "video_hash": video_hash,
        "metadata_hash": metadata_hash,
        "proof_id": proof_id,
        "tier": tier,
        "source_address": source_address,
        "contract_id": contract_id,
    }
    for field in _CONFLICT_FIELDS:
        if existing_row.get(field) != incoming.get(field):
            raise ConflictError(
                idempotency_key=idempotency_key,
                field=field,
                existing_value=existing_row.get(field),
                incoming_value=incoming.get(field),
            )

    return existing_row, False


class ConflictError(Exception):
    """Raised when the same idempotency key is reused with a conflicting payload."""

    def __init__(
        self,
        *,
        idempotency_key: str,
        field: str,
        existing_value: object,
        incoming_value: object,
    ) -> None:
        super().__init__(
            f"idempotency key reused with conflicting value for '{field}'"
        )
        self.idempotency_key = idempotency_key
        self.field = field
        self.existing_value = existing_value
        self.incoming_value = incoming_value


def enqueue_job(job_type: str, payload: dict, max_attempts: int = 3) -> int:
    if not database_url():
        return -1
    with get_connection() as connection:
        with connection.cursor() as cursor:
            cursor.execute(
                """
                insert into jobs (type, payload, max_attempts)
                values (%s, %s, %s)
                returning id;
                """,
                (job_type, Jsonb(payload), max_attempts),
            )
            row = cursor.fetchone()
        connection.commit()
        return row["id"]


def get_job(job_id: int) -> dict[str, Any] | None:
    if not database_url():
        return None
    with get_connection() as connection:
        with connection.cursor() as cursor:
            cursor.execute(
                """
                select
                    id, type, status, payload, result, error, progress,
                    attempts, max_attempts, worker_id, lease_expires_at, created_at, updated_at
                from jobs
                where id = %s;
                """,
                (job_id,),
            )
            row = cursor.fetchone()
            return dict(row) if row else None


def lease_job(worker_id: str, job_types: list[str], lease_duration: int = 300) -> dict[str, Any] | None:
    if not database_url():
        return None
    with get_connection() as connection:
        with connection.cursor() as cursor:
            # Find a pending job or a processing job with expired lease.
            cursor.execute(
                """
                update jobs
                set
                    status = 'processing',
                    worker_id = %s,
                    lease_expires_at = now() + interval '%s seconds',
                    attempts = attempts + 1,
                    updated_at = now()
                where id = (
                    select id
                    from jobs
                    where
                        type = any(%s)
                        and (
                            status = 'pending'
                            or (status = 'processing' and lease_expires_at < now())
                        )
                    order by created_at asc
                    for update skip locked
                    limit 1
                )
                returning id, type, payload, attempts, max_attempts;
                """,
                (worker_id, lease_duration, job_types),
            )
            row = cursor.fetchone()
        connection.commit()
        return dict(row) if row else None


def heartbeat_job(job_id: int, progress: float, lease_duration: int = 300) -> bool:
    if not database_url():
        return False
    with get_connection() as connection:
        with connection.cursor() as cursor:
            cursor.execute(
                """
                update jobs
                set
                    progress = %s,
                    lease_expires_at = now() + interval '%s seconds',
                    updated_at = now()
                where id = %s and status = 'processing'
                returning id;
                """,
                (progress, lease_duration, job_id),
            )
            row = cursor.fetchone()
        connection.commit()
        return row is not None


def complete_job(job_id: int, result: dict) -> None:
    if not database_url():
        return
    with get_connection() as connection:
        with connection.cursor() as cursor:
            cursor.execute(
                """
                update jobs
                set
                    status = 'completed',
                    result = %s,
                    progress = 1.0,
                    updated_at = now(),
                    lease_expires_at = null,
                    worker_id = null
                where id = %s;
                """,
                (Jsonb(result), job_id),
            )
        connection.commit()


def fail_job(job_id: int, error: str, is_fatal: bool) -> None:
    if not database_url():
        return
    with get_connection() as connection:
        with connection.cursor() as cursor:
            if is_fatal:
                status = 'failed'
            else:
                cursor.execute("select attempts, max_attempts from jobs where id = %s;", (job_id,))
                row = cursor.fetchone()
                if row and row["attempts"] >= row["max_attempts"]:
                    status = 'failed'
                else:
                    status = 'pending'

            cursor.execute(
                """
                update jobs
                set
                    status = %s,
                    error = %s,
                    updated_at = now(),
                    lease_expires_at = null,
                    worker_id = null
                where id = %s;
                """,
                (status, error, job_id),
            )
        connection.commit()


def cancel_job(job_id: int) -> bool:
    if not database_url():
        return False
    with get_connection() as connection:
        with connection.cursor() as cursor:
            cursor.execute(
                """
                update jobs
                set
                    status = 'cancelled',
                    updated_at = now(),
                    lease_expires_at = null,
                    worker_id = null
                where id = %s and status in ('pending', 'processing')
                returning id;
                """,
                (job_id,),
            )
            row = cursor.fetchone()
        connection.commit()
        return row is not None
