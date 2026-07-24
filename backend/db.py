from __future__ import annotations

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
            cursor.execute(
                """
                create table if not exists proof_history_events (
                    id bigserial primary key,
                    proof_id text not null,
                    action text not null,
                    actor text,
                    reason_code integer not null,
                    contract_id text,
                    tx_hash text,
                    tx_status text,
                    created_at timestamptz not null default now()
                );
                """
            )
            cursor.execute(
                """
                create index if not exists proof_history_events_proof_id_idx
                on proof_history_events (proof_id);
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


def insert_proof_history_event(
    *,
    proof_id: str,
    action: str,
    actor: str | None = None,
    reason_code: int,
    contract_id: str | None = None,
    tx_hash: str | None = None,
    tx_status: str | None = None,
) -> dict[str, Any] | None:
    if not database_url():
        return None

    with get_connection() as connection:
        with connection.cursor() as cursor:
            cursor.execute(
                """
                insert into proof_history_events (
                    proof_id,
                    action,
                    actor,
                    reason_code,
                    contract_id,
                    tx_hash,
                    tx_status
                )
                values (%s, %s, %s, %s, %s, %s, %s)
                returning id, created_at;
                """,
                (
                    proof_id,
                    action,
                    actor,
                    reason_code,
                    contract_id,
                    tx_hash,
                    tx_status,
                ),
            )
            row = cursor.fetchone()
        connection.commit()
        return dict(row) if row else None


def list_proof_history_events(
    proof_id: str, limit: int = 50, offset: int = 0
) -> list[dict[str, Any]]:
    if not database_url():
        return []

    limit = max(1, min(limit, 100))
    offset = max(0, offset)
    with get_connection() as connection:
        with connection.cursor() as cursor:
            cursor.execute(
                """
                select
                    id,
                    proof_id,
                    action,
                    actor,
                    reason_code,
                    contract_id,
                    tx_hash,
                    tx_status,
                    created_at
                from proof_history_events
                where proof_id = %s
                order by id asc
                limit %s offset %s;
                """,
                (proof_id, limit, offset),
            )
            return [dict(row) for row in cursor.fetchall()]
