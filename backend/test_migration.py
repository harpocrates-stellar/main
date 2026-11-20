from __future__ import annotations

import os
import pytest
from unittest.mock import patch, MagicMock


@pytest.fixture(autouse=True)
def clear_database_url():
    """Ensure DATABASE_URL is unset or set to a test value."""
    original = os.environ.get("DATABASE_URL")
    # Set a dummy URL for tests that need DB access.
    # Tests that don't need a DB will override this per test.
    os.environ["DATABASE_URL"] = "postgresql://test:test@localhost:5432/test"
    yield
    if original is not None:
        os.environ["DATABASE_URL"] = original
    else:
        os.environ.pop("DATABASE_URL", None)


# ---------------------------------------------------------------------------
# Tests for the migration runner (without a real database)
# ---------------------------------------------------------------------------


@patch("migration._database_url", return_value=None)
def test_run_migrations_no_db(mock_url):
    """When DATABASE_URL is not configured, run_migrations returns []."""
    from migration import run_migrations
    assert run_migrations() == []


@patch("migration._database_url", return_value="postgresql://localhost/test")
@patch("migration._get_connection")
def test_run_migrations_applies_all(mock_conn, mock_url):
    """All migrations are applied when the ledger is empty."""
    from migration import run_migrations

    # Simulate an empty migrations table (no applied migrations)
    mock_cursor = MagicMock()
    mock_cursor.fetchall.return_value = []  # _applied_migrations returns empty
    mock_connection = MagicMock()
    mock_connection.cursor.return_value.__enter__.return_value = mock_cursor
    mock_conn.return_value.__enter__.return_value = mock_connection

    result = run_migrations()

    assert len(result) > 0
    for entry in result:
        assert entry["action"] in ("applied",)
    # Verify migration SQL was executed
    assert mock_cursor.execute.call_count > 1  # ledger table + migrations


@patch("migration._database_url", return_value="postgresql://localhost/test")
@patch("migration._get_connection")
def test_run_migrations_skips_applied(mock_conn, mock_url):
    """Migrations that are already in the ledger are skipped."""
    from migration import MIGRATIONS, run_migrations, _compute_checksum

    # Simulate that migration 1 is already applied, with the checksum the
    # ledger records on apply (the column is NOT NULL in the ledger schema).
    applied_migration_ids = {1}
    recorded = [
        {
            "migration_id": m.id,
            "name": m.name,
            "checksum": _compute_checksum(m.sql),
        }
        for m in MIGRATIONS
        if m.id in applied_migration_ids
    ]

    mock_cursor = MagicMock()
    mock_cursor.fetchall.return_value = recorded
    mock_connection = MagicMock()
    mock_connection.cursor.return_value.__enter__.return_value = mock_cursor
    mock_conn.return_value.__enter__.return_value = mock_connection

    result = run_migrations()

    mid_1_entry = [e for e in result if e["migration_id"] == 1]
    assert len(mid_1_entry) == 1
    assert mid_1_entry[0]["action"] == "skipped"
    assert mid_1_entry[0]["checksum_status"] == "verified"


# ---------------------------------------------------------------------------
# Tests for drift detection (without a real database)
# ---------------------------------------------------------------------------


def test_detect_drift_no_db():
    """When no DATABASE_URL is set, detect_drift returns []."""
    from migration import detect_drift

    with patch("migration._database_url", return_value=None):
        assert detect_drift() == []


@patch("migration._database_url", return_value="postgresql://localhost/test")
@patch("migration._get_connection")
def test_detect_drift_missing_table(mock_conn, mock_url):
    """A table missing from the database is reported as a drift."""
    from migration import detect_drift, EXPECTED_TABLES

    # First query returns only tables that are NOT in EXPECTED_TABLES
    mock_cursor = MagicMock()
    # information_schema.tables returns no expected tables
    mock_cursor.fetchall.side_effect = [
        [{"table_name": "some_other_table"}],  # first fetch: no expected tables found
        [],  # columns query for each expected table won't be reached
    ]
    mock_connection = MagicMock()
    mock_connection.cursor.return_value.__enter__.return_value = mock_cursor
    mock_conn.return_value.__enter__.return_value = mock_connection

    drifts = detect_drift()

    assert len(drifts) == len(EXPECTED_TABLES)
    for d in drifts:
        assert d.issue == "missing_table"


# ---------------------------------------------------------------------------
# Tests for migration checksum stability
# ---------------------------------------------------------------------------


def test_migration_checksum_stability():
    """Migration SQL checksums are deterministic (same input = same hash)."""
    from migration import MIGRATIONS, _compute_checksum

    for m in MIGRATIONS:
        c1 = _compute_checksum(m.sql)
        c2 = _compute_checksum(m.sql)
        assert c1 == c2, f"Migration {m.id} ({m.name}) checksum is not stable"
        assert len(c1) == 64, f"Checksum should be 64 hex chars, got {len(c1)}"


# ---------------------------------------------------------------------------
# Tests for the migrations table query
# ---------------------------------------------------------------------------


def test_applied_migrations_empty():
    """When no migrations are applied, the set is empty."""
    from migration import _applied_migrations

    with patch("migration._get_connection") as mock_conn:
        mock_cursor = MagicMock()
        mock_cursor.fetchall.return_value = []
        mock_connection = MagicMock()
        mock_connection.cursor.return_value.__enter__.return_value = mock_cursor
        mock_conn.return_value.__enter__.return_value = mock_connection

        result = _applied_migrations()
        assert result == set()


# ---------------------------------------------------------------------------
# Tests for expected table definitions consistency
# ---------------------------------------------------------------------------


def test_expected_tables_cover_all_migration_tables():
    """Every table that a migration creates has a corresponding drift-check entry."""
    from migration import MIGRATIONS, EXPECTED_TABLES
    import re

    created_tables = set()
    for m in MIGRATIONS:
        for match in re.finditer(
            r"CREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?(\w+)", m.sql, re.IGNORECASE
        ):
            created_tables.add(match.group(1).lower())

    missing = created_tables - set(k.lower() for k in EXPECTED_TABLES)
    assert not missing, (
        f"Tables created by migrations but missing from EXPECTED_TABLES: {missing}"
    )


# ---------------------------------------------------------------------------
# Tests for startup checksum verification
# ---------------------------------------------------------------------------


def _ledger_rows(*migration_ids):
    """Build schema-faithful ledger rows (id, name, checksum) for tests."""
    from migration import MIGRATIONS, _compute_checksum

    by_id = {m.id: m for m in MIGRATIONS}
    return [
        {
            "migration_id": mid,
            "name": by_id[mid].name,
            "checksum": _compute_checksum(by_id[mid].sql),
        }
        for mid in migration_ids
    ]


def _patch_ledger(mock_conn, rows):
    mock_cursor = MagicMock()
    mock_cursor.fetchall.return_value = rows
    mock_connection = MagicMock()
    mock_connection.cursor.return_value.__enter__.return_value = mock_cursor
    mock_conn.return_value.__enter__.return_value = mock_connection
    return mock_cursor


def test_verify_migration_checksums_no_db():
    """Verification is a no-op when no database is configured."""
    from migration import verify_migration_checksums

    with patch("migration._database_url", return_value=None):
        assert verify_migration_checksums() == []


@patch("migration._database_url", return_value="postgresql://localhost/test")
@patch("migration._get_connection")
def test_verify_migration_checksums_all_match(mock_conn, mock_url):
    """An intact ledger reports no checksum issues."""
    from migration import verify_migration_checksums

    _patch_ledger(mock_conn, _ledger_rows(1, 2, 3))

    assert verify_migration_checksums() == []


@patch("migration._database_url", return_value="postgresql://localhost/test")
@patch("migration._get_connection")
def test_verify_migration_checksums_detects_mismatch(mock_conn, mock_url):
    """A changed migration definition is reported as a checksum mismatch."""
    from migration import MIGRATIONS, _compute_checksum, verify_migration_checksums

    rows = _ledger_rows(1)
    rows[0]["checksum"] = "0" * 64  # recorded digest no longer matches the SQL

    _patch_ledger(mock_conn, rows)
    issues = verify_migration_checksums()

    assert len(issues) == 1
    issue = issues[0]
    assert issue.migration_id == 1
    assert issue.issue == "checksum_mismatch"
    assert issue.recorded == "0" * 64
    assert issue.expected == _compute_checksum(MIGRATIONS[0].sql)


@patch("migration._database_url", return_value="postgresql://localhost/test")
@patch("migration._get_connection")
def test_verify_migration_checksums_missing_digest(mock_conn, mock_url):
    """A ledger row without a recorded digest is reported, not silently trusted."""
    from migration import verify_migration_checksums

    rows = _ledger_rows(1)
    rows[0]["checksum"] = None
    _patch_ledger(mock_conn, rows)

    issues = verify_migration_checksums()

    assert len(issues) == 1
    assert issues[0].issue == "missing_checksum"
    assert issues[0].recorded is None
    assert issues[0].expected is not None


@patch("migration._database_url", return_value="postgresql://localhost/test")
@patch("migration._get_connection")
def test_verify_migration_checksums_unknown_migration(mock_conn, mock_url):
    """A ledger row the code no longer defines is reported as unknown."""
    from migration import verify_migration_checksums

    _patch_ledger(
        mock_conn,
        [{"migration_id": 9999, "name": "removed migration", "checksum": "a" * 64}],
    )

    issues = verify_migration_checksums()

    assert len(issues) == 1
    assert issues[0].migration_id == 9999
    assert issues[0].issue == "unknown_migration"
    assert issues[0].expected is None


def test_checksum_enforcement_mode_defaults_and_overrides(monkeypatch):
    """Enforcement defaults to fail-closed and only `warn` opts out."""
    from migration import _checksum_enforcement

    monkeypatch.delenv("MIGRATION_CHECKSUM_ENFORCEMENT", raising=False)
    assert _checksum_enforcement() == "enforce"

    monkeypatch.setenv("MIGRATION_CHECKSUM_ENFORCEMENT", "WARN")
    assert _checksum_enforcement() == "warn"

    monkeypatch.setenv("MIGRATION_CHECKSUM_ENFORCEMENT", "not-a-mode")
    assert _checksum_enforcement() == "enforce"


@patch("migration._database_url", return_value="postgresql://localhost/test")
@patch("migration._get_connection")
def test_run_migrations_raises_on_checksum_mismatch(mock_conn, mock_url):
    """Startup aborts when an applied migration's SQL no longer matches."""
    from migration import MigrationChecksumError, run_migrations

    rows = _ledger_rows(1)
    rows[0]["checksum"] = "0" * 64
    _patch_ledger(mock_conn, rows)

    with pytest.raises(MigrationChecksumError) as excinfo:
        run_migrations()

    assert "checksum_mismatch(migration_id=1)" in str(excinfo.value)
    # Privacy guard: the error must not leak migration SQL.
    assert "CREATE TABLE" not in str(excinfo.value)


@patch("migration._database_url", return_value="postgresql://localhost/test")
@patch("migration._get_connection")
def test_run_migrations_warn_mode_reports_without_raising(mock_conn, mock_url, monkeypatch):
    """`warn` keeps the service bootable while still reporting the drift."""
    from migration import run_migrations

    monkeypatch.setenv("MIGRATION_CHECKSUM_ENFORCEMENT", "warn")
    rows = _ledger_rows(1)
    rows[0]["checksum"] = "0" * 64
    _patch_ledger(mock_conn, rows)

    result = run_migrations()

    entry = [e for e in result if e["migration_id"] == 1][0]
    assert entry["action"] == "skipped"
    assert entry["checksum_status"] == "checksum_mismatch"


@patch("migration._database_url", return_value="postgresql://localhost/test")
@patch("migration._get_connection")
def test_run_migrations_warn_mode_ignores_mismatch_for_pending(mock_conn, mock_url, monkeypatch):
    """Pending migrations still apply after a non-fatal checksum report."""
    from migration import run_migrations

    monkeypatch.setenv("MIGRATION_CHECKSUM_ENFORCEMENT", "warn")
    rows = _ledger_rows(1)
    rows[0]["checksum"] = "0" * 64
    mock_cursor = _patch_ledger(mock_conn, rows)

    result = run_migrations()

    assert mock_cursor.execute.call_count > 1
    assert any(e["action"] == "applied" for e in result if e["migration_id"] > 1)
