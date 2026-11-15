"""Tests for server-selected analytics export filenames and authorized display labels."""

from __future__ import annotations

import gzip
import json
import os
import re
import sys
from pathlib import Path

import pytest

_BACKEND_DIR = Path(__file__).resolve().parent
_REPO_ROOT = _BACKEND_DIR.parent
for _p in (str(_BACKEND_DIR), str(_REPO_ROOT)):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from analytics.consent import (
    ANALYTICS_EXPORT_SCOPE,
    ConsentDecision,
    ConsentManager,
    ConsentSource,
    ConsentStatus,
)
from analytics.export_manager import (
    ExportDestinationError,
    ExportManager,
    ExportPolicy,
    MAX_DISPLAY_LABEL_BYTES,
    SAFE_EXPORT_FILENAME_PREFIX,
    allocate_server_export_filename,
    sanitize_display_label,
)
from analytics.log_processor import LogEntry, LogProcessor

_SERVER_NAME_RE = re.compile(r"^harpocrates-analytics-export-[0-9a-f]{32}\.json(?:\.gz)?$")


def _safe_entry(entry_id: str = "evt-1", ts: float = 100.0) -> LogEntry:
    return LogEntry(
        entry_id=entry_id,
        event_name="api_latency",
        message_summary="request completed",
        timestamp_epoch_seconds=ts,
        export_safe=True,
        export_signature="sig-v1:123456789abc",
    )


def test_allocate_server_export_filename_is_random_and_extension_safe() -> None:
    plain = allocate_server_export_filename(compress=False)
    compressed = allocate_server_export_filename(compress=True)

    assert _SERVER_NAME_RE.match(plain)
    assert plain.endswith(".json")
    assert _SERVER_NAME_RE.match(compressed)
    assert compressed.endswith(".json.gz")
    assert plain != allocate_server_export_filename(compress=False)


@pytest.mark.parametrize(
    "bad_prefix",
    [
        "",
        "../evil-",
        "dir/sub-",
        "dir\\sub-",
        "UPPERCASE-",
        "no-trailing-dash",
        "a" * 60 + "-",
    ],
)
def test_allocate_server_export_filename_rejects_unsafe_prefix(bad_prefix: str) -> None:
    with pytest.raises(ValueError, match="unsafe server export filename prefix"):
        allocate_server_export_filename(prefix=bad_prefix)


@pytest.mark.parametrize(
    "hostile_input",
    [
        "../../etc/passwd",
        "..\\..\\Windows\\System32\\drivers\\etc\\hosts",
        "/abs/path/override.json",
        "CON.json",
        "report\x00.evil.sh",
        "tenant-export-2026\r\nContent-Disposition: attachment",
    ],
)
def test_write_export_ignores_user_controlled_filenames_for_filesystem_paths(
    tmp_path: Path, hostile_input: str
) -> None:
    dest_dir = tmp_path / "exports"
    mgr = ExportManager(policy=ExportPolicy(), processor=LogProcessor())

    artifact, written_path, status = mgr.write_export_to_directory(
        dest_dir,
        entries=[_safe_entry("e1")],
        exported_by_tag="acct_ops",
        export_token_verified=True,
        display_label=hostile_input,
        requested_filename=hostile_input,
    )

    assert status == "ok"
    assert artifact is not None
    assert written_path is not None
    assert written_path.parent == dest_dir.resolve()
    assert written_path.name == artifact.server_filename
    assert _SERVER_NAME_RE.match(written_path.name)
    assert "passwd" not in written_path.name
    assert "hosts" not in written_path.name
    assert ".." not in str(written_path.relative_to(dest_dir.resolve()))

    # Only the single server-named file exists in destination directory
    files_on_disk = list(dest_dir.iterdir())
    assert files_on_disk == [written_path]

    envelope = json.loads(written_path.read_text(encoding="utf-8"))
    assert envelope["metadata"]["server_filename"] == artifact.server_filename
    assert envelope["metadata"]["display_label"] == artifact.display_label
    assert len(envelope["records"]) == 1


def test_display_label_preserved_only_in_authorized_output_and_withheld_when_unauthorized(
    tmp_path: Path,
) -> None:
    dest_dir = tmp_path / "shadow_exports"
    mgr = ExportManager(policy=ExportPolicy(), processor=LogProcessor())

    # Unauthenticated shadow mode: export_token_verified=False
    unauth_art, unauth_path, status = mgr.write_export_to_directory(
        dest_dir,
        entries=[_safe_entry("e1")],
        exported_by_tag="acct_ops",
        export_token_verified=False,
        display_label="Quarterly Audit Label",
    )

    assert status == "ok"
    assert unauth_art is not None
    assert unauth_art.display_label is None
    assert unauth_art.exported_by_tag is None
    assert unauth_path is not None

    unauth_raw = unauth_path.read_text(encoding="utf-8")
    assert "Quarterly Audit Label" not in unauth_raw
    unauth_envelope = json.loads(unauth_raw)
    assert "display_label" not in unauth_envelope["metadata"]
    assert "exported_by_tag" not in unauth_envelope["metadata"]
    assert unauth_envelope["records"] == []

    # Authorized mode: export_token_verified=True preserves display_label inside output
    auth_art, auth_path, auth_status = mgr.write_export_to_directory(
        dest_dir,
        entries=[_safe_entry("e1")],
        exported_by_tag="acct_ops",
        export_token_verified=True,
        display_label="Quarterly Audit Label",
    )
    assert auth_status == "ok"
    assert auth_art is not None
    assert auth_art.display_label == "Quarterly Audit Label"
    assert auth_path is not None
    assert "Quarterly" not in auth_path.name

    auth_envelope = json.loads(auth_path.read_text(encoding="utf-8"))
    assert auth_envelope["metadata"]["display_label"] == "Quarterly Audit Label"
    assert auth_envelope["metadata"]["exported_by_tag"] == "acct_ops"
    assert len(auth_envelope["records"]) == 1


def test_consent_manager_gates_authorized_display_label_preservation(tmp_path: Path) -> None:
    cm = ConsentManager()
    mgr = ExportManager(policy=ExportPolicy(), processor=LogProcessor(), consent_manager=cm)
    dest_dir = tmp_path / "consent_exports"

    # Without granted export consent, display_label and records are withheld even if token is verified
    art_denied, path_denied, _ = mgr.write_export_to_directory(
        dest_dir,
        entries=[_safe_entry("e1")],
        exported_by_tag="acct_tenant",
        export_token_verified=True,
        display_label="Tenant Label Alpha",
    )
    assert art_denied is not None
    assert art_denied.display_label is None
    assert path_denied is not None
    assert "Tenant Label Alpha" not in path_denied.read_text(encoding="utf-8")

    # Grant explicit analytics:export consent
    cm.set_consent(
        "acct_tenant",
        ConsentDecision(
            status=ConsentStatus.GRANTED,
            source=ConsentSource.USER_EXPLICIT,
            scope=[ANALYTICS_EXPORT_SCOPE],
            granted_at_epoch_seconds=1_000.0,
            expires_at_epoch_seconds=0.0,
        ),
    )
    assert cm.is_export_authorized("acct_tenant") is True

    art_ok, path_ok, _ = mgr.write_export_to_directory(
        dest_dir,
        entries=[_safe_entry("e1")],
        exported_by_tag="acct_tenant",
        export_token_verified=True,
        display_label="Tenant Label Alpha",
    )
    assert art_ok is not None
    assert art_ok.display_label == "Tenant Label Alpha"
    assert path_ok is not None
    envelope_ok = json.loads(path_ok.read_text(encoding="utf-8"))
    assert envelope_ok["metadata"]["display_label"] == "Tenant Label Alpha"

    # Withdraw consent -> subsequent export withholds display_label again
    cm.withdraw_consent("acct_tenant")
    assert cm.is_export_authorized("acct_tenant") is False
    art_after, path_after, _ = mgr.write_export_to_directory(
        dest_dir,
        entries=[_safe_entry("e1")],
        exported_by_tag="acct_tenant",
        export_token_verified=True,
        display_label="Post-Withdrawal Secret Label",
    )
    assert art_after is not None
    assert art_after.display_label is None
    assert path_after is not None
    assert "Post-Withdrawal Secret Label" not in path_after.read_text(encoding="utf-8")


def test_compressed_filesystem_export_writes_valid_gzip_envelope(tmp_path: Path) -> None:
    dest_dir = tmp_path / "gz_exports"
    mgr = ExportManager(policy=ExportPolicy(), processor=LogProcessor())

    art, path, status = mgr.write_export_to_directory(
        dest_dir,
        entries=[_safe_entry("gz1")],
        exported_by_tag="acct_gz",
        compress=True,
        export_token_verified=True,
        display_label="Compressed Ops Bundle",
    )
    assert status == "ok"
    assert art is not None
    assert path is not None
    assert path.name.endswith(".json.gz")

    decompressed = gzip.decompress(path.read_bytes()).decode("utf-8")
    envelope = json.loads(decompressed)
    assert envelope["metadata"]["display_label"] == "Compressed Ops Bundle"
    assert envelope["metadata"]["compress"] is True
    assert "compressed_records" in envelope


def test_write_export_writes_nothing_when_token_rejected(tmp_path: Path) -> None:
    dest_dir = tmp_path / "strict_exports"
    mgr = ExportManager(
        policy=ExportPolicy(allow_unauthenticated_export_shadow_mode=False),
        processor=LogProcessor(),
    )

    art, path, status = mgr.write_export_to_directory(
        dest_dir,
        entries=[_safe_entry("e1")],
        export_token_verified=False,
        display_label="Should Never Write",
    )
    assert art is None
    assert path is None
    assert status == "export_token_required"
    assert list(dest_dir.iterdir()) == []


def test_sanitize_display_label_caps_bytes_strips_controls_and_redacts_secrets() -> None:
    stellar_secret = "S" + ("B" * 55)
    pem_marker = "-----BEGIN " + "PRIVATE KEY-----"
    hex_digest = "a" * 64

    cleaned = sanitize_display_label(
        f"  Report\x00\u202e\nfor {stellar_secret} {pem_marker} Bearer tok_1234567890 {hex_digest}  "
    )
    assert cleaned is not None
    assert "\x00" not in cleaned
    assert "\u202e" not in cleaned
    assert "\n" not in cleaned
    assert stellar_secret not in cleaned
    assert pem_marker not in cleaned
    assert "tok_1234567890" not in cleaned
    assert hex_digest not in cleaned
    assert "[REDACTED]" in cleaned

    oversized = "é" * 200  # 2 bytes per UTF-8 character
    capped = sanitize_display_label(oversized, max_bytes=MAX_DISPLAY_LABEL_BYTES)
    assert capped is not None
    assert len(capped.encode("utf-8")) <= MAX_DISPLAY_LABEL_BYTES

    assert sanitize_display_label("   \t\r\n\u200b  ") is None
    assert sanitize_display_label(None) is None

    with pytest.raises(ValueError, match="display_label must be a string or None"):
        sanitize_display_label(12345)  # type: ignore[arg-type]


def test_destination_directory_validation_rejects_file_null_and_symlinks(tmp_path: Path) -> None:
    mgr = ExportManager(policy=ExportPolicy(), processor=LogProcessor())

    with pytest.raises(ExportDestinationError):
        mgr.write_export_to_directory("", entries=[_safe_entry()])

    with pytest.raises(ExportDestinationError):
        mgr.write_export_to_directory("bad\x00dir", entries=[_safe_entry()])

    existing_file = tmp_path / "not_a_dir.txt"
    existing_file.write_text("hi", encoding="utf-8")
    with pytest.raises(ExportDestinationError, match="directory"):
        mgr.write_export_to_directory(existing_file, entries=[_safe_entry()])

    real_dir = tmp_path / "real_target"
    real_dir.mkdir()
    symlink_dir = tmp_path / "link_target"
    try:
        os.symlink(real_dir, symlink_dir, target_is_directory=True)
    except (OSError, NotImplementedError):
        pytest.skip("OS policy prevents unprivileged symlink creation")

    with pytest.raises(ExportDestinationError, match="symlink"):
        mgr.write_export_to_directory(symlink_dir, entries=[_safe_entry()])
