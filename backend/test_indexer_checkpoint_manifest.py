"""
Focused tests for the verified indexer checkpoint manifest.

Covers:
- Binding network, contract, schema_version, and observed_ledger into a canonical
  SHA-256-verified checkpoint manifest
- Fail-closed integrity verification against tampering and malformed manifests
- Rejecting incompatible resumes (network, contract, schema, ledger regression,
  tampered manifest, unverified legacy cursor) without mutating the trusted projection
- Atomic file-backed persistence and round-trip verification in temporary state directories
- Backward compatibility with existing poll_indexer_once callers
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest import mock

import pytest

from chain_indexer import (
    DEFAULT_SOROBAN_RPC_URL,
    INDEXER_CHECKPOINT_MANIFEST_VERSION,
    CheckpointVerificationError,
    IncompatibleCheckpointError,
    build_checkpoint_manifest,
    load_checkpoint_manifest_file,
    poll_indexer_once,
    resolve_indexer_network,
    validate_checkpoint_resume,
    verify_checkpoint_manifest,
    write_checkpoint_manifest_file,
)
from db import (
    get_indexer_checkpoint_manifest,
    get_indexer_cursor,
    list_proof_events,
    save_indexer_cursor,
)

CONTRACT_A = "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAXGI"
CONTRACT_B = "CBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBXGI"
PROOF_1 = "aa" * 32
PROOF_2 = "bb" * 32
TX_1 = "11" * 32
TX_2 = "22" * 32


@pytest.fixture(autouse=True)
def _reset_indexer_state():
    """Ensure each test starts with a clean in-memory indexer cursor/manifest."""
    save_indexer_cursor("soroban_events", "")
    yield
    save_indexer_cursor("soroban_events", "")


# ---------------------------------------------------------------------------
# Unit Tests: Canonical Building & Fail-Closed Integrity Verification
# ---------------------------------------------------------------------------


def test_build_and_verify_checkpoint_manifest_binds_all_fields():
    manifest = build_checkpoint_manifest(
        network="TestNet",
        contract_id=CONTRACT_A,
        schema_version="1",
        cursor="0000000501-0000000001",
        observed_ledger=501,
    )

    assert manifest.manifest_version == INDEXER_CHECKPOINT_MANIFEST_VERSION
    assert manifest.network == "testnet"
    assert manifest.contract_id == CONTRACT_A
    assert manifest.schema_version == "1"
    assert manifest.cursor == "0000000501-0000000001"
    assert manifest.observed_ledger == 501
    assert len(manifest.manifest_hash) == 64

    verified = verify_checkpoint_manifest(manifest.to_dict())
    assert verified == manifest


@pytest.mark.parametrize(
    "field,tampered_value",
    [
        ("network", "mainnet"),
        ("contract_id", CONTRACT_B),
        ("schema_version", "2"),
        ("observed_ledger", 502),
        ("cursor", "0000000502-0000000001"),
        ("manifest_hash", "0" * 64),
    ],
)
def test_verify_checkpoint_manifest_rejects_tampering(field, tampered_value):
    manifest = build_checkpoint_manifest(
        network="testnet",
        contract_id=CONTRACT_A,
        schema_version="1",
        cursor="cursor-501",
        observed_ledger=501,
    )
    tampered = manifest.to_dict()
    tampered[field] = tampered_value

    with pytest.raises(CheckpointVerificationError) as exc_info:
        verify_checkpoint_manifest(tampered)
    assert exc_info.value.reason == "manifest_integrity_failed"


def test_verify_checkpoint_manifest_rejects_malformed_and_boundary_inputs():
    manifest = build_checkpoint_manifest(
        network="testnet",
        contract_id=CONTRACT_A,
        schema_version="1",
        cursor="cursor-1",
        observed_ledger=0,  # boundary: ledger 0 is valid
    )
    assert verify_checkpoint_manifest(manifest).observed_ledger == 0

    # Missing required field
    missing_field = manifest.to_dict()
    del missing_field["schema_version"]
    with pytest.raises(CheckpointVerificationError) as exc_info:
        verify_checkpoint_manifest(missing_field)
    assert exc_info.value.reason == "malformed_manifest"

    # Negative observed_ledger
    neg_ledger = manifest.to_dict()
    neg_ledger["observed_ledger"] = -1
    with pytest.raises(CheckpointVerificationError) as exc_info:
        verify_checkpoint_manifest(neg_ledger)
    assert exc_info.value.reason == "malformed_manifest"

    # Boolean observed_ledger (bool is subclass of int in Python)
    bool_ledger = manifest.to_dict()
    bool_ledger["observed_ledger"] = True
    with pytest.raises(CheckpointVerificationError) as exc_info:
        verify_checkpoint_manifest(bool_ledger)
    assert exc_info.value.reason == "malformed_manifest"

    # Unsupported manifest_version
    bad_ver = manifest.to_dict()
    bad_ver["manifest_version"] = 99
    with pytest.raises(CheckpointVerificationError) as exc_info:
        verify_checkpoint_manifest(bad_ver)
    assert exc_info.value.reason == "unsupported_manifest_version"


# ---------------------------------------------------------------------------
# Unit Tests: Resume Compatibility Checks
# ---------------------------------------------------------------------------


def test_validate_checkpoint_resume_rejects_incompatible_targets():
    manifest = build_checkpoint_manifest(
        network="testnet",
        contract_id=CONTRACT_A,
        schema_version="1",
        cursor="cursor-500",
        observed_ledger=500,
    )

    # Compatible resume (same ledger or advancing ledger)
    assert (
        validate_checkpoint_resume(
            manifest,
            network="testnet",
            contract_id=CONTRACT_A,
            schema_version="1",
            current_ledger=500,
        )
        == manifest
    )
    assert (
        validate_checkpoint_resume(
            manifest,
            network="testnet",
            contract_id=CONTRACT_A,
            schema_version="1",
            current_ledger=510,
        )
        == manifest
    )

    # Network mismatch
    with pytest.raises(IncompatibleCheckpointError) as exc_info:
        validate_checkpoint_resume(
            manifest,
            network="mainnet",
            contract_id=CONTRACT_A,
            schema_version="1",
        )
    assert exc_info.value.reason == "network_mismatch"

    # Contract mismatch
    with pytest.raises(IncompatibleCheckpointError) as exc_info:
        validate_checkpoint_resume(
            manifest,
            network="testnet",
            contract_id=CONTRACT_B,
            schema_version="1",
        )
    assert exc_info.value.reason == "contract_mismatch"

    # Schema mismatch
    with pytest.raises(IncompatibleCheckpointError) as exc_info:
        validate_checkpoint_resume(
            manifest,
            network="testnet",
            contract_id=CONTRACT_A,
            schema_version="2",
        )
    assert exc_info.value.reason == "schema_mismatch"

    # Observed ledger regression
    with pytest.raises(IncompatibleCheckpointError) as exc_info:
        validate_checkpoint_resume(
            manifest,
            network="testnet",
            contract_id=CONTRACT_A,
            schema_version="1",
            current_ledger=499,
        )
    assert exc_info.value.reason == "ledger_regression"


def test_resolve_indexer_network_infers_from_rpc_url(monkeypatch):
    monkeypatch.delenv("STELLAR_NETWORK", raising=False)
    monkeypatch.delenv("HARPOCRATES_NETWORK", raising=False)
    monkeypatch.delenv("RELEASE_NETWORK", raising=False)

    assert resolve_indexer_network(rpc_url=DEFAULT_SOROBAN_RPC_URL) == "testnet"
    assert resolve_indexer_network(rpc_url="https://soroban-rpc.mainnet.stellar.gateway.fm") == "mainnet"
    assert resolve_indexer_network(rpc_url="https://rpc-futurenet.stellar.org") == "futurenet"
    assert resolve_indexer_network(rpc_url="http://localhost:8000/soroban/rpc") == "standalone"
    assert resolve_indexer_network(network="MainNet", rpc_url=DEFAULT_SOROBAN_RPC_URL) == "mainnet"


# ---------------------------------------------------------------------------
# File Persistence Tests (Temporary State Directory)
# ---------------------------------------------------------------------------


def test_checkpoint_manifest_file_roundtrip_and_tamper_detection(tmp_path: Path):
    manifest_file = tmp_path / "state" / "indexer_checkpoint.json"
    assert load_checkpoint_manifest_file(manifest_file) is None

    manifest = build_checkpoint_manifest(
        network="testnet",
        contract_id=CONTRACT_A,
        schema_version="1",
        cursor="cursor-700",
        observed_ledger=700,
    )
    write_checkpoint_manifest_file(manifest_file, manifest)
    assert manifest_file.exists()

    loaded = load_checkpoint_manifest_file(manifest_file)
    assert loaded == manifest

    # Tamper with file on disk -> fail closed
    raw = json.loads(manifest_file.read_text(encoding="utf-8"))
    raw["observed_ledger"] = 999
    manifest_file.write_text(json.dumps(raw), encoding="utf-8")

    with pytest.raises(CheckpointVerificationError) as exc_info:
        load_checkpoint_manifest_file(manifest_file)
    assert exc_info.value.reason == "manifest_integrity_failed"


# ---------------------------------------------------------------------------
# End-to-End poll_indexer_once: Reject Incompatible Resume Without Mutating Projection
# ---------------------------------------------------------------------------


@mock.patch("chain_indexer.fetch_latest_ledger", return_value=500)
@mock.patch("chain_indexer.fetch_contract_events")
def test_poll_indexer_once_persists_manifest_and_rejects_incompatible_resume_without_mutation(
    mock_fetch_events,
    mock_latest,
    tmp_path: Path,
):
    manifest_file = tmp_path / "checkpoint.json"

    # Run 1: Fresh start -> indexes 1 event and writes verified checkpoint manifest
    mock_fetch_events.return_value = {
        "cursor": "cursor-501",
        "latestLedger": 501,
        "events": [
            {
                "txHash": TX_1,
                "ledger": 501,
                "id": "0000000501-0000000001",
                "topic": ["proof", "revoke", PROOF_1],
            }
        ],
    }

    summary1 = poll_indexer_once(
        contract_id=CONTRACT_A,
        network="testnet",
        schema_version="1",
        manifest_path=manifest_file,
    )
    assert summary1["indexed"] == 1
    assert summary1["new_cursor"] == "cursor-501"
    assert summary1["checkpoint_manifest"]["network"] == "testnet"
    assert summary1["checkpoint_manifest"]["contract_id"] == CONTRACT_A
    assert summary1["checkpoint_manifest"]["schema_version"] == "1"
    assert summary1["checkpoint_manifest"]["observed_ledger"] == 501

    stored_before = get_indexer_checkpoint_manifest()
    assert stored_before == summary1["checkpoint_manifest"]
    events_before, _ = list_proof_events(limit=100)
    count_before = len(events_before)

    # Run 2: Incompatible contract resume -> MUST reject before RPC fetch and without mutating projection
    mock_fetch_events.reset_mock()
    mock_fetch_events.return_value = {
        "cursor": "cursor-502",
        "latestLedger": 502,
        "events": [
            {
                "txHash": TX_2,
                "ledger": 502,
                "id": "0000000502-0000000001",
                "topic": ["proof", "revoke", PROOF_2],
            }
        ],
    }

    with pytest.raises(IncompatibleCheckpointError) as exc_info:
        poll_indexer_once(
            contract_id=CONTRACT_B,
            network="testnet",
            schema_version="1",
            manifest_path=manifest_file,
        )
    assert exc_info.value.reason == "contract_mismatch"
    assert not mock_fetch_events.called

    # Trusted projection and stored checkpoint are completely untouched
    events_after, _ = list_proof_events(limit=100)
    assert len(events_after) == count_before
    assert get_indexer_cursor() == "cursor-501"
    assert get_indexer_checkpoint_manifest() == stored_before

    # Run 3: Incompatible network resume -> rejected without mutation
    with pytest.raises(IncompatibleCheckpointError) as exc_info:
        poll_indexer_once(
            contract_id=CONTRACT_A,
            network="mainnet",
            schema_version="1",
            manifest_path=manifest_file,
        )
    assert exc_info.value.reason == "network_mismatch"
    assert not mock_fetch_events.called
    assert get_indexer_cursor() == "cursor-501"

    # Run 4: Incompatible schema resume -> rejected without mutation
    with pytest.raises(IncompatibleCheckpointError) as exc_info:
        poll_indexer_once(
            contract_id=CONTRACT_A,
            network="testnet",
            schema_version="2",
            manifest_path=manifest_file,
        )
    assert exc_info.value.reason == "schema_mismatch"
    assert not mock_fetch_events.called
    assert get_indexer_cursor() == "cursor-501"


@mock.patch("chain_indexer.fetch_latest_ledger", return_value=600)
@mock.patch("chain_indexer.fetch_contract_events")
def test_poll_indexer_once_rejects_ledger_regression_without_mutating_projection(
    mock_fetch_events,
    mock_latest,
    tmp_path: Path,
):
    manifest_file = tmp_path / "checkpoint_regression.json"

    # Establish checkpoint at ledger 605
    mock_fetch_events.return_value = {
        "cursor": "cursor-605",
        "latestLedger": 605,
        "events": [],
    }
    summary1 = poll_indexer_once(
        contract_id=CONTRACT_A,
        network="testnet",
        schema_version="1",
        manifest_path=manifest_file,
    )
    assert summary1["checkpoint_manifest"]["observed_ledger"] == 605
    events_before, _ = list_proof_events(limit=100)
    count_before = len(events_before)

    # RPC returns a regressed ledger (600 < 605) with a new event -> MUST reject before ingestion
    mock_fetch_events.return_value = {
        "cursor": "cursor-600",
        "latestLedger": 600,
        "events": [
            {
                "txHash": "33" * 32,
                "ledger": 600,
                "id": "0000000600-0000000001",
                "topic": ["proof", "revoke", "cc" * 32],
            }
        ],
    }

    with pytest.raises(IncompatibleCheckpointError) as exc_info:
        poll_indexer_once(
            contract_id=CONTRACT_A,
            network="testnet",
            schema_version="1",
            manifest_path=manifest_file,
        )
    assert exc_info.value.reason == "ledger_regression"

    # Projection and cursor/manifest remain untouched
    events_after, _ = list_proof_events(limit=100)
    assert len(events_after) == count_before
    assert get_indexer_cursor() == "cursor-605"
    assert load_checkpoint_manifest_file(manifest_file).observed_ledger == 605


@mock.patch("chain_indexer.fetch_contract_events")
def test_poll_indexer_once_require_verified_manifest_rejects_unverified_legacy_cursor(
    mock_fetch_events,
):
    save_indexer_cursor("soroban_events", "legacy-cursor-100", ledger=100)

    with pytest.raises(IncompatibleCheckpointError) as exc_info:
        poll_indexer_once(
            contract_id=CONTRACT_A,
            network="testnet",
            schema_version="1",
            require_verified_manifest=True,
        )
    assert exc_info.value.reason == "missing_checkpoint_manifest"
    assert not mock_fetch_events.called
    assert get_indexer_cursor() == "legacy-cursor-100"
