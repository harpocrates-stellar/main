from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path
from typing import Any

from tracing import traced


ROOT_DIR = Path(__file__).resolve().parents[1]
SINGLE_SCRIPT_PATH = ROOT_DIR / "zk" / "noir" / "scripts" / "generate-silent-witness-wsl.ps1"
BATCH_SCRIPT_PATH = ROOT_DIR / "zk" / "noir" / "scripts" / "generate-silent-witness-aggregator.sh"
REDACTED_SCRIPT_PATH = ROOT_DIR / "zk" / "noir" / "scripts" / "generate-redacted-derivative-witness.sh"

from verifier_inputs import (
    MAX_AGGREGATION_SIZE,
    MIN_AGGREGATION_SIZE,
    check_aggregation_batch_size,
)


@traced("proof.noir.generate", attributes={"proof.system": "noir"})
def generate_silent_witness(
    video_hash: str,
    credential_secret: str,
    nullifier_secret: str,
    verifier_scope: str = "0",
    epoch: int = 0,
) -> dict[str, Any]:
    """Generate a single Silent Witness proof."""
    completed = subprocess.run(
        [
            "powershell",
            "-NoProfile",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            str(SINGLE_SCRIPT_PATH),
            "-VideoHash",
            video_hash,
            "-CredentialSecret",
            credential_secret,
            "-NullifierSecret",
            nullifier_secret,
            "-VerifierScope",
            verifier_scope,
            "-Epoch",
            str(epoch),
        ],
        cwd=ROOT_DIR,
        check=False,
        capture_output=True,
        text=True,
        timeout=int(os.getenv("NOIR_PROOF_TIMEOUT_SECONDS", "180")),
    )

    if completed.returncode != 0:
        detail = completed.stderr.strip() or completed.stdout.strip()
        raise RuntimeError(detail or "Noir proof generation failed.")

    for line in completed.stdout.splitlines():
        line = line.strip()
        if line.startswith("{") and line.endswith("}"):
            return json.loads(line)

    raise RuntimeError("Noir proof generator did not return JSON.")


@traced("proof.noir.aggregate", attributes={"proof.system": "noir"})
def generate_aggregated_proof(
    video_hashes: list[str],
    credential_secret: str,
    nullifier_secret: str,
) -> dict[str, Any]:
    """Generate a bounded aggregated proof for multiple video hashes.

    Uses the Silent Witness Aggregator circuit to produce a single
    UltraHonk proof covering up to ``MAX_AGGREGATION_SIZE`` (8) video
    hashes under the same credential identity.

    Args:
        video_hashes: Ordered list of 32-byte hex video hashes (1-8).
        credential_secret: Decimal field string for the credential secret.
        nullifier_secret: Decimal field string for the nullifier secret.

    Returns:
        JSON-serialized dictionary with aggregated proof artifacts.

    Raises:
        ValueError: If the batch size is out of bounds.
        RuntimeError: If the Noir/batch process fails.
    """
    batch_size = len(video_hashes)
    try:
        check_aggregation_batch_size(batch_size)
    except Exception as exc:
        raise ValueError(
            f"Batch size must be between {MIN_AGGREGATION_SIZE} and {MAX_AGGREGATION_SIZE} (got {batch_size})"
        ) from exc

    cmd = [
        "bash",
        str(BATCH_SCRIPT_PATH),
        *video_hashes,
        credential_secret,
        nullifier_secret,
    ]

    completed = subprocess.run(
        cmd,
        cwd=ROOT_DIR,
        check=False,
        capture_output=True,
        text=True,
        timeout=int(os.getenv("NOIR_PROOF_TIMEOUT_SECONDS", "300")),
    )

    if completed.returncode != 0:
        detail = completed.stderr.strip() or completed.stdout.strip()
        raise RuntimeError(detail or "Aggregated proof generation failed.")

    for line in completed.stdout.splitlines():
        line = line.strip()
        if line.startswith("{") and line.endswith("}"):
            return json.loads(line)

    raise RuntimeError("Aggregated proof generator did not return JSON.")


@traced("proof.noir.redacted_derivative", attributes={"proof.system": "noir"})
def generate_redacted_derivative_proof(
    video_hash: str,
    derivative_hash: str,
    credential_secret: str,
    nullifier_secret: str,
    redaction_commitment: str,
    verifier_scope: str = "0",
    epoch: int = 0,
) -> dict[str, Any]:
    """Generate a redacted derivative ancestry proof.

    Proves that ``derivative_hash`` is a redacted derivative of
    ``video_hash`` under the same credential identity, without revealing
    the underlying media, redaction witness, or private keys.

    Args:
        video_hash: 32-byte hex hash of the canonical source video.
        derivative_hash: 32-byte hex hash of the redacted derivative.
        credential_secret: Decimal field string for the credential secret.
        nullifier_secret: Decimal field string for the nullifier secret.
        redaction_commitment: Decimal field string committing to the
            redaction witness (never the raw witness itself).
        verifier_scope: Decimal field string scoping the proof.
        epoch: Integer epoch for replay protection.

    Returns:
        JSON-serialized dictionary with redacted derivative proof artifacts.

    Raises:
        ValueError: If inputs are malformed or oversized.
        RuntimeError: If the Noir process fails or returns no JSON.
    """
    if not video_hash or not derivative_hash:
        raise ValueError("video_hash and derivative_hash are required.")
    if len(video_hash) > 128 or len(derivative_hash) > 128:
        raise ValueError("video_hash and derivative_hash must be at most 128 characters.")
    if not redaction_commitment:
        raise ValueError("redaction_commitment is required.")

    cmd = [
        "bash",
        str(REDACTED_SCRIPT_PATH),
        video_hash,
        derivative_hash,
        credential_secret,
        nullifier_secret,
        redaction_commitment,
        verifier_scope,
        str(epoch),
    ]

    completed = subprocess.run(
        cmd,
        cwd=ROOT_DIR,
        check=False,
        capture_output=True,
        text=True,
        timeout=int(os.getenv("NOIR_PROOF_TIMEOUT_SECONDS", "240")),
    )

    if completed.returncode != 0:
        detail = completed.stderr.strip() or completed.stdout.strip()
        raise RuntimeError(detail or "Redacted derivative proof generation failed.")

    for line in completed.stdout.splitlines():
        line = line.strip()
        if line.startswith("{") and line.endswith("}"):
            return json.loads(line)

    raise RuntimeError("Redacted derivative proof generator did not return JSON.")
