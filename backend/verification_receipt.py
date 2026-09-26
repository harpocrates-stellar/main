"""Stable, typed response envelopes for verification operations."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Literal, TypedDict


class VerificationReceipt(TypedDict):
    """The public contract returned by a verification request."""

    protocol: Literal["harpocrates-verification-receipt"]
    version: Literal[1]
    status: Literal["accepted", "verified", "unverified"]
    evidence_digest: str
    schema_hash: str | None
    verification_method: Literal["selective_disclosure"]
    issued_at: str
    request_id: str
    reason_code: str | None


def build_verification_receipt(*, evidence_digest: str, schema_hash: str | None, request_id: str, status: Literal["accepted", "verified", "unverified"] = "accepted", reason_code: str | None = None) -> VerificationReceipt:
    """Build a JSON-safe receipt without exposing proof material or secrets."""
    return {
        "protocol": "harpocrates-verification-receipt",
        "version": 1,
        "status": status,
        "evidence_digest": evidence_digest,
        "schema_hash": schema_hash,
        "verification_method": "selective_disclosure",
        "issued_at": datetime.now(timezone.utc).isoformat(),
        "request_id": request_id,
        "reason_code": reason_code,
    }
