#!/usr/bin/env python3
"""
Generate privacy regression fixtures.

This script generates synthetic test vectors for privacy regression testing.
All values are synthetic — no real media, secrets, witnesses, or keys.
"""

from __future__ import annotations

import json
import hashlib
import secrets
from datetime import datetime, timezone, timedelta
from pathlib import Path

FIXTURES_DIR = Path(__file__).parent

# Constants for synthetic data generation
SYNTHETIC_SOURCE_HASH = "ab" * 32
SYNTHETIC_PROOF_ID = "cd" * 32
SYNTHETIC_NULLIFIER = "ef" * 32
SYNTHETIC_MERKLE_ROOT = "ab" * 32
SYNTHETIC_CONTRACT_ID = "CAAAAAAAAABCD1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890"
SYNTHETIC_ISSUER_DID = "did:example:issuer"
SYNTHETIC_ATTESTER_DID = "did:example:attester"
SYNTHETIC_TSA_URL = "https://tsa.example.com"
SYNTHETIC_RPC_URL = "https://rpc.example.com"
SYNTHETIC_INDEXER_URL = "https://indexer.example.com"
SYNTHETIC_VERIFIER_URL = "https://verifier.example.com"
SYNTHETIC_ORACLE_URL = "https://oracle.example.com"

def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")

def _past_iso(days: int) -> str:
    return (datetime.now(timezone.utc) - timedelta(days=days)).isoformat().replace("+00:00", "Z")

def _future_iso(days: int) -> str:
    return (datetime.now(timezone.utc) + timedelta(days=days)).isoformat().replace("+00:00", "Z")

def _random_hex(length: int) -> str:
    return secrets.token_hex(length // 2)

def _base_valid_metadata(version: int = 1, tier: str = "silent", **overrides) -> dict:
    base = {
        "protocol": "harpocrates",
        "version": version,
        "tier": tier,
        "sourceHash": SYNTHETIC_SOURCE_HASH,
        "proofId": SYNTHETIC_PROOF_ID,
        "timestamp": _now_iso(),
    }
    base.update(overrides)
    return base

def generate_malformed() -> dict:
    cases = [
        {
            "id": "mal-001-invalid-hex-source-hash",
            "description": "sourceHash with non-hex characters must be rejected",
            "input": _base_valid_metadata(sourceHash="g" * 64),
            "expect": {
                "reject_code": "invalid_hash_format",
                "must_not_log": [],
                "must_not_store": []
            }
        },
        {
            "id": "mal-002-invalid-hex-proof-id",
            "description": "proofId with non-hex characters must be rejected",
            "input": _base_valid_metadata(proofId="z" * 64),
            "expect": {
                "reject_code": "invalid_hash_format",
                "must_not_log": [],
                "must_not_store": []
            }
        },
        {
            "id": "mal-003-short-source-hash",
            "description": "sourceHash with 63 characters (one short) must be rejected",
            "input": _base_valid_metadata(sourceHash="a" * 63),
            "expect": {
                "reject_code": "invalid_hash_format",
                "must_not_log": [],
                "must_not_store": []
            }
        },
        {
            "id": "mal-004-long-source-hash",
            "description": "sourceHash with 65 characters (one over) must be rejected",
            "input": _base_valid_metadata(sourceHash="a" * 65),
            "expect": {
                "reject_code": "invalid_hash_format",
                "must_not_log": [],
                "must_not_store": []
            }
        },
        {
            "id": "mal-005-wrong-protocol",
            "description": "Unknown protocol must be rejected",
            "input": _base_valid_metadata(protocol="unknown-protocol"),
            "expect": {
                "reject_code": "unsupported_protocol",
                "must_not_log": [],
                "must_not_store": []
            }
        },
        {
            "id": "mal-006-invalid-tier",
            "description": "Invalid tier must be rejected",
            "input": _base_valid_metadata(tier="premium"),
            "expect": {
                "reject_code": "invalid_tier",
                "must_not_log": [],
                "must_not_store": []
            }
        },
        {
            "id": "mal-007-version-as-string",
            "description": "Version as string instead of number must be rejected",
            "input": {**_base_valid_metadata(), "version": "1"},
            "expect": {
                "reject_code": "invalid_version_type",
                "must_not_log": [],
                "must_not_store": []
            }
        },
        {
            "id": "mal-008-missing-timestamp",
            "description": "Missing timestamp field must be rejected",
            "input": {k: v for k, v in _base_valid_metadata().items() if k != "timestamp"},
            "expect": {
                "reject_code": "missing_required_field",
                "must_not_log": [],
                "must_not_store": []
            }
        },
        {
            "id": "mal-009-naive-timestamp",
            "description": "Naive datetime (no timezone) must be rejected",
            "input": _base_valid_metadata(timestamp="2026-07-24T12:00:00"),
            "expect": {
                "reject_code": "invalid_timestamp_format",
                "must_not_log": [],
                "must_not_store": []
            }
        },
        {
            "id": "mal-010-future-timestamp",
            "description": "Timestamp in the future beyond drift window must be rejected",
            "input": _base_valid_metadata(timestamp=_future_iso(365 * 100)),
            "expect": {
                "reject_code": "timestamp_out_of_range",
                "must_not_log": [],
                "must_not_store": []
            }
        },
        {
            "id": "mal-011-null-input",
            "description": "Null as top-level input must be rejected",
            "input": None,
            "expect": {
                "reject_code": "invalid_input_type",
                "must_not_log": [],
                "must_not_store": []
            }
        },
        {
            "id": "mal-012-array-input",
            "description": "Array as top-level input must be rejected",
            "input": [],
            "expect": {
                "reject_code": "invalid_input_type",
                "must_not_log": [],
                "must_not_store": []
            }
        },
        {
            "id": "mal-013-nested-secret-proof-field",
            "description": "Nested 'proof' field containing sensitive data must be redacted and rejected",
            "input": _base_valid_metadata(version=2, inner={"proof": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.sensitive-jwt-token"}),
            "expect": {
                "reject_code": "sensitive_field_detected",
                "must_not_log": ["eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.sensitive-jwt-token"],
                "must_not_store": ["inner.proof"]
            }
        },
        {
            "id": "mal-014-nested-nullifier-secret",
            "description": "Nested 'nullifierSecret' field must be redacted and rejected",
            "input": _base_valid_metadata(version=2, outer={"middle": {"nullifierSecret": "super-secret-nullifier-value"}}),
            "expect": {
                "reject_code": "sensitive_field_detected",
                "must_not_log": ["super-secret-nullifier-value"],
                "must_not_store": ["outer.middle.nullifierSecret"]
            }
        },
        {
            "id": "mal-015-witness-data-in-list",
            "description": "witnessData in list items must be redacted and rejected",
            "input": _base_valid_metadata(version=2, items=[
                {"witnessData": "witness-value-1", "index": 0},
                {"witnessData": "witness-value-2", "index": 1}
            ]),
            "expect": {
                "reject_code": "sensitive_field_detected",
                "must_not_log": ["witness-value-1", "witness-value-2"],
                "must_not_store": ["items[0].witnessData", "items[1].witnessData"]
            }
        },
        {
            "id": "mal-016-public-inputs-field",
            "description": "publicInputs field must be redacted and rejected",
            "input": _base_valid_metadata(version=2, publicInputs=["input1", "input2", "input3"]),
            "expect": {
                "reject_code": "sensitive_field_detected",
                "must_not_log": ["input1", "input2", "input3"],
                "must_not_store": ["publicInputs"]
            }
        },
        {
            "id": "mal-017-credential-secret-field",
            "description": "credentialSecret field must be redacted and rejected",
            "input": _base_valid_metadata(version=2, credentialSecret="abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"),
            "expect": {
                "reject_code": "sensitive_field_detected",
                "must_not_log": ["abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"],
                "must_not_store": ["credentialSecret"]
            }
        },
        {
            "id": "mal-018-authorization-header",
            "description": "Authorization header with bearer token must be redacted and rejected",
            "input": _base_valid_metadata(version=2, authorization="Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.secret-token"),
            "expect": {
                "reject_code": "sensitive_field_detected",
                "must_not_log": ["eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.secret-token"],
                "must_not_store": ["authorization"]
            }
        }
    ]

    return {
        "schemaVersion": 1,
        "category": "malformed",
        "description": "Malformed input vectors that must be rejected at the privacy boundary before any processing",
        "cases": cases
    }

def generate_oversized() -> dict:
    max_payload = 65536  # 64 KiB

    cases = [
        {
            "id": "ovr-001-payload-exceeds-64kib",
            "description": "Envelope payload exceeding 64 KiB limit must be rejected",
            "input": _base_valid_metadata(version=2, big_field="x" * (max_payload + 1)),
            "expect": {
                "reject_code": "payload_too_large",
                "must_not_log": [],
                "must_not_store": ["big_field"]
            }
        },
        {
            "id": "ovr-002-single-field-exceeds-limit",
            "description": "Single field value far exceeding 64 KiB must be rejected",
            "input": _base_valid_metadata(version=2, giant="A" * (max_payload * 2)),
            "expect": {
                "reject_code": "payload_too_large",
                "must_not_log": [],
                "must_not_store": ["giant"]
            }
        },
        {
            "id": "ovr-003-many-fields-exceed-limit",
            "description": "Many small fields collectively exceeding 64 KiB must be rejected",
            "input": _base_valid_metadata(version=2, **{f"field_{i}": "x" * 200 for i in range(500)}),
            "expect": {
                "reject_code": "payload_too_large",
                "must_not_log": [],
                "must_not_store": []
            }
        },
        {
            "id": "ovr-004-deeply-nested-structure",
            "description": "Excessively deep nesting must be rejected",
            "input": _base_valid_metadata(version=2, deep={"level1": {"level2": {"level3": {"level4": {"level5": {"level6": {"level7": {"level8": {"level9": {"level10": "deep"}}}}}}}}}}),
            "expect": {
                "reject_code": "nesting_depth_exceeded",
                "must_not_log": [],
                "must_not_store": []
            }
        },
        {
            "id": "ovr-005-large-array-in-field",
            "description": "Large array in extra field must be rejected",
            "input": _base_valid_metadata(version=2, largeArray=["item" * 100] * 1000),
            "expect": {
                "reject_code": "payload_too_large",
                "must_not_log": [],
                "must_not_store": ["largeArray"]
            }
        }
    ]

    return {
        "schemaVersion": 1,
        "category": "oversized",
        "description": "Oversized input vectors that must be rejected at the privacy boundary before any processing",
        "cases": cases
    }

def generate_expired() -> dict:
    cases = [
        {
            "id": "exp-001-proof-expired",
            "description": "Proof past its validity window must be rejected",
            "input": _base_valid_metadata(validUntil=_past_iso(365 * 2)),
            "expect": {
                "reject_code": "proof_expired",
                "must_not_log": [],
                "must_not_store": []
            }
        },
        {
            "id": "exp-002-timestamp-too-old",
            "description": "Timestamp older than maximum allowed age must be rejected",
            "input": _base_valid_metadata(timestamp=_past_iso(365 * 20)),
            "expect": {
                "reject_code": "timestamp_too_old",
                "must_not_log": [],
                "must_not_store": []
            }
        },
        {
            "id": "exp-003-rfc3161-chain-expired",
            "description": "RFC 3161 timestamp chain with expired leaf must be rejected",
            "input": _base_valid_metadata(rfc3161Chain={
                "chain": ["base64-cert-1", "base64-cert-2"],
                "trustRoots": ["base64-root"],
                "genTime": _past_iso(365 * 3),
                "expiresAt": _past_iso(365 * 2)
            }),
            "expect": {
                "reject_code": "rfc3161_chain_expired",
                "must_not_log": [],
                "must_not_store": []
            }
        },
        {
            "id": "exp-004-credential-expired",
            "description": "Expired credential in proof must be rejected",
            "input": _base_valid_metadata(version=2, tier="source", credential={
                "type": "VerifiableCredential",
                "issuer": SYNTHETIC_ISSUER_DID,
                "validFrom": _past_iso(365 * 3),
                "validUntil": _past_iso(365 * 2),
                "credentialSubject": {"id": "did:example:subject"}
            }),
            "expect": {
                "reject_code": "credential_expired",
                "must_not_log": [],
                "must_not_store": ["credential"]
            }
        },
        {
            "id": "exp-005-attestation-expired",
            "description": "Expired attestation must be rejected",
            "input": _base_valid_metadata(version=2, tier="seal", attestation={
                "type": "TimeAttestation",
                "issuedAt": _past_iso(365 * 3),
                "expiresAt": _past_iso(365 * 2),
                "attester": SYNTHETIC_ATTESTER_DID
            }),
            "expect": {
                "reject_code": "attestation_expired",
                "must_not_log": [],
                "must_not_store": ["attestation"]
            }
        },
        {
            "id": "exp-006-nullifier-epoch-expired",
            "description": "Nullifier from expired epoch must be rejected",
            "input": _base_valid_metadata(version=2, nullifier=SYNTHETIC_NULLIFIER, epoch=0, currentEpoch=100),
            "expect": {
                "reject_code": "nullifier_epoch_expired",
                "must_not_log": [SYNTHETIC_NULLIFIER],
                "must_not_store": ["nullifier"]
            }
        }
    ]

    return {
        "schemaVersion": 1,
        "category": "expired",
        "description": "Expired proof, timestamp, or credential vectors that must be rejected at the privacy boundary",
        "cases": cases
    }

def generate_revoked() -> dict:
    cases = [
        {
            "id": "rev-001-nullifier-revoked",
            "description": "Revoked nullifier must be rejected",
            "input": _base_valid_metadata(version=2, nullifier=SYNTHETIC_NULLIFIER, revocationStatus="revoked"),
            "expect": {
                "reject_code": "nullifier_revoked",
                "must_not_log": [SYNTHETIC_NULLIFIER],
                "must_not_store": ["nullifier"]
            }
        },
        {
            "id": "rev-002-credential-revoked",
            "description": "Revoked credential must be rejected",
            "input": _base_valid_metadata(version=2, tier="source", credential={
                "type": "VerifiableCredential",
                "issuer": SYNTHETIC_ISSUER_DID,
                "id": "cred-123",
                "revocationStatus": "revoked",
                "revocationReason": "compromised"
            }),
            "expect": {
                "reject_code": "credential_revoked",
                "must_not_log": [],
                "must_not_store": ["credential"]
            }
        },
        {
            "id": "rev-003-attestation-revoked",
            "description": "Revoked attestation must be rejected",
            "input": _base_valid_metadata(version=2, tier="seal", attestation={
                "type": "TimeAttestation",
                "id": "att-456",
                "revoked": True,
                "revocationDate": _past_iso(60)
            }),
            "expect": {
                "reject_code": "attestation_revoked",
                "must_not_log": [],
                "must_not_store": ["attestation"]
            }
        },
        {
            "id": "rev-004-issuer-key-revoked",
            "description": "Proof signed by revoked issuer key must be rejected",
            "input": _base_valid_metadata(version=2, issuer={
                "did": SYNTHETIC_ISSUER_DID,
                "keyId": "key-789",
                "revoked": True,
                "revokedAt": _past_iso(90)
            }),
            "expect": {
                "reject_code": "issuer_key_revoked",
                "must_not_log": [],
                "must_not_store": ["issuer"]
            }
        },
        {
            "id": "rev-005-merkle-root-revoked",
            "description": "Proof against revoked merkle root must be rejected",
            "input": _base_valid_metadata(version=2, merkleRoot=SYNTHETIC_MERKLE_ROOT, merkleRootStatus="revoked"),
            "expect": {
                "reject_code": "merkle_root_revoked",
                "must_not_log": [],
                "must_not_store": []
            }
        },
        {
            "id": "rev-006-contract-revoked",
            "description": "Proof for revoked contract must be rejected",
            "input": _base_valid_metadata(contractId=SYNTHETIC_CONTRACT_ID, contractStatus="revoked"),
            "expect": {
                "reject_code": "contract_revoked",
                "must_not_log": [],
                "must_not_store": []
            }
        }
    ]

    return {
        "schemaVersion": 1,
        "category": "revoked",
        "description": "Revoked nullifier, credential, or attestation vectors that must be rejected at the privacy boundary",
        "cases": cases
    }

def generate_unsupported() -> dict:
    cases = [
        {
            "id": "uns-001-unsupported-protocol-version",
            "description": "Unsupported protocol version must be rejected",
            "input": _base_valid_metadata(version=99),
            "expect": {
                "reject_code": "unsupported_version",
                "must_not_log": [],
                "must_not_store": []
            }
        },
        {
            "id": "uns-002-deprecated-tier",
            "description": "Deprecated tier must be rejected",
            "input": _base_valid_metadata(tier="legacy"),
            "expect": {
                "reject_code": "deprecated_tier",
                "must_not_log": [],
                "must_not_store": []
            }
        },
        {
            "id": "uns-003-unsupported-proof-type",
            "description": "Unsupported proof type must be rejected",
            "input": _base_valid_metadata(version=2, proofType="unsupported-zk-snark"),
            "expect": {
                "reject_code": "unsupported_proof_type",
                "must_not_log": [],
                "must_not_store": []
            }
        },
        {
            "id": "uns-004-unsupported-aggregation",
            "description": "Unsupported aggregation method must be rejected",
            "input": _base_valid_metadata(version=2, aggregation="unsupported-method"),
            "expect": {
                "reject_code": "unsupported_aggregation",
                "must_not_log": [],
                "must_not_store": []
            }
        },
        {
            "id": "uns-005-unsupported-selector",
            "description": "Unsupported selective disclosure selector must be rejected",
            "input": _base_valid_metadata(version=2, tier="source", selector={
                "type": "unsupported-selector-type",
                "fields": ["field1", "field2"]
            }),
            "expect": {
                "reject_code": "unsupported_selector",
                "must_not_log": [],
                "must_not_store": []
            }
        },
        {
            "id": "uns-006-unsupported-curve",
            "description": "Unsupported elliptic curve must be rejected",
            "input": _base_valid_metadata(version=2, curve="unsupported-curve"),
            "expect": {
                "reject_code": "unsupported_curve",
                "must_not_log": [],
                "must_not_store": []
            }
        },
        {
            "id": "uns-007-unsupported-hash-algorithm",
            "description": "Unsupported hash algorithm must be rejected",
            "input": _base_valid_metadata(version=2, hashAlgorithm="MD5"),
            "expect": {
                "reject_code": "unsupported_hash_algorithm",
                "must_not_log": [],
                "must_not_store": []
            }
        },
        {
            "id": "uns-008-unsupported-signature-scheme",
            "description": "Unsupported signature scheme must be rejected",
            "input": _base_valid_metadata(version=2, tier="seal", signatureScheme="RSA-PKCS1-v1_5"),
            "expect": {
                "reject_code": "unsupported_signature_scheme",
                "must_not_log": [],
                "must_not_store": []
            }
        },
        {
            "id": "uns-009-unsupported-network",
            "description": "Unsupported network must be rejected",
            "input": _base_valid_metadata(network="Unsupported Network"),
            "expect": {
                "reject_code": "unsupported_network",
                "must_not_log": [],
                "must_not_store": []
            }
        }
    ]

    return {
        "schemaVersion": 1,
        "category": "unsupported",
        "description": "Unsupported protocol version, tier, or feature vectors that must be rejected at the privacy boundary",
        "cases": cases
    }

def generate_dependency_failure() -> dict:
    cases = [
        {
            "id": "dep-001-tsa-timeout",
            "description": "TSA (RFC 3161) request timeout must be handled gracefully",
            "input": _base_valid_metadata(rfc3161={"tsaUrl": SYNTHETIC_TSA_URL, "timeoutMs": 5000}),
            "expect": {
                "reject_code": "tsa_timeout",
                "must_not_log": [],
                "must_not_store": []
            }
        },
        {
            "id": "dep-002-tsa-unreachable",
            "description": "TSA unreachable must be handled gracefully",
            "input": _base_valid_metadata(rfc3161={"tsaUrl": "https://unreachable-tsa.example.com", "timeoutMs": 5000}),
            "expect": {
                "reject_code": "tsa_unreachable",
                "must_not_log": [],
                "must_not_store": []
            }
        },
        {
            "id": "dep-003-rpc-timeout",
            "description": "Stellar RPC request timeout must be handled gracefully",
            "input": _base_valid_metadata(stellarRpc={"url": SYNTHETIC_RPC_URL, "timeoutMs": 10000}),
            "expect": {
                "reject_code": "rpc_timeout",
                "must_not_log": [],
                "must_not_store": []
            }
        },
        {
            "id": "dep-004-rpc-rate-limited",
            "description": "RPC rate limit response must be handled gracefully",
            "input": _base_valid_metadata(stellarRpc={"url": SYNTHETIC_RPC_URL, "rateLimited": True, "retryAfterMs": 60000}),
            "expect": {
                "reject_code": "rpc_rate_limited",
                "must_not_log": [],
                "must_not_store": []
            }
        },
        {
            "id": "dep-005-indexer-unavailable",
            "description": "Indexer service unavailable must be handled gracefully",
            "input": _base_valid_metadata(indexer={"url": SYNTHETIC_INDEXER_URL, "status": "unavailable"}),
            "expect": {
                "reject_code": "indexer_unavailable",
                "must_not_log": [],
                "must_not_store": []
            }
        },
        {
            "id": "dep-006-verifier-service-down",
            "description": "Verifier service down must be handled gracefully",
            "input": _base_valid_metadata(version=2, verifier={"url": SYNTHETIC_VERIFIER_URL, "status": "down"}),
            "expect": {
                "reject_code": "verifier_unavailable",
                "must_not_log": [],
                "must_not_store": []
            }
        },
        {
            "id": "dep-007-database-connection-failed",
            "description": "Database connection failure must be handled gracefully",
            "input": _base_valid_metadata(database={"status": "connection_failed"}),
            "expect": {
                "reject_code": "database_unavailable",
                "must_not_log": [],
                "must_not_store": []
            }
        },
        {
            "id": "dep-008-cache-miss-storm",
            "description": "Cache miss storm must be handled gracefully",
            "input": _base_valid_metadata(cache={"status": "miss_storm", "missRate": 0.99}),
            "expect": {
                "reject_code": "cache_degraded",
                "must_not_log": [],
                "must_not_store": []
            }
        },
        {
            "id": "dep-009-external-oracle-failure",
            "description": "External oracle failure must be handled gracefully",
            "input": _base_valid_metadata(version=2, tier="source", oracle={
                "url": SYNTHETIC_ORACLE_URL,
                "status": "failure",
                "errorCode": "ORACLE_UNAVAILABLE"
            }),
            "expect": {
                "reject_code": "oracle_failure",
                "must_not_log": [],
                "must_not_store": []
            }
        },
        {
            "id": "dep-010-network-partition",
            "description": "Network partition must be handled gracefully",
            "input": _base_valid_metadata(network={"partition": True, "affectedServices": ["rpc", "indexer", "tsa"]}),
            "expect": {
                "reject_code": "network_partition",
                "must_not_log": [],
                "must_not_store": []
            }
        }
    ]

    return {
        "schemaVersion": 1,
        "category": "dependency-failure",
        "description": "Simulated external dependency failure vectors that must be handled gracefully at the privacy boundary",
        "cases": cases
    }

def main() -> None:
    generators = {
        "malformed.json": generate_malformed,
        "oversized.json": generate_oversized,
        "expired.json": generate_expired,
        "revoked.json": generate_revoked,
        "unsupported.json": generate_unsupported,
        "dependency-failure.json": generate_dependency_failure,
    }

    for filename, generator in generators.items():
        filepath = FIXTURES_DIR / filename
        data = generator()
        with open(filepath, "w") as f:
            json.dump(data, f, indent=2)
        print(f"Generated {filepath}")

if __name__ == "__main__":
    main()