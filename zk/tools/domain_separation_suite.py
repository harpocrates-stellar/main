#!/usr/bin/env python3
"""Circuit-level protocol domain separation compatibility suite and vector generator.

Independently derives canonical protocol domain tags, scope field commitments,
circuit statement witnesses, and on-chain public-input frames across every
supported Harpocrates domain tuple:
  - Networks: `testnet` (active deployment), `mainnet`, `local`
  - Protocol versions: `v1` (active deployment), `v2`
  - Verifier scopes: global `0` and canonical `v:<verifier>:p:<purpose>` scopes
  - Statement schemas: `silent_witness/v2`, `silent_witness/v1`,
    `revocation_witness/v1`, and `redacted_ancestry/v1`

Evaluates both circuit-level constraint satisfaction (mirroring Noir assertions
in `silent_witness/src/main.nr`, `harpocrates_common/src/lib.nr`, and
`redacted_ancestry/src/main.nr`) and verifier-boundary frame acceptance to
guarantee fail-closed rejection of proof or nullifier reuse across networks,
verifier scopes, epochs, protocol versions, and circuit families.

Usage:
    python zk/tools/domain_separation_suite.py          # write vector corpus
    python zk/tools/domain_separation_suite.py --check  # verify corpus + run suite
"""

from __future__ import annotations

import argparse
import difflib
import hashlib
import hmac
import json
import sys
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

SUITE_FORMAT = "harpocrates.domain-separation-compatibility"
SUITE_VERSION = 1

REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_VECTOR_PATH = (
    REPO_ROOT / "zk" / "vectors" / "domain_separation_compatibility_v1.json"
)

EXIT_OK = 0
EXIT_CHECK_FAILED = 1
EXIT_USAGE = 2

# =============================================================================
# Independently derived cryptographic domain constants (zero runtime imports from
# backend/verifier_inputs.py or zk/vectors/generate_vectors.py)
# =============================================================================

FIELD_BYTES = 32
BN254_SCALAR_MODULUS = int(
    "30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001",
    16,
)

DIGEST_ALGORITHM_SHA256 = 0
PROTOCOL_ID = "harpocrates"

# Active v1 deployment field elements pinned in harpocrates_common/src/lib.nr
PROTOCOL_FIELD_HARPOCRATES = bytes.fromhex(
    "261e9f6e39e3c1ae6aca9f29e84c10d59c82d5f4b40c21c1b7e3c01ad571c201"
)
VERSION_FIELD_V1 = bytes.fromhex(
    "0c89eff4ec8e39a01e9f19547a0cc9dd7fd2a97d79ba4d94fd32e97a1f5ac623"
)
NETWORK_FIELD_TESTNET = bytes.fromhex(
    "2a2c3f48ce2e3c2f1e6c89b18d64b5f5c1f88a59a0d9bc82cb61a1e8cb77a50f"
)


def _derive_domain_component_field(namespace: str, label: str) -> bytes:
    """Derive a canonical non-zero 32-byte BN254 field element for domain tuples."""
    digest = hashlib.sha256(f"harpocrates:domain:{namespace}:{label}".encode("ascii")).digest()
    reduced = int.from_bytes(digest, "big") % BN254_SCALAR_MODULUS
    if reduced == 0:
        reduced = 1
    return reduced.to_bytes(FIELD_BYTES, "big")


def _ascii_padded_field_bytes(ascii_label: str) -> bytes:
    raw = ascii_label.encode("ascii")
    if len(raw) >= FIELD_BYTES:
        raise ValueError("ASCII domain separator must fit in < 32 bytes for BN254 padding")
    padded = raw.rjust(FIELD_BYTES, b"\x00")
    if int.from_bytes(padded, "big") >= BN254_SCALAR_MODULUS:
        raise ValueError("Encoded ASCII separator exceeds BN254 modulus")
    return padded


def _ascii_padded_field_int(ascii_label: str) -> int:
    return int.from_bytes(_ascii_padded_field_bytes(ascii_label), "big")


SUPPORTED_PROTOCOL_FIELDS: dict[str, bytes] = {
    "harpocrates": PROTOCOL_FIELD_HARPOCRATES,
}

SUPPORTED_PROTOCOL_VERSIONS: dict[str, bytes] = {
    "v1": VERSION_FIELD_V1,
    "v2": _derive_domain_component_field("version", "2"),
}

SUPPORTED_NETWORKS: dict[str, bytes] = {
    "testnet": NETWORK_FIELD_TESTNET,
    "mainnet": _derive_domain_component_field("network", "mainnet"),
    "local": _derive_domain_component_field("network", "local"),
}

SUPPORTED_VERIFIER_SCOPES: tuple[str, ...] = (
    "0",
    "v:verifier-alpha:p:default",
    "v:verifier-alpha:p:attestation",
    "v:verifier-beta:p:default",
)

SCOPED_NULLIFIER_SEPARATORS: dict[str, int] = {
    "v1": _ascii_padded_field_int("HARPOCRATES_SCOPED_NULLIFIER_V1"),
    "v2": _ascii_padded_field_int("HARPOCRATES_SCOPED_NULLIFIER_V2"),
}

REVOCATION_SEPARATORS: dict[str, bytes] = {
    "v1": _ascii_padded_field_bytes("HARPOCRATES_REVOCATION_V1"),
    "v2": _ascii_padded_field_bytes("HARPOCRATES_REVOCATION_V2"),
}

REDACTED_ANCESTRY_SEPARATORS: dict[str, int] = {
    "parent_commit": _ascii_padded_field_int("HP_REDACT_PARENT_V1"),
    "redact_params": _ascii_padded_field_int("HP_REDACT_PARAMS_V1"),
    "derivative": _ascii_padded_field_int("HP_REDACT_DERIV_V1"),
    "ancestry": _ascii_padded_field_int("HP_REDACT_ANCESTRY_V1"),
    "nullifier": _ascii_padded_field_int("HP_REDACT_NULLIFIER_V1"),
}
OPERATION_REDACT_FIELD = int.from_bytes(b"redact", "big")

# Synthetic-only deterministic test witness (matches Noir test seed conventions;
# never derived from real credentials or media).
SYNTHETIC_CREDENTIAL_SECRET = 12345
SYNTHETIC_NULLIFIER_SECRET = 67890
SYNTHETIC_VIDEO_SHA256 = hashlib.sha256(b"harpocrates-domain-suite-synthetic-video-v1").digest()
SYNTHETIC_VIDEO_HI = int.from_bytes(SYNTHETIC_VIDEO_SHA256[:16], "big")
SYNTHETIC_VIDEO_LO = int.from_bytes(SYNTHETIC_VIDEO_SHA256[16:], "big")
SYNTHETIC_EPOCH_DEFAULT = 5
SYNTHETIC_REVOCATION_SEED = 77777


@dataclass(frozen=True)
class DomainContext:
    """Target verifier & circuit domain expectation against which a statement is checked."""

    schema: str
    protocol: str
    protocol_version: str
    network: str
    circuit_version: int
    verifier_scope: str = "0"
    epoch: int = 0


@dataclass(frozen=True)
class CompatibilityVerdict:
    """Result of evaluating a candidate statement against a target `DomainContext`."""

    accepted: bool
    reject_code: str | None = None
    circuit_assert: str | None = None
    layer: str = "both"


def pedersen_model_hash(fields: Sequence[int]) -> int:
    """Deterministic collision-resistant field hash preserving exact Noir tuple structure."""
    hasher = hashlib.sha256(b"harpocrates:domain-suite:pedersen-model:v1")
    hasher.update(len(fields).to_bytes(4, "big"))
    for elem in fields:
        if elem < 0 or elem >= BN254_SCALAR_MODULUS:
            raise ValueError("Field element outside canonical BN254 scalar field")
        hasher.update(elem.to_bytes(FIELD_BYTES, "big"))
    reduced = int.from_bytes(hasher.digest(), "big") % BN254_SCALAR_MODULUS
    return 1 if reduced == 0 else reduced


def derive_wire_domain_tag(
    protocol_field: bytes,
    version_field: bytes,
    network_field: bytes,
) -> bytes:
    """Compute wire `domain_tag = SHA-256(protocol_field || version_field || network_field)`."""
    if (
        len(protocol_field) != FIELD_BYTES
        or len(version_field) != FIELD_BYTES
        or len(network_field) != FIELD_BYTES
    ):
        raise ValueError("Each domain component must be exactly 32 bytes")
    return hashlib.sha256(protocol_field + version_field + network_field).digest()


def derive_in_circuit_domain_tag(
    protocol_field: bytes,
    version_field: bytes,
    network_field: bytes,
) -> int:
    """Compute in-circuit `expected_domain_tag()` field commitment over the 3 components."""
    return pedersen_model_hash(
        [
            int.from_bytes(protocol_field, "big"),
            int.from_bytes(version_field, "big"),
            int.from_bytes(network_field, "big"),
        ]
    )


def derive_scope_field_int(scope_label: str) -> int:
    """Independently derive canonical scope field element from `0` or `v:<id>:p:<purpose>`."""
    if scope_label == "0":
        return 0
    digest = hashlib.sha256(f"harpocrates:scope:{scope_label}".encode("ascii")).digest()
    reduced = int.from_bytes(digest, "big") % BN254_SCALAR_MODULUS
    return 1 if reduced == 0 else reduced


def compute_scoped_nullifier_int(
    credential_secret: int,
    nullifier_secret: int,
    video_hash_hi: int,
    video_hash_lo: int,
    verifier_scope_field: int,
    epoch: int,
    *,
    protocol_version: str = "v1",
) -> int:
    """Mirror `harpocrates_common::compute_scoped_nullifier` for `protocol_version`."""
    sep = SCOPED_NULLIFIER_SEPARATORS[protocol_version]
    scope_hash = pedersen_model_hash([sep, verifier_scope_field, epoch])
    evidence_digest = pedersen_model_hash(
        [DIGEST_ALGORITHM_SHA256, video_hash_hi, video_hash_lo, scope_hash]
    )
    return pedersen_model_hash([credential_secret, nullifier_secret, evidence_digest])


def encode_u32_trailer(version: int) -> bytes:
    if version < 0 or version > 0xFFFFFFFF:
        raise ValueError("circuit_version must fit in u32")
    return (b"\x00" * 28) + version.to_bytes(4, "big")


def encode_silent_witness_v2_frame(
    *,
    video_hash_hi: int,
    video_hash_lo: int,
    credential_root: int,
    nullifier: int,
    verifier_scope_field: int,
    epoch: int,
    domain_tag: bytes,
    circuit_version_bytes: bytes,
) -> bytes:
    return b"".join(
        [
            video_hash_hi.to_bytes(FIELD_BYTES, "big"),
            video_hash_lo.to_bytes(FIELD_BYTES, "big"),
            credential_root.to_bytes(FIELD_BYTES, "big"),
            nullifier.to_bytes(FIELD_BYTES, "big"),
            verifier_scope_field.to_bytes(FIELD_BYTES, "big"),
            epoch.to_bytes(FIELD_BYTES, "big"),
            domain_tag,
            circuit_version_bytes,
        ]
    )


def encode_silent_witness_v1_frame(
    *,
    video_hash_hi: int,
    video_hash_lo: int,
    credential_root: int,
    nullifier: int,
    domain_tag: bytes,
) -> bytes:
    return b"".join(
        [
            video_hash_hi.to_bytes(FIELD_BYTES, "big"),
            video_hash_lo.to_bytes(FIELD_BYTES, "big"),
            credential_root.to_bytes(FIELD_BYTES, "big"),
            nullifier.to_bytes(FIELD_BYTES, "big"),
            domain_tag,
        ]
    )


def encode_revocation_v1_frame(
    *,
    revocation_root: int,
    nullifier: int,
    domain_separator: bytes,
    credential_root: int,
) -> bytes:
    return b"".join(
        [
            revocation_root.to_bytes(FIELD_BYTES, "big"),
            nullifier.to_bytes(FIELD_BYTES, "big"),
            domain_separator,
            credential_root.to_bytes(FIELD_BYTES, "big"),
        ]
    )


def build_statement_for_context(ctx: DomainContext) -> dict[str, Any]:
    """Derive a complete synthetic statement + wire frame for domain tuple `ctx`."""
    p_field = SUPPORTED_PROTOCOL_FIELDS[ctx.protocol]
    v_field = SUPPORTED_PROTOCOL_VERSIONS[ctx.protocol_version]
    n_field = SUPPORTED_NETWORKS[ctx.network]

    wire_domain = derive_wire_domain_tag(p_field, v_field, n_field)
    circuit_domain = derive_in_circuit_domain_tag(p_field, v_field, n_field)
    scope_int = derive_scope_field_int(ctx.verifier_scope)
    cred_root = pedersen_model_hash([SYNTHETIC_CREDENTIAL_SECRET])

    is_active_deployment = (
        ctx.protocol == "harpocrates"
        and ctx.protocol_version == "v1"
        and ctx.network == "testnet"
    )

    if ctx.schema == "silent_witness/v2":
        nullifier = compute_scoped_nullifier_int(
            SYNTHETIC_CREDENTIAL_SECRET,
            SYNTHETIC_NULLIFIER_SECRET,
            SYNTHETIC_VIDEO_HI,
            SYNTHETIC_VIDEO_LO,
            scope_int,
            ctx.epoch,
            protocol_version=ctx.protocol_version,
        )
        frame = encode_silent_witness_v2_frame(
            video_hash_hi=SYNTHETIC_VIDEO_HI,
            video_hash_lo=SYNTHETIC_VIDEO_LO,
            credential_root=cred_root,
            nullifier=nullifier,
            verifier_scope_field=scope_int,
            epoch=ctx.epoch,
            domain_tag=wire_domain,
            circuit_version_bytes=encode_u32_trailer(ctx.circuit_version),
        )
        return {
            "tuple_id": (
                f"{ctx.schema}:{ctx.protocol}:{ctx.protocol_version}:"
                f"{ctx.network}:scope={ctx.verifier_scope}:epoch={ctx.epoch}"
            ),
            "schema": ctx.schema,
            "codec": "hpx-vi/2",
            "protocol": ctx.protocol,
            "protocol_version": ctx.protocol_version,
            "network": ctx.network,
            "circuit_version": ctx.circuit_version,
            "verifier_scope": ctx.verifier_scope,
            "verifier_scope_field_hex": f"{scope_int:064x}",
            "epoch": ctx.epoch,
            "active_deployment": is_active_deployment and ctx.circuit_version == 2,
            "domain_components": {
                "protocol_field_hex": p_field.hex(),
                "version_field_hex": v_field.hex(),
                "network_field_hex": n_field.hex(),
                "scoped_nullifier_separator_hex": (
                    f"{SCOPED_NULLIFIER_SEPARATORS[ctx.protocol_version]:064x}"
                ),
            },
            "wire_domain_tag_hex": wire_domain.hex(),
            "circuit_domain_tag_hex": f"{circuit_domain:064x}",
            "credential_root_hex": f"{cred_root:064x}",
            "nullifier_hex": f"{nullifier:064x}",
            "public_inputs_hex": frame.hex(),
        }

    if ctx.schema == "silent_witness/v1":
        nullifier = compute_scoped_nullifier_int(
            SYNTHETIC_CREDENTIAL_SECRET,
            SYNTHETIC_NULLIFIER_SECRET,
            SYNTHETIC_VIDEO_HI,
            SYNTHETIC_VIDEO_LO,
            0,
            0,
            protocol_version=ctx.protocol_version,
        )
        frame = encode_silent_witness_v1_frame(
            video_hash_hi=SYNTHETIC_VIDEO_HI,
            video_hash_lo=SYNTHETIC_VIDEO_LO,
            credential_root=cred_root,
            nullifier=nullifier,
            domain_tag=wire_domain,
        )
        return {
            "tuple_id": f"{ctx.schema}:{ctx.protocol}:{ctx.protocol_version}:{ctx.network}",
            "schema": ctx.schema,
            "codec": "hpx-vi/1",
            "protocol": ctx.protocol,
            "protocol_version": ctx.protocol_version,
            "network": ctx.network,
            "circuit_version": ctx.circuit_version,
            "verifier_scope": "0",
            "verifier_scope_field_hex": f"{0:064x}",
            "epoch": 0,
            "active_deployment": is_active_deployment and ctx.circuit_version == 1,
            "domain_components": {
                "protocol_field_hex": p_field.hex(),
                "version_field_hex": v_field.hex(),
                "network_field_hex": n_field.hex(),
            },
            "wire_domain_tag_hex": wire_domain.hex(),
            "circuit_domain_tag_hex": f"{circuit_domain:064x}",
            "credential_root_hex": f"{cred_root:064x}",
            "nullifier_hex": f"{nullifier:064x}",
            "public_inputs_hex": frame.hex(),
        }

    if ctx.schema == "revocation_witness/v1":
        rev_sep = REVOCATION_SEPARATORS[ctx.protocol_version]
        rev_root = pedersen_model_hash([SYNTHETIC_REVOCATION_SEED])
        rev_nullifier = pedersen_model_hash(
            [
                SYNTHETIC_CREDENTIAL_SECRET,
                SYNTHETIC_NULLIFIER_SECRET,
                int.from_bytes(rev_sep, "big"),
            ]
        )
        frame = encode_revocation_v1_frame(
            revocation_root=rev_root,
            nullifier=rev_nullifier,
            domain_separator=rev_sep,
            credential_root=cred_root,
        )
        return {
            "tuple_id": f"{ctx.schema}:{ctx.protocol}:{ctx.protocol_version}:{ctx.network}",
            "schema": ctx.schema,
            "codec": "hpx-vi/1",
            "protocol": ctx.protocol,
            "protocol_version": ctx.protocol_version,
            "network": ctx.network,
            "circuit_version": ctx.circuit_version,
            "verifier_scope": "0",
            "verifier_scope_field_hex": f"{0:064x}",
            "epoch": 0,
            "active_deployment": is_active_deployment and ctx.circuit_version == 1,
            "domain_components": {
                "revocation_domain_separator_hex": rev_sep.hex(),
            },
            "wire_domain_tag_hex": rev_sep.hex(),
            "circuit_domain_tag_hex": rev_sep.hex(),
            "credential_root_hex": f"{cred_root:064x}",
            "nullifier_hex": f"{rev_nullifier:064x}",
            "public_inputs_hex": frame.hex(),
        }

    if ctx.schema == "redacted_ancestry/v1":
        version_suffix = ctx.protocol_version.upper()
        parent_sep = _ascii_padded_field_int(f"HP_REDACT_PARENT_{version_suffix}")
        params_sep = _ascii_padded_field_int(f"HP_REDACT_PARAMS_{version_suffix}")
        deriv_sep = _ascii_padded_field_int(f"HP_REDACT_DERIV_{version_suffix}")
        ancestry_sep = _ascii_padded_field_int(f"HP_REDACT_ANCESTRY_{version_suffix}")
        nullifier_sep = _ascii_padded_field_int(f"HP_REDACT_NULLIFIER_{version_suffix}")

        parent_commit = pedersen_model_hash([parent_sep, 11111, 22222, 33333])
        params_digest = pedersen_model_hash([params_sep, 44444, 55555])
        deriv_digest = pedersen_model_hash(
            [
                deriv_sep,
                11111,
                22222,
                params_digest,
                55555,
            ]
        )
        ancestry_root = pedersen_model_hash(
            [
                ancestry_sep,
                parent_commit,
                deriv_digest,
                params_digest,
                OPERATION_REDACT_FIELD,
                1,
                ctx.circuit_version,
            ]
        )
        ra_nullifier = pedersen_model_hash(
            [
                nullifier_sep,
                SYNTHETIC_CREDENTIAL_SECRET,
                SYNTHETIC_NULLIFIER_SECRET,
                ancestry_root,
            ]
        )
        frame = b"".join(
            [
                parent_commit.to_bytes(FIELD_BYTES, "big"),
                deriv_digest.to_bytes(FIELD_BYTES, "big"),
                params_digest.to_bytes(FIELD_BYTES, "big"),
                OPERATION_REDACT_FIELD.to_bytes(FIELD_BYTES, "big"),
                ancestry_root.to_bytes(FIELD_BYTES, "big"),
                ra_nullifier.to_bytes(FIELD_BYTES, "big"),
                (1).to_bytes(FIELD_BYTES, "big"),
                wire_domain,
            ]
        )
        return {
            "tuple_id": f"{ctx.schema}:{ctx.protocol}:{ctx.protocol_version}:{ctx.network}",
            "schema": ctx.schema,
            "codec": "redacted_ancestry/1",
            "protocol": ctx.protocol,
            "protocol_version": ctx.protocol_version,
            "network": ctx.network,
            "circuit_version": ctx.circuit_version,
            "verifier_scope": "0",
            "verifier_scope_field_hex": f"{0:064x}",
            "epoch": 0,
            "active_deployment": is_active_deployment and ctx.circuit_version == 1,
            "domain_components": {
                "protocol_field_hex": p_field.hex(),
                "version_field_hex": v_field.hex(),
                "network_field_hex": n_field.hex(),
                "operation_redact_hex": f"{OPERATION_REDACT_FIELD:064x}",
                "nullifier_separator_hex": f"{nullifier_sep:064x}",
            },
            "wire_domain_tag_hex": wire_domain.hex(),
            "circuit_domain_tag_hex": f"{circuit_domain:064x}",
            "credential_root_hex": f"{ancestry_root:064x}",
            "nullifier_hex": f"{ra_nullifier:064x}",
            "public_inputs_hex": frame.hex(),
        }

    raise ValueError(f"Unsupported statement schema: {ctx.schema}")


def evaluate_domain_compatibility(
    public_inputs_hex: str,
    *,
    target: DomainContext,
) -> CompatibilityVerdict:
    """Evaluate wire-frame and circuit-level domain separation for `target`.

    Enforces canonical frame sizing, 128-bit limb padding, version trailer
    canonicity, BN254 scalar field bounds, non-zero identity commitments, exact
    `(protocol, protocol_version, network)` domain tag equality, target
    `verifier_scope` / `epoch` policy equality, and in-circuit nullifier
    derivation binding.
    """
    try:
        raw = bytes.fromhex(public_inputs_hex)
    except ValueError:
        return CompatibilityVerdict(False, reject_code="malformed_hex", layer="wire")

    p_field = SUPPORTED_PROTOCOL_FIELDS[target.protocol]
    v_field = SUPPORTED_PROTOCOL_VERSIONS[target.protocol_version]
    n_field = SUPPORTED_NETWORKS[target.network]
    expected_wire_domain = derive_wire_domain_tag(p_field, v_field, n_field)
    expected_scope_int = derive_scope_field_int(target.verifier_scope)
    expected_cred_root = pedersen_model_hash([SYNTHETIC_CREDENTIAL_SECRET])

    if target.schema == "silent_witness/v2":
        if len(raw) != 256:
            return CompatibilityVerdict(False, reject_code="length", layer="wire")

        limbs = [raw[i * 32 : (i + 1) * 32] for i in range(8)]
        if limbs[0][:16] != b"\x00" * 16 or limbs[1][:16] != b"\x00" * 16:
            return CompatibilityVerdict(False, reject_code="padding", layer="wire")

        trailer = limbs[7]
        if trailer[:28] != b"\x00" * 28 or int.from_bytes(
            trailer[28:], "big"
        ) != target.circuit_version:
            return CompatibilityVerdict(
                False,
                reject_code="version_mismatch",
                circuit_assert="circuit version mismatch",
                layer="both",
            )

        scalar_ints = [int.from_bytes(limbs[i], "big") for i in range(6)]
        if any(val >= BN254_SCALAR_MODULUS for val in scalar_ints):
            return CompatibilityVerdict(
                False, reject_code="non_canonical_field", layer="wire"
            )

        if scalar_ints[2] == 0 or scalar_ints[3] == 0 or limbs[6] == b"\x00" * 32:
            return CompatibilityVerdict(False, reject_code="zero_field", layer="wire")

        if not hmac.compare_digest(limbs[6], expected_wire_domain):
            return CompatibilityVerdict(
                False,
                reject_code="domain_mismatch",
                circuit_assert="unsupported",
                layer="both",
            )

        if scalar_ints[4] != expected_scope_int:
            return CompatibilityVerdict(
                False,
                reject_code="scope_mismatch",
                layer="verifier_policy",
            )

        if scalar_ints[5] != target.epoch:
            return CompatibilityVerdict(
                False,
                reject_code="epoch_mismatch",
                layer="verifier_policy",
            )

        # Circuit-level constraint check: recompute root and scoped nullifier for
        # the claimed (video_hash, verifier_scope, epoch, protocol_version).
        expected_nullifier = compute_scoped_nullifier_int(
            SYNTHETIC_CREDENTIAL_SECRET,
            SYNTHETIC_NULLIFIER_SECRET,
            scalar_ints[0],
            scalar_ints[1],
            scalar_ints[4],
            scalar_ints[5],
            protocol_version=target.protocol_version,
        )
        if scalar_ints[2] != expected_cred_root or scalar_ints[3] != expected_nullifier:
            return CompatibilityVerdict(
                False,
                reject_code="nullifier_binding_mismatch",
                circuit_assert="malformed",
                layer="circuit",
            )

        return CompatibilityVerdict(True)

    if target.schema == "silent_witness/v1":
        if len(raw) != 160:
            return CompatibilityVerdict(False, reject_code="length", layer="wire")
        limbs = [raw[i * 32 : (i + 1) * 32] for i in range(5)]
        if limbs[0][:16] != b"\x00" * 16 or limbs[1][:16] != b"\x00" * 16:
            return CompatibilityVerdict(False, reject_code="padding", layer="wire")
        scalar_ints = [int.from_bytes(limbs[i], "big") for i in range(4)]
        if any(val >= BN254_SCALAR_MODULUS for val in scalar_ints):
            return CompatibilityVerdict(
                False, reject_code="non_canonical_field", layer="wire"
            )
        if scalar_ints[2] == 0 or scalar_ints[3] == 0 or limbs[4] == b"\x00" * 32:
            return CompatibilityVerdict(False, reject_code="zero_field", layer="wire")
        if not hmac.compare_digest(limbs[4], expected_wire_domain):
            return CompatibilityVerdict(
                False,
                reject_code="domain_mismatch",
                circuit_assert="unsupported",
                layer="both",
            )
        expected_nullifier = compute_scoped_nullifier_int(
            SYNTHETIC_CREDENTIAL_SECRET,
            SYNTHETIC_NULLIFIER_SECRET,
            scalar_ints[0],
            scalar_ints[1],
            0,
            0,
            protocol_version=target.protocol_version,
        )
        if scalar_ints[2] != expected_cred_root or scalar_ints[3] != expected_nullifier:
            return CompatibilityVerdict(
                False,
                reject_code="nullifier_binding_mismatch",
                circuit_assert="malformed",
                layer="circuit",
            )
        return CompatibilityVerdict(True)

    if target.schema == "revocation_witness/v1":
        if len(raw) != 128:
            return CompatibilityVerdict(False, reject_code="length", layer="wire")
        limbs = [raw[i * 32 : (i + 1) * 32] for i in range(4)]
        scalar_ints = [int.from_bytes(limbs[i], "big") for i in range(4)]
        if any(val >= BN254_SCALAR_MODULUS for val in scalar_ints):
            return CompatibilityVerdict(
                False, reject_code="non_canonical_field", layer="wire"
            )
        if any(val == 0 for val in scalar_ints):
            return CompatibilityVerdict(False, reject_code="zero_field", layer="wire")
        expected_sep = REVOCATION_SEPARATORS[target.protocol_version]
        if not hmac.compare_digest(limbs[2], expected_sep) or target.network != "testnet":
            return CompatibilityVerdict(
                False,
                reject_code="domain_mismatch",
                circuit_assert="unsupported",
                layer="both",
            )
        return CompatibilityVerdict(True)

    if target.schema == "redacted_ancestry/v1":
        if len(raw) != 256:
            return CompatibilityVerdict(False, reject_code="length", layer="wire")
        limbs = [raw[i * 32 : (i + 1) * 32] for i in range(8)]
        if not hmac.compare_digest(limbs[7], expected_wire_domain):
            return CompatibilityVerdict(
                False,
                reject_code="domain_mismatch",
                circuit_assert="domain tag mismatch",
                layer="both",
            )
        op_int = int.from_bytes(limbs[3], "big")
        if op_int != OPERATION_REDACT_FIELD:
            return CompatibilityVerdict(
                False,
                reject_code="operation_mismatch",
                circuit_assert="operation must be redact",
                layer="circuit",
            )
        expected_ra = build_statement_for_context(target)
        if raw.hex() != expected_ra["public_inputs_hex"]:
            return CompatibilityVerdict(
                False,
                reject_code="nullifier_binding_mismatch",
                circuit_assert="nullifier mismatch",
                layer="circuit",
            )
        return CompatibilityVerdict(True)

    return CompatibilityVerdict(False, reject_code="unknown_schema", layer="wire")


def _splice_field(frame_hex: str, field_index: int, replacement_32: bytes) -> str:
    raw = bytearray.fromhex(frame_hex)
    start = field_index * FIELD_BYTES
    raw[start : start + FIELD_BYTES] = replacement_32
    return bytes(raw).hex()


def generate_compatibility_corpus() -> dict[str, Any]:
    """Generate the full positive tuple matrix and negative cross-domain rejection corpus."""
    domain_tuples: list[dict[str, Any]] = []

    # 1. All supported silent_witness/v2 (network x protocol_version x verifier_scope) tuples.
    for network in ("testnet", "mainnet", "local"):
        for protocol_version in ("v1", "v2"):
            for scope in SUPPORTED_VERIFIER_SCOPES:
                epoch = 0 if scope == "0" else SYNTHETIC_EPOCH_DEFAULT
                ctx = DomainContext(
                    schema="silent_witness/v2",
                    protocol="harpocrates",
                    protocol_version=protocol_version,
                    network=network,
                    circuit_version=2,
                    verifier_scope=scope,
                    epoch=epoch,
                )
                domain_tuples.append(build_statement_for_context(ctx))

    # 2. All supported silent_witness/v1 (network x protocol_version) unscoped tuples.
    for network in ("testnet", "mainnet", "local"):
        for protocol_version in ("v1", "v2"):
            ctx = DomainContext(
                schema="silent_witness/v1",
                protocol="harpocrates",
                protocol_version=protocol_version,
                network=network,
                circuit_version=1,
            )
            domain_tuples.append(build_statement_for_context(ctx))

    # 3. Revocation witness v1 and v2 domain tuples.
    for protocol_version in ("v1", "v2"):
        domain_tuples.append(
            build_statement_for_context(
                DomainContext(
                    schema="revocation_witness/v1",
                    protocol="harpocrates",
                    protocol_version=protocol_version,
                    network="testnet",
                    circuit_version=1,
                )
            )
        )

    # 4. Redacted ancestry tuples across all supported networks and protocol versions.
    for network in ("testnet", "mainnet", "local"):
        for protocol_version in ("v1", "v2"):
            domain_tuples.append(
                build_statement_for_context(
                    DomainContext(
                        schema="redacted_ancestry/v1",
                        protocol="harpocrates",
                        protocol_version=protocol_version,
                        network=network,
                        circuit_version=1,
                    )
                )
            )

    by_id = {entry["tuple_id"]: entry for entry in domain_tuples}

    active_scoped_alpha = by_id[
        f"silent_witness/v2:harpocrates:v1:testnet:scope=v:verifier-alpha:p:default:epoch={SYNTHETIC_EPOCH_DEFAULT}"
    ]
    active_global = by_id["silent_witness/v2:harpocrates:v1:testnet:scope=0:epoch=0"]
    mainnet_scoped_alpha = by_id[
        f"silent_witness/v2:harpocrates:v1:mainnet:scope=v:verifier-alpha:p:default:epoch={SYNTHETIC_EPOCH_DEFAULT}"
    ]
    local_scoped_alpha = by_id[
        f"silent_witness/v2:harpocrates:v1:local:scope=v:verifier-alpha:p:default:epoch={SYNTHETIC_EPOCH_DEFAULT}"
    ]
    v2proto_scoped_alpha = by_id[
        f"silent_witness/v2:harpocrates:v2:testnet:scope=v:verifier-alpha:p:default:epoch={SYNTHETIC_EPOCH_DEFAULT}"
    ]
    sw1_local = by_id["silent_witness/v1:harpocrates:v1:local"]
    sw1_v2proto = by_id["silent_witness/v1:harpocrates:v2:testnet"]
    sw1_active = by_id["silent_witness/v1:harpocrates:v1:testnet"]
    rv_v2proto = by_id["revocation_witness/v1:harpocrates:v2:testnet"]
    rv_active = by_id["revocation_witness/v1:harpocrates:v1:testnet"]
    ra_mainnet = by_id["redacted_ancestry/v1:harpocrates:v1:mainnet"]
    ra_v2proto = by_id["redacted_ancestry/v1:harpocrates:v2:testnet"]

    permuted_domain_tag = derive_wire_domain_tag(
        PROTOCOL_FIELD_HARPOCRATES,
        NETWORK_FIELD_TESTNET,  # swapped order: network before version
        VERSION_FIELD_V1,
    )

    rejection_cases: list[dict[str, Any]] = [
        # --- Cross-network reuse ---
        {
            "id": "ds-neg-001-cross-network-mainnet-to-testnet",
            "category": "cross_network_reuse",
            "description": "silent_witness/v2 statement generated for mainnet replayed against testnet",
            "source_tuple": mainnet_scoped_alpha["tuple_id"],
            "target": {
                "schema": "silent_witness/v2",
                "protocol": "harpocrates",
                "protocol_version": "v1",
                "network": "testnet",
                "circuit_version": 2,
                "verifier_scope": "v:verifier-alpha:p:default",
                "epoch": SYNTHETIC_EPOCH_DEFAULT,
            },
            "public_inputs_hex": mainnet_scoped_alpha["public_inputs_hex"],
            "expected_reject_code": "domain_mismatch",
            "expected_circuit_assert": "unsupported",
        },
        {
            "id": "ds-neg-002-cross-network-testnet-to-mainnet",
            "category": "cross_network_reuse",
            "description": "silent_witness/v2 statement generated for testnet replayed against mainnet",
            "source_tuple": active_scoped_alpha["tuple_id"],
            "target": {
                "schema": "silent_witness/v2",
                "protocol": "harpocrates",
                "protocol_version": "v1",
                "network": "mainnet",
                "circuit_version": 2,
                "verifier_scope": "v:verifier-alpha:p:default",
                "epoch": SYNTHETIC_EPOCH_DEFAULT,
            },
            "public_inputs_hex": active_scoped_alpha["public_inputs_hex"],
            "expected_reject_code": "domain_mismatch",
            "expected_circuit_assert": "unsupported",
        },
        {
            "id": "ds-neg-003-cross-network-local-to-testnet",
            "category": "cross_network_reuse",
            "description": "silent_witness/v2 statement generated for local devnet replayed against testnet",
            "source_tuple": local_scoped_alpha["tuple_id"],
            "target": {
                "schema": "silent_witness/v2",
                "protocol": "harpocrates",
                "protocol_version": "v1",
                "network": "testnet",
                "circuit_version": 2,
                "verifier_scope": "v:verifier-alpha:p:default",
                "epoch": SYNTHETIC_EPOCH_DEFAULT,
            },
            "public_inputs_hex": local_scoped_alpha["public_inputs_hex"],
            "expected_reject_code": "domain_mismatch",
            "expected_circuit_assert": "unsupported",
        },
        {
            "id": "ds-neg-004-sw1-cross-network-local-to-testnet",
            "category": "cross_network_reuse",
            "description": "silent_witness/v1 unscoped statement from local network replayed on testnet",
            "source_tuple": sw1_local["tuple_id"],
            "target": {
                "schema": "silent_witness/v1",
                "protocol": "harpocrates",
                "protocol_version": "v1",
                "network": "testnet",
                "circuit_version": 1,
                "verifier_scope": "0",
                "epoch": 0,
            },
            "public_inputs_hex": sw1_local["public_inputs_hex"],
            "expected_reject_code": "domain_mismatch",
            "expected_circuit_assert": "unsupported",
        },
        {
            "id": "ds-neg-005-redacted-ancestry-mainnet-to-testnet",
            "category": "cross_network_reuse",
            "description": "redacted_ancestry/v1 statement generated on mainnet replayed on testnet",
            "source_tuple": ra_mainnet["tuple_id"],
            "target": {
                "schema": "redacted_ancestry/v1",
                "protocol": "harpocrates",
                "protocol_version": "v1",
                "network": "testnet",
                "circuit_version": 1,
                "verifier_scope": "0",
                "epoch": 0,
            },
            "public_inputs_hex": ra_mainnet["public_inputs_hex"],
            "expected_reject_code": "domain_mismatch",
            "expected_circuit_assert": "domain tag mismatch",
        },
        # --- Cross-verifier-scope & cross-epoch reuse ---
        {
            "id": "ds-neg-006-cross-scope-unmodified-alpha-to-beta",
            "category": "cross_scope_reuse",
            "description": "Unmodified verifier-alpha proof replayed directly against verifier-beta policy",
            "source_tuple": active_scoped_alpha["tuple_id"],
            "target": {
                "schema": "silent_witness/v2",
                "protocol": "harpocrates",
                "protocol_version": "v1",
                "network": "testnet",
                "circuit_version": 2,
                "verifier_scope": "v:verifier-beta:p:default",
                "epoch": SYNTHETIC_EPOCH_DEFAULT,
            },
            "public_inputs_hex": active_scoped_alpha["public_inputs_hex"],
            "expected_reject_code": "scope_mismatch",
            "expected_circuit_assert": None,
        },
        {
            "id": "ds-neg-007-cross-scope-spliced-alpha-nullifier-into-beta",
            "category": "cross_scope_reuse",
            "description": "Verifier-alpha nullifier spliced with verifier-beta public scope fails circuit constraint",
            "source_tuple": active_scoped_alpha["tuple_id"],
            "target": {
                "schema": "silent_witness/v2",
                "protocol": "harpocrates",
                "protocol_version": "v1",
                "network": "testnet",
                "circuit_version": 2,
                "verifier_scope": "v:verifier-beta:p:default",
                "epoch": SYNTHETIC_EPOCH_DEFAULT,
            },
            "public_inputs_hex": _splice_field(
                active_scoped_alpha["public_inputs_hex"],
                4,
                derive_scope_field_int("v:verifier-beta:p:default").to_bytes(32, "big"),
            ),
            "expected_reject_code": "nullifier_binding_mismatch",
            "expected_circuit_assert": "malformed",
        },
        {
            "id": "ds-neg-008-cross-purpose-same-verifier-default-to-attestation",
            "category": "cross_scope_reuse",
            "description": "Same verifier-alpha nullifier spliced from p:default into p:attestation fails circuit constraint",
            "source_tuple": active_scoped_alpha["tuple_id"],
            "target": {
                "schema": "silent_witness/v2",
                "protocol": "harpocrates",
                "protocol_version": "v1",
                "network": "testnet",
                "circuit_version": 2,
                "verifier_scope": "v:verifier-alpha:p:attestation",
                "epoch": SYNTHETIC_EPOCH_DEFAULT,
            },
            "public_inputs_hex": _splice_field(
                active_scoped_alpha["public_inputs_hex"],
                4,
                derive_scope_field_int("v:verifier-alpha:p:attestation").to_bytes(
                    32, "big"
                ),
            ),
            "expected_reject_code": "nullifier_binding_mismatch",
            "expected_circuit_assert": "malformed",
        },
        {
            "id": "ds-neg-009-global-scope-replayed-at-scoped-verifier",
            "category": "cross_scope_reuse",
            "description": "Global unscoped (scope=0) statement replayed at scoped verifier-alpha",
            "source_tuple": active_global["tuple_id"],
            "target": {
                "schema": "silent_witness/v2",
                "protocol": "harpocrates",
                "protocol_version": "v1",
                "network": "testnet",
                "circuit_version": 2,
                "verifier_scope": "v:verifier-alpha:p:default",
                "epoch": 0,
            },
            "public_inputs_hex": active_global["public_inputs_hex"],
            "expected_reject_code": "scope_mismatch",
            "expected_circuit_assert": None,
        },
        {
            "id": "ds-neg-010-cross-epoch-spliced-nullifier-reuse",
            "category": "cross_scope_reuse",
            "description": "Epoch 5 nullifier spliced with epoch 6 public input fails circuit constraint",
            "source_tuple": active_scoped_alpha["tuple_id"],
            "target": {
                "schema": "silent_witness/v2",
                "protocol": "harpocrates",
                "protocol_version": "v1",
                "network": "testnet",
                "circuit_version": 2,
                "verifier_scope": "v:verifier-alpha:p:default",
                "epoch": SYNTHETIC_EPOCH_DEFAULT + 1,
            },
            "public_inputs_hex": _splice_field(
                active_scoped_alpha["public_inputs_hex"],
                5,
                (SYNTHETIC_EPOCH_DEFAULT + 1).to_bytes(32, "big"),
            ),
            "expected_reject_code": "nullifier_binding_mismatch",
            "expected_circuit_assert": "malformed",
        },
        # --- Cross-protocol-version & cross-circuit-version reuse ---
        {
            "id": "ds-neg-011-cross-protocol-version-v2-to-v1",
            "category": "cross_protocol_version_reuse",
            "description": "silent_witness/v2 statement from protocol v2 replayed against protocol v1",
            "source_tuple": v2proto_scoped_alpha["tuple_id"],
            "target": {
                "schema": "silent_witness/v2",
                "protocol": "harpocrates",
                "protocol_version": "v1",
                "network": "testnet",
                "circuit_version": 2,
                "verifier_scope": "v:verifier-alpha:p:default",
                "epoch": SYNTHETIC_EPOCH_DEFAULT,
            },
            "public_inputs_hex": v2proto_scoped_alpha["public_inputs_hex"],
            "expected_reject_code": "domain_mismatch",
            "expected_circuit_assert": "unsupported",
        },
        {
            "id": "ds-neg-012-cross-protocol-version-v1-to-v2",
            "category": "cross_protocol_version_reuse",
            "description": "silent_witness/v2 statement from protocol v1 replayed against protocol v2",
            "source_tuple": active_scoped_alpha["tuple_id"],
            "target": {
                "schema": "silent_witness/v2",
                "protocol": "harpocrates",
                "protocol_version": "v2",
                "network": "testnet",
                "circuit_version": 2,
                "verifier_scope": "v:verifier-alpha:p:default",
                "epoch": SYNTHETIC_EPOCH_DEFAULT,
            },
            "public_inputs_hex": active_scoped_alpha["public_inputs_hex"],
            "expected_reject_code": "domain_mismatch",
            "expected_circuit_assert": "unsupported",
        },
        {
            "id": "ds-neg-013-sw1-cross-protocol-version-v2-to-v1",
            "category": "cross_protocol_version_reuse",
            "description": "silent_witness/v1 statement from protocol v2 replayed against protocol v1",
            "source_tuple": sw1_v2proto["tuple_id"],
            "target": {
                "schema": "silent_witness/v1",
                "protocol": "harpocrates",
                "protocol_version": "v1",
                "network": "testnet",
                "circuit_version": 1,
                "verifier_scope": "0",
                "epoch": 0,
            },
            "public_inputs_hex": sw1_v2proto["public_inputs_hex"],
            "expected_reject_code": "domain_mismatch",
            "expected_circuit_assert": "unsupported",
        },
        {
            "id": "ds-neg-014-circuit-version-downgrade-trailer",
            "category": "cross_protocol_version_reuse",
            "description": "silent_witness/v2 frame relabelled with circuit_version=1 trailer",
            "source_tuple": active_scoped_alpha["tuple_id"],
            "target": {
                "schema": "silent_witness/v2",
                "protocol": "harpocrates",
                "protocol_version": "v1",
                "network": "testnet",
                "circuit_version": 2,
                "verifier_scope": "v:verifier-alpha:p:default",
                "epoch": SYNTHETIC_EPOCH_DEFAULT,
            },
            "public_inputs_hex": _splice_field(
                active_scoped_alpha["public_inputs_hex"],
                7,
                encode_u32_trailer(1),
            ),
            "expected_reject_code": "version_mismatch",
            "expected_circuit_assert": "circuit version mismatch",
        },
        {
            "id": "ds-neg-015-circuit-version-dirty-upper-bytes",
            "category": "cross_protocol_version_reuse",
            "description": "silent_witness/v2 frame with non-zero upper bytes in circuit_version trailer",
            "source_tuple": active_scoped_alpha["tuple_id"],
            "target": {
                "schema": "silent_witness/v2",
                "protocol": "harpocrates",
                "protocol_version": "v1",
                "network": "testnet",
                "circuit_version": 2,
                "verifier_scope": "v:verifier-alpha:p:default",
                "epoch": SYNTHETIC_EPOCH_DEFAULT,
            },
            "public_inputs_hex": _splice_field(
                active_scoped_alpha["public_inputs_hex"],
                7,
                (b"\x00" * 27) + b"\x01\x00\x00\x00\x02",
            ),
            "expected_reject_code": "version_mismatch",
            "expected_circuit_assert": "circuit version mismatch",
        },
        {
            "id": "ds-neg-016-revocation-v2-separator-on-v1-registry",
            "category": "cross_protocol_version_reuse",
            "description": "revocation_witness statement carrying HARPOCRATES_REVOCATION_V2 separator on v1 registry",
            "source_tuple": rv_v2proto["tuple_id"],
            "target": {
                "schema": "revocation_witness/v1",
                "protocol": "harpocrates",
                "protocol_version": "v1",
                "network": "testnet",
                "circuit_version": 1,
                "verifier_scope": "0",
                "epoch": 0,
            },
            "public_inputs_hex": rv_v2proto["public_inputs_hex"],
            "expected_reject_code": "domain_mismatch",
            "expected_circuit_assert": "unsupported",
        },
        {
            "id": "ds-neg-017-redacted-ancestry-v2-to-v1",
            "category": "cross_protocol_version_reuse",
            "description": "redacted_ancestry/v1 statement from protocol v2 replayed on protocol v1",
            "source_tuple": ra_v2proto["tuple_id"],
            "target": {
                "schema": "redacted_ancestry/v1",
                "protocol": "harpocrates",
                "protocol_version": "v1",
                "network": "testnet",
                "circuit_version": 1,
                "verifier_scope": "0",
                "epoch": 0,
            },
            "public_inputs_hex": ra_v2proto["public_inputs_hex"],
            "expected_reject_code": "domain_mismatch",
            "expected_circuit_assert": "domain tag mismatch",
        },
        # --- Cross-schema & component-permutation boundary cases ---
        {
            "id": "ds-neg-018-sw1-frame-submitted-to-sw2-scoped-boundary",
            "category": "cross_schema_boundary",
            "description": "160-byte silent_witness/v1 frame replayed at 256-byte silent_witness/v2 boundary",
            "source_tuple": sw1_active["tuple_id"],
            "target": {
                "schema": "silent_witness/v2",
                "protocol": "harpocrates",
                "protocol_version": "v1",
                "network": "testnet",
                "circuit_version": 2,
                "verifier_scope": "0",
                "epoch": 0,
            },
            "public_inputs_hex": sw1_active["public_inputs_hex"],
            "expected_reject_code": "length",
            "expected_circuit_assert": None,
        },
        {
            "id": "ds-neg-019-revocation-separator-spliced-into-silent-witness-domain",
            "category": "cross_schema_boundary",
            "description": "HARPOCRATES_REVOCATION_V1 separator spliced into silent_witness/v2 domain_tag slot",
            "source_tuple": rv_active["tuple_id"],
            "target": {
                "schema": "silent_witness/v2",
                "protocol": "harpocrates",
                "protocol_version": "v1",
                "network": "testnet",
                "circuit_version": 2,
                "verifier_scope": "v:verifier-alpha:p:default",
                "epoch": SYNTHETIC_EPOCH_DEFAULT,
            },
            "public_inputs_hex": _splice_field(
                active_scoped_alpha["public_inputs_hex"],
                6,
                REVOCATION_SEPARATORS["v1"],
            ),
            "expected_reject_code": "domain_mismatch",
            "expected_circuit_assert": "unsupported",
        },
        {
            "id": "ds-neg-020-permuted-domain-tuple-component-order",
            "category": "domain_tuple_boundary",
            "description": "Domain tag computed with swapped (protocol, network, version) order",
            "source_tuple": active_scoped_alpha["tuple_id"],
            "target": {
                "schema": "silent_witness/v2",
                "protocol": "harpocrates",
                "protocol_version": "v1",
                "network": "testnet",
                "circuit_version": 2,
                "verifier_scope": "v:verifier-alpha:p:default",
                "epoch": SYNTHETIC_EPOCH_DEFAULT,
            },
            "public_inputs_hex": _splice_field(
                active_scoped_alpha["public_inputs_hex"],
                6,
                permuted_domain_tag,
            ),
            "expected_reject_code": "domain_mismatch",
            "expected_circuit_assert": "unsupported",
        },
        {
            "id": "ds-neg-021-noncanonical-scope-at-modulus-boundary",
            "category": "domain_tuple_boundary",
            "description": "verifier_scope equal to BN254 scalar modulus rejected as non_canonical_field",
            "source_tuple": active_scoped_alpha["tuple_id"],
            "target": {
                "schema": "silent_witness/v2",
                "protocol": "harpocrates",
                "protocol_version": "v1",
                "network": "testnet",
                "circuit_version": 2,
                "verifier_scope": "v:verifier-alpha:p:default",
                "epoch": SYNTHETIC_EPOCH_DEFAULT,
            },
            "public_inputs_hex": _splice_field(
                active_scoped_alpha["public_inputs_hex"],
                4,
                BN254_SCALAR_MODULUS.to_bytes(32, "big"),
            ),
            "expected_reject_code": "non_canonical_field",
            "expected_circuit_assert": None,
        },
    ]

    return {
        "format": SUITE_FORMAT,
        "version": SUITE_VERSION,
        "description": (
            "Independently derived circuit-level and verifier-boundary protocol "
            "domain separation vectors across supported Harpocrates networks, "
            "verifier scopes, epochs, protocol versions, and statement schemas. "
            "Synthetic witness values only."
        ),
        "supported_dimensions": {
            "protocols": sorted(SUPPORTED_PROTOCOL_FIELDS.keys()),
            "protocol_versions": sorted(SUPPORTED_PROTOCOL_VERSIONS.keys()),
            "networks": ["local", "testnet", "mainnet"],
            "verifier_scopes": list(SUPPORTED_VERIFIER_SCOPES),
            "schemas": [
                "silent_witness/v2",
                "silent_witness/v1",
                "revocation_witness/v1",
                "redacted_ancestry/v1",
            ],
        },
        "domain_tuples": domain_tuples,
        "rejection_cases": rejection_cases,
    }


def verify_corpus_invariants(corpus: Mapping[str, Any]) -> list[str]:
    """Run deterministic self-checks across all positive tuples and rejection cases."""
    errors: list[str] = []
    tuples = corpus.get("domain_tuples", [])
    rejections = corpus.get("rejection_cases", [])

    # 1. Every positive tuple must pass evaluation against its own DomainContext.
    for entry in tuples:
        ctx = DomainContext(
            schema=entry["schema"],
            protocol=entry["protocol"],
            protocol_version=entry["protocol_version"],
            network=entry["network"],
            circuit_version=int(entry["circuit_version"]),
            verifier_scope=entry["verifier_scope"],
            epoch=int(entry["epoch"]),
        )
        verdict = evaluate_domain_compatibility(entry["public_inputs_hex"], target=ctx)
        if not verdict.accepted:
            errors.append(
                f"positive tuple {entry['tuple_id']} unexpectedly rejected: {verdict.reject_code}"
            )

    # 2. Pairwise disjointness: all silent_witness/v2 nullifiers across (protocol_version, scope)
    # and all wire_domain_tags across (network, protocol_version) must be strictly distinct.
    sw2_tuples = [t for t in tuples if t["schema"] == "silent_witness/v2"]
    seen_wire_tags: dict[tuple[str, str], str] = {}
    for entry in sw2_tuples:
        pair = (entry["network"], entry["protocol_version"])
        tag = entry["wire_domain_tag_hex"]
        if pair in seen_wire_tags:
            if seen_wire_tags[pair] != tag:
                errors.append(f"inconsistent wire_domain_tag within {pair}")
        else:
            if tag in seen_wire_tags.values():
                errors.append(f"wire_domain_tag collision for {pair}")
            seen_wire_tags[pair] = tag

    # Cross-check pairwise rejection for every distinct pair of silent_witness/v2 tuples.
    for idx_a, tuple_a in enumerate(sw2_tuples):
        for idx_b, tuple_b in enumerate(sw2_tuples):
            if idx_a == idx_b:
                continue
            target_b = DomainContext(
                schema=tuple_b["schema"],
                protocol=tuple_b["protocol"],
                protocol_version=tuple_b["protocol_version"],
                network=tuple_b["network"],
                circuit_version=int(tuple_b["circuit_version"]),
                verifier_scope=tuple_b["verifier_scope"],
                epoch=int(tuple_b["epoch"]),
            )
            verdict = evaluate_domain_compatibility(
                tuple_a["public_inputs_hex"],
                target=target_b,
            )
            if verdict.accepted:
                errors.append(
                    f"cross-tuple reuse accepted: {tuple_a['tuple_id']} -> {tuple_b['tuple_id']}"
                )

    # 3. Every negative rejection case must fail with its exact expected_reject_code.
    for case in rejections:
        raw_target = case["target"]
        ctx = DomainContext(
            schema=raw_target["schema"],
            protocol=raw_target["protocol"],
            protocol_version=raw_target["protocol_version"],
            network=raw_target["network"],
            circuit_version=int(raw_target["circuit_version"]),
            verifier_scope=raw_target["verifier_scope"],
            epoch=int(raw_target["epoch"]),
        )
        verdict = evaluate_domain_compatibility(case["public_inputs_hex"], target=ctx)
        if verdict.accepted:
            errors.append(f"rejection case {case['id']} was unexpectedly accepted")
            continue
        if verdict.reject_code != case["expected_reject_code"]:
            errors.append(
                f"rejection case {case['id']} code {verdict.reject_code!r} != {case['expected_reject_code']!r}"
            )
        if verdict.circuit_assert != case["expected_circuit_assert"]:
            errors.append(
                f"rejection case {case['id']} circuit_assert {verdict.circuit_assert!r} != {case['expected_circuit_assert']!r}"
            )

    return errors


def render_corpus_bytes(corpus: Mapping[str, Any]) -> bytes:
    text = json.dumps(corpus, indent=2, sort_keys=False, ensure_ascii=True) + "\n"
    return text.encode("utf-8")


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Generate or verify the circuit-level protocol domain separation "
            "compatibility vector corpus."
        )
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=DEFAULT_VECTOR_PATH,
        help="Path to domain_separation_compatibility_v1.json",
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="Verify the committed vector file matches generated output and pass all invariants.",
    )
    args = parser.parse_args(argv)

    corpus = generate_compatibility_corpus()
    invariant_errors = verify_corpus_invariants(corpus)
    if invariant_errors:
        for err in invariant_errors:
            print(f"invariant failure: {err}", file=sys.stderr)
        return EXIT_CHECK_FAILED

    expected_bytes = render_corpus_bytes(corpus)

    if args.check:
        if not args.output.is_file():
            print(f"missing vector file: {args.output.name}", file=sys.stderr)
            return EXIT_CHECK_FAILED
        actual_bytes = args.output.read_bytes().replace(b"\r\n", b"\n")
        if actual_bytes != expected_bytes:
            diff = difflib.unified_diff(
                actual_bytes.decode("utf-8", errors="replace").splitlines(keepends=True),
                expected_bytes.decode("utf-8").splitlines(keepends=True),
                fromfile=str(args.output.name),
                tofile="expected",
            )
            sys.stderr.writelines(list(diff)[:80])
            return EXIT_CHECK_FAILED
        print(
            json.dumps(
                {
                    "domain_tuples": len(corpus["domain_tuples"]),
                    "event": "domain_separation.check.ok",
                    "rejection_cases": len(corpus["rejection_cases"]),
                },
                sort_keys=True,
                separators=(",", ":"),
            )
        )
        return EXIT_OK

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_bytes(expected_bytes)
    print(
        json.dumps(
            {
                "domain_tuples": len(corpus["domain_tuples"]),
                "event": "domain_separation.written",
                "rejection_cases": len(corpus["rejection_cases"]),
            },
            sort_keys=True,
            separators=(",", ":"),
        )
    )
    return EXIT_OK


if __name__ == "__main__":
    raise SystemExit(main())
