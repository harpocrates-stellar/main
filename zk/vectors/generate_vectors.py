#!/usr/bin/env python3
"""Regenerate the cross-layer verifier conformance vectors.

The emitted file (``verifier_conformance_v1.json``) is the single source of
truth consumed by every verifier boundary in the repository:

    backend   backend/test_conformance_vectors.py   (Python codec)
    frontend  frontend/src/verifierInputs.conformance.test.ts (TypeScript codec)
    contract  contracts/contracts/harpocrates-registry/src/test_conformance.rs

The scoped-nullifier fixture in ``zk/noir/fixtures`` is generated as well,
using the Nargo version pinned in ``zk/toolchain.lock.json``. Nargo evaluates
the shared Noir derivation; set ``NARGO`` to use an explicit executable.

Run this script only when the vector corpus changes; JSON files are checked
in so the runners never depend on Python being available.

    python zk/vectors/generate_vectors.py

The vector file is versioned. Adding cases is a minor change; changing the
meaning of an existing case id, the codec id, or the reject-code set requires
bumping ``version`` and shipping a migration note in
docs/zk-conformance-vectors.md.
"""

from __future__ import annotations

import argparse
from collections.abc import Sequence
import difflib
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile

OUT_PATH = Path(__file__).resolve().parent / "verifier_conformance_v1.json"
OUT_PATH_V2 = Path(__file__).resolve().parent / "verifier_conformance_v2.json"

REPO_ROOT = Path(__file__).resolve().parents[2]
SCOPED_OUT_PATH = REPO_ROOT / "zk/noir/fixtures/scoped_nullifier_vectors.json"
SCOPED_INPUT_NAMES = (
    "credential_secret",
    "nullifier_secret",
    "video_hash_hi",
    "video_hash_lo",
    "verifier_scope",
    "epoch",
)

CODEC_ID = "hpx-vi/1"
CODEC_ID_V2 = "hpx-vi/2"
VECTOR_VERSION = 1
VECTOR_VERSION_V2 = 2

FIELD_LEN = 32
PUBLIC_INPUTS_LEN = 160
SILENT_WITNESS_V2_FIELD_COUNT = 8
SILENT_WITNESS_V2_PUBLIC_INPUTS_LEN = FIELD_LEN * SILENT_WITNESS_V2_FIELD_COUNT  # 256
MIN_PROOF_BYTES = 64
MAX_PROOF_BYTES = 65536

# Circuit version bound into the `silent_witness/v2` envelope (#368). Must
# match EXPECTED_CIRCUIT_VERSION in verifier_inputs.rs and
# CURRENT_CIRCUIT_VERSION in zk/noir/silent_witness/src/main.nr.
EXPECTED_CIRCUIT_VERSION = 2

# BN254 scalar field modulus, big-endian. A field element encoding is canonical
# only when it is strictly below this value.
BN254_R_HEX = "30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001"

# Must byte-for-byte match REVOCATION_DOMAIN_SEPARATOR in
# contracts/contracts/harpocrates-registry/src/lib.rs:
# 7 zero bytes of BN254 padding followed by the 25 ASCII bytes of
# "HARPOCRATES_REVOCATION_V1".
DOMAIN_HEX = ("00" * 7) + b"HARPOCRATES_REVOCATION_V1".hex()

# Silent-witness domain tag: SHA-256(protocol || circuit-version || network).
# The three component fields are byte-for-byte counterparts of
# backend/verifier_inputs.py (DOMAIN_*_FIELD), so a proof is bound to exactly
# this (protocol, circuit version, network) tuple.
DOMAIN_PROTOCOL_FIELD = bytes.fromhex(
    "261e9f6e39e3c1ae6aca9f29e84c10d59c82d5f4b40c21c1b7e3c01ad571c201"
)
DOMAIN_VERSION_FIELD = bytes.fromhex(
    "0c89eff4ec8e39a01e9f19547a0cc9dd7fd2a97d79ba4d94fd32e97a1f5ac623"
)
DOMAIN_NETWORK_FIELD = bytes.fromhex(
    "2a2c3f48ce2e3c2f1e6c89b18d64b5f5c1f88a59a0d9bc82cb61a1e8cb77a50f"
)


def _domain_tag(protocol: bytes, version: bytes, network: bytes) -> str:
    return hashlib.sha256(protocol + version + network).hexdigest()


def _bump_last_byte(field: bytes) -> bytes:
    return field[:-1] + bytes([(field[-1] + 1) % 256])


DOMAIN_TAG_HEX = _domain_tag(DOMAIN_PROTOCOL_FIELD, DOMAIN_VERSION_FIELD, DOMAIN_NETWORK_FIELD)

# Single-component mutations: each tag is recomputed with exactly one domain
# component changed, modelling cross-protocol / cross-version / cross-network
# proof replay. They stay canonical, non-zero 32-byte values, so the expected
# failure is a domain *mismatch* rather than a framing/canonicity error.
DOMAIN_TAG_WRONG_PROTOCOL_HEX = _domain_tag(
    _bump_last_byte(DOMAIN_PROTOCOL_FIELD), DOMAIN_VERSION_FIELD, DOMAIN_NETWORK_FIELD
)
DOMAIN_TAG_WRONG_VERSION_HEX = _domain_tag(
    DOMAIN_PROTOCOL_FIELD, _bump_last_byte(DOMAIN_VERSION_FIELD), DOMAIN_NETWORK_FIELD
)
DOMAIN_TAG_WRONG_NETWORK_HEX = _domain_tag(
    DOMAIN_PROTOCOL_FIELD, DOMAIN_VERSION_FIELD, _bump_last_byte(DOMAIN_NETWORK_FIELD)
)

ZERO = "00" * FIELD_LEN
ONES = "ff" * FIELD_LEN

# Circuit version 2 encoded as a u32 in the low 4 bytes of a field element.
VERSION_2 = "00" * 28 + "00000002"
VERSION_1 = "00" * 28 + "00000001"
VERSION_3 = "00" * 28 + "00000003"
VERSION_DIRTY_UPPER = "00" * 27 + "01" + "00000002"

VIDEO_HASH = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
PAD16 = "00" * 16
VIDEO_HI = PAD16 + VIDEO_HASH[:32]
VIDEO_LO = PAD16 + VIDEO_HASH[32:]

CREDENTIAL_ROOT = "01" * FIELD_LEN
NULLIFIER = "02" * FIELD_LEN
REVOCATION_ROOT = "03" * FIELD_LEN
VERIFIER_SCOPE = "04" * FIELD_LEN
# Epoch 5 as a u64 in the low 8 bytes of a field element.
EPOCH = "00" * 24 + "0000000000000005"
EPOCH_ZERO = "00" * FIELD_LEN

PROOF_MIN = "ab" * MIN_PROOF_BYTES
PROOF_TYPICAL = "cd" * 512


def silent(hi: str, lo: str, root: str, nullifier: str, domain: str = DOMAIN_TAG_HEX) -> str:
    return hi + lo + root + nullifier + domain


def silent_v2(
    hi: str,
    lo: str,
    root: str,
    nullifier: str,
    scope: str = VERIFIER_SCOPE,
    epoch: str = EPOCH,
    domain: str = DOMAIN_TAG_HEX,
    version: str | None = None,
) -> str:
    """silent_witness/v2 frame: the scoped frame followed by the circuit version."""
    if version is None:
        version = VERSION_2
    return hi + lo + root + nullifier + scope + epoch + domain + version


def revocation(root: str, nullifier: str, domain: str, credential: str) -> str:
    return root + nullifier + domain + credential


SILENT_VALID = silent(VIDEO_HI, VIDEO_LO, CREDENTIAL_ROOT, NULLIFIER)
SILENT_V2_VALID = silent_v2(VIDEO_HI, VIDEO_LO, CREDENTIAL_ROOT, NULLIFIER)
REVOCATION_VALID = revocation(REVOCATION_ROOT, NULLIFIER, DOMAIN_HEX, CREDENTIAL_ROOT)


def case(
    case_id: str,
    schema: str,
    description: str,
    public_inputs_hex: str,
    reject_code: str | None,
    proof_hex: str = PROOF_MIN,
) -> dict[str, object]:
    return {
        "id": case_id,
        "schema": schema,
        "description": description,
        "public_inputs_hex": public_inputs_hex,
        "proof_hex": proof_hex,
        "expect": {
            "accept": reject_code is None,
            "reject_code": reject_code,
        },
    }


def build_cases() -> list[dict[str, object]]:
    cases: list[dict[str, object]] = []

    # ---- positive corpus ------------------------------------------------
    cases.append(
        case(
            "sw-pos-001-canonical",
            "silent_witness/v1",
            "Canonical silent-witness inputs with a minimum-length proof.",
            SILENT_VALID,
            None,
        )
    )
    cases.append(
        case(
            "sw-pos-002-typical-proof-size",
            "silent_witness/v1",
            "Same inputs with a realistically sized proof blob.",
            SILENT_VALID,
            None,
            PROOF_TYPICAL,
        )
    )
    cases.append(
        case(
            "sw-pos-003-zero-video-hash",
            "silent_witness/v1",
            "A zero video hash is structurally legal; only identity fields must be non-zero.",
            silent(PAD16 + "00" * 16, PAD16 + "00" * 16, CREDENTIAL_ROOT, NULLIFIER),
            None,
        )
    )
    cases.append(
        case(
            "sw-pos-004-max-canonical-field",
            "silent_witness/v1",
            "Identity fields one below the BN254 modulus remain canonical.",
            silent(VIDEO_HI, VIDEO_LO, _decrement_hex(BN254_R_HEX), NULLIFIER),
            None,
        )
    )
    cases.append(
        case(
            "rv-pos-001-canonical",
            "revocation_witness/v1",
            "Canonical revocation inputs carrying the v1 domain separator.",
            REVOCATION_VALID,
            None,
        )
    )
    cases.append(
        case(
            "rv-pos-002-max-proof-size",
            "revocation_witness/v1",
            "Proof blob exactly at the accepted upper bound.",
            REVOCATION_VALID,
            None,
            "ee" * MAX_PROOF_BYTES,
        )
    )

    # ---- length / framing -----------------------------------------------
    cases.append(
        case(
            "sw-neg-001-empty",
            "silent_witness/v1",
            "Empty public inputs.",
            "",
            "length",
        )
    )
    cases.append(
        case(
            "sw-neg-002-truncated-one-byte",
            "silent_witness/v1",
            "127 bytes: one byte short of a full frame.",
            SILENT_VALID[:-2],
            "length",
        )
    )
    cases.append(
        case(
            "sw-neg-003-truncated-one-field",
            "silent_witness/v1",
            "96 bytes: a whole field element missing.",
            SILENT_VALID[: 96 * 2],
            "length",
        )
    )
    cases.append(
        case(
            "sw-neg-004-oversized-one-byte",
            "silent_witness/v1",
            "129 bytes: one trailing byte past the frame.",
            SILENT_VALID + "00",
            "length",
        )
    )
    cases.append(
        case(
            "sw-neg-005-doubled-frame",
            "silent_witness/v1",
            "Two concatenated valid frames must not be accepted as one.",
            SILENT_VALID + SILENT_VALID,
            "length",
        )
    )

    # ---- padding invariants ---------------------------------------------
    cases.append(
        case(
            "sw-neg-010-hi-padding-dirty",
            "silent_witness/v1",
            "High half of video_hash_hi must be zero padding.",
            silent("01" + PAD16[2:] + VIDEO_HASH[:32], VIDEO_LO, CREDENTIAL_ROOT, NULLIFIER),
            "padding",
        )
    )
    cases.append(
        case(
            "sw-neg-011-lo-padding-dirty",
            "silent_witness/v1",
            "High half of video_hash_lo must be zero padding.",
            silent(VIDEO_HI, PAD16[:30] + "01" + VIDEO_HASH[32:], CREDENTIAL_ROOT, NULLIFIER),
            "padding",
        )
    )

    # ---- field canonicity ------------------------------------------------
    cases.append(
        case(
            "sw-neg-020-credential-root-equals-modulus",
            "silent_witness/v1",
            "A field element equal to the modulus is a non-canonical encoding.",
            silent(VIDEO_HI, VIDEO_LO, BN254_R_HEX, NULLIFIER),
            "non_canonical_field",
        )
    )
    cases.append(
        case(
            "sw-neg-021-nullifier-all-ones",
            "silent_witness/v1",
            "0xff..ff is far above the modulus.",
            silent(VIDEO_HI, VIDEO_LO, CREDENTIAL_ROOT, ONES),
            "non_canonical_field",
        )
    )
    cases.append(
        case(
            "rv-neg-020-revocation-root-non-canonical",
            "revocation_witness/v1",
            "Non-canonical revocation root.",
            revocation(ONES, NULLIFIER, DOMAIN_HEX, CREDENTIAL_ROOT),
            "non_canonical_field",
        )
    )

    # ---- zero identity fields -------------------------------------------
    cases.append(
        case(
            "sw-neg-030-zero-nullifier",
            "silent_witness/v1",
            "A zero nullifier would disable replay protection.",
            silent(VIDEO_HI, VIDEO_LO, CREDENTIAL_ROOT, ZERO),
            "zero_field",
        )
    )
    cases.append(
        case(
            "sw-neg-031-zero-credential-root",
            "silent_witness/v1",
            "A zero credential root can never be registered on-chain.",
            silent(VIDEO_HI, VIDEO_LO, ZERO, NULLIFIER),
            "zero_field",
        )
    )
    cases.append(
        case(
            "rv-neg-030-zero-revocation-root",
            "revocation_witness/v1",
            "A zero revocation root is not a valid published root.",
            revocation(ZERO, NULLIFIER, DOMAIN_HEX, CREDENTIAL_ROOT),
            "zero_field",
        )
    )

    # ---- domain binding --------------------------------------------------
    cases.append(
        case(
            "rv-neg-040-zero-domain",
            "revocation_witness/v1",
            "Missing domain separator.",
            revocation(REVOCATION_ROOT, NULLIFIER, ZERO, CREDENTIAL_ROOT),
            "domain_mismatch",
        )
    )
    cases.append(
        case(
            "rv-neg-041-domain-off-by-one",
            "revocation_witness/v1",
            "Domain separator differing in the final version byte (V1 -> V2).",
            revocation(
                REVOCATION_ROOT,
                NULLIFIER,
                DOMAIN_HEX[:-2] + "32",
                CREDENTIAL_ROOT,
            ),
            "domain_mismatch",
        )
    )
    cases.append(
        case(
            "rv-neg-042-domain-case-folded",
            "revocation_witness/v1",
            "Lowercased domain ASCII: the separator is compared byte-wise, not case-insensitively.",
            revocation(
                REVOCATION_ROOT,
                NULLIFIER,
                ("00" * 7) + b"harpocrates_revocation_v1".hex(),
                CREDENTIAL_ROOT,
            ),
            "domain_mismatch",
        )
    )
    cases.append(
        case(
            "rv-neg-043-fields-rotated",
            "revocation_witness/v1",
            "Field order rotated by one element; caught by the domain check.",
            revocation(NULLIFIER, DOMAIN_HEX, CREDENTIAL_ROOT, REVOCATION_ROOT),
            "domain_mismatch",
        )
    )
    cases.append(
        case(
            "sw-neg-044-domain-mismatch",
            "silent_witness/v1",
            "Silent-witness domain tag must match the protocol binding.",
            silent(VIDEO_HI, VIDEO_LO, CREDENTIAL_ROOT, NULLIFIER, ONES),
            "domain_mismatch",
        )
    )
    # Cross-component rejection vectors: the domain tag binds
    # SHA-256(protocol || circuit-version || network), so a proof carrying a tag
    # computed for a *different* protocol, circuit version, or network must be
    # rejected even though it is otherwise canonical and non-zero.
    cases.append(
        case(
            "sw-neg-045-domain-wrong-protocol",
            "silent_witness/v1",
            "Domain tag recomputed with a different protocol component (cross-protocol replay).",
            silent(
                VIDEO_HI,
                VIDEO_LO,
                CREDENTIAL_ROOT,
                NULLIFIER,
                DOMAIN_TAG_WRONG_PROTOCOL_HEX,
            ),
            "domain_mismatch",
        )
    )
    cases.append(
        case(
            "sw-neg-046-domain-wrong-circuit-version",
            "silent_witness/v1",
            "Domain tag recomputed with a different circuit version (cross-version replay).",
            silent(
                VIDEO_HI,
                VIDEO_LO,
                CREDENTIAL_ROOT,
                NULLIFIER,
                DOMAIN_TAG_WRONG_VERSION_HEX,
            ),
            "domain_mismatch",
        )
    )
    cases.append(
        case(
            "sw-neg-047-domain-wrong-network",
            "silent_witness/v1",
            "Domain tag recomputed with a different network component (cross-network replay).",
            silent(
                VIDEO_HI,
                VIDEO_LO,
                CREDENTIAL_ROOT,
                NULLIFIER,
                DOMAIN_TAG_WRONG_NETWORK_HEX,
            ),
            "domain_mismatch",
        )
    )

    # ---- proof blob bounds ------------------------------------------------
    cases.append(
        case(
            "sw-neg-050-empty-proof",
            "silent_witness/v1",
            "Empty proof blob.",
            SILENT_VALID,
            "proof_undersize",
            "",
        )
    )
    cases.append(
        case(
            "sw-neg-051-proof-one-byte-short",
            "silent_witness/v1",
            "Proof blob one byte below the accepted floor.",
            SILENT_VALID,
            "proof_undersize",
            "ab" * (MIN_PROOF_BYTES - 1),
        )
    )
    cases.append(
        case(
            "sw-neg-052-proof-one-byte-long",
            "silent_witness/v1",
            "Proof blob one byte past the accepted ceiling.",
            SILENT_VALID,
            "proof_oversize",
            "ab" * (MAX_PROOF_BYTES + 1),
        )
    )

    # ---- boundary: proof exactly at limits (regression) -----------------
    cases.append(
        case(
            "sw-pos-010-proof-exactly-min",
            "silent_witness/v1",
            "Proof blob exactly at the accepted floor (MIN_PROOF_BYTES=64).",
            SILENT_VALID,
            None,
            "ab" * MIN_PROOF_BYTES,
        )
    )
    cases.append(
        case(
            "sw-pos-011-proof-exactly-max",
            "silent_witness/v1",
            "Proof blob exactly at the accepted ceiling (MAX_PROOF_BYTES=65536).",
            SILENT_VALID,
            None,
            "cd" * MAX_PROOF_BYTES,
        )
    )

    # ---- field canonicity boundary: one below vs at modulus -------------
    cases.append(
        case(
            "sw-neg-022-credential-root-above-modulus-by-one",
            "silent_witness/v1",
            "Field element one above the BN254 modulus is non-canonical.",
            silent(VIDEO_HI, VIDEO_LO, _increment_hex(BN254_R_HEX), NULLIFIER),
            "non_canonical_field",
        )
    )
    cases.append(
        case(
            "rv-neg-021-nullifier-equals-modulus",
            "revocation_witness/v1",
            "Nullifier equal to the BN254 modulus is non-canonical.",
            revocation(REVOCATION_ROOT, BN254_R_HEX, DOMAIN_HEX, CREDENTIAL_ROOT),
            "non_canonical_field",
        )
    )
    cases.append(
        case(
            "rv-neg-022-credential-root-all-ones",
            "revocation_witness/v1",
            "0xff..ff credential root is far above the modulus.",
            revocation(REVOCATION_ROOT, NULLIFIER, DOMAIN_HEX, ONES),
            "non_canonical_field",
        )
    )

    # ---- zero identity fields: revocation witness -----------------------
    cases.append(
        case(
            "rv-neg-031-zero-nullifier",
            "revocation_witness/v1",
            "A zero nullifier in a revocation frame disables replay protection.",
            revocation(REVOCATION_ROOT, ZERO, DOMAIN_HEX, CREDENTIAL_ROOT),
            "zero_field",
        )
    )
    cases.append(
        case(
            "rv-neg-032-zero-credential-root",
            "revocation_witness/v1",
            "A zero credential root in a revocation frame is invalid.",
            revocation(REVOCATION_ROOT, NULLIFIER, DOMAIN_HEX, ZERO),
            "zero_field",
        )
    )

    # ---- padding: silent witness lo field dirty high half ---------------
    cases.append(
        case(
            "sw-neg-012-hi-padding-all-ones",
            "silent_witness/v1",
            "All-ones high half in video_hash_hi field must be rejected as dirty padding.",
            silent(ONES[:32] + VIDEO_HASH[:32], VIDEO_LO, CREDENTIAL_ROOT, NULLIFIER),
            "padding",
        )
    )

    # ---- domain binding: domain mismatch --------------------------------
    cases.append(
        case(
            "rv-neg-044-domain-mismatch",
            "revocation_witness/v1",
            "All-ones domain separator is non-canonical (canonical check precedes domain match).",
            revocation(REVOCATION_ROOT, NULLIFIER, ONES, CREDENTIAL_ROOT),
            "non_canonical_field",
        )
    )

    # ---- check-order regression: length beats padding -------------------
    cases.append(
        case(
            "sw-neg-060-length-before-padding",
            "silent_witness/v1",
            "A frame that is both dirty-padded and wrong length must be rejected for length, not padding (check order).",
            "01" + SILENT_VALID[:-4],  # 159 bytes with dirty first byte — length wins
            "length",
        )
    )

    # ---- revocation length / framing (malformed public-input shapes) ----
    cases.append(
        case(
            "rv-neg-001-empty",
            "revocation_witness/v1",
            "Empty revocation public inputs.",
            "",
            "length",
        )
    )
    cases.append(
        case(
            "rv-neg-002-truncated-one-byte",
            "revocation_witness/v1",
            "127 bytes: one byte short of a revocation frame.",
            REVOCATION_VALID[:-2],
            "length",
        )
    )
    cases.append(
        case(
            "rv-neg-003-truncated-one-field",
            "revocation_witness/v1",
            "96 bytes: a whole field element missing from a revocation frame.",
            REVOCATION_VALID[: 96 * 2],
            "length",
        )
    )
    cases.append(
        case(
            "rv-neg-004-oversized-one-byte",
            "revocation_witness/v1",
            "129 bytes: one trailing byte past the revocation frame.",
            REVOCATION_VALID + "00",
            "length",
        )
    )
    cases.append(
        case(
            "rv-neg-005-doubled-frame",
            "revocation_witness/v1",
            "Two concatenated valid revocation frames must not be accepted as one.",
            REVOCATION_VALID + REVOCATION_VALID,
            "length",
        )
    )
    cases.append(
        case(
            "rv-neg-006-silent-length-as-revocation",
            "revocation_witness/v1",
            "A silent-witness-length (160-byte) frame must not be accepted under the revocation schema.",
            SILENT_VALID,
            "length",
        )
    )
    cases.append(
        case(
            "sw-neg-006-revocation-length-as-silent",
            "silent_witness/v1",
            "A revocation-length (128-byte) frame must not be accepted under the silent-witness schema.",
            REVOCATION_VALID,
            "length",
        )
    )

    # ---- revocation proof blob bounds -----------------------------------
    cases.append(
        case(
            "rv-neg-050-empty-proof",
            "revocation_witness/v1",
            "Empty proof blob for a revocation frame.",
            REVOCATION_VALID,
            "proof_undersize",
            "",
        )
    )
    cases.append(
        case(
            "rv-neg-051-proof-one-byte-short",
            "revocation_witness/v1",
            "Revocation proof one byte below the accepted floor.",
            REVOCATION_VALID,
            "proof_undersize",
            "ab" * (MIN_PROOF_BYTES - 1),
        )
    )

    return cases


def build_cases_v2() -> list[dict[str, object]]:
    """silent_witness/v2 cases: the v2-envelope interpretation of the v1 silent
    corpus, plus version-field-specific rejections (#368)."""
    cases: list[dict[str, object]] = []

    # ---- positive corpus --------------------------------------------------
    cases.append(
        case(
            "sw2-pos-001-canonical",
            "silent_witness/v2",
            "Canonical v2 inputs (version 2) with a minimum-length proof.",
            SILENT_V2_VALID,
            None,
        )
    )
    cases.append(
        case(
            "sw2-pos-002-typical-proof-size",
            "silent_witness/v2",
            "Same inputs with a realistically sized proof blob.",
            SILENT_V2_VALID,
            None,
            PROOF_TYPICAL,
        )
    )
    cases.append(
        case(
            "sw2-pos-003-zero-video-hash",
            "silent_witness/v2",
            "A zero video hash is structurally legal; only identity fields must be non-zero.",
            silent_v2(PAD16 + "00" * 16, PAD16 + "00" * 16, CREDENTIAL_ROOT, NULLIFIER),
            None,
        )
    )
    cases.append(
        case(
            "sw2-pos-004-max-canonical-field",
            "silent_witness/v2",
            "Identity fields one below the BN254 modulus remain canonical.",
            silent_v2(VIDEO_HI, VIDEO_LO, _decrement_hex(BN254_R_HEX), NULLIFIER),
            None,
        )
    )
    cases.append(
        case(
            "sw2-pos-010-proof-exactly-min",
            "silent_witness/v2",
            "Proof blob exactly at the accepted floor.",
            SILENT_V2_VALID,
            None,
            "ab" * MIN_PROOF_BYTES,
        )
    )

    # ---- length / framing -------------------------------------------------
    cases.append(case("sw2-neg-001-empty", "silent_witness/v2", "Empty public inputs.", "", "length"))
    cases.append(
        case(
            "sw2-neg-002-truncated-one-byte",
            "silent_witness/v2",
            "255 bytes: one byte short of a v2 frame.",
            SILENT_V2_VALID[:-2],
            "length",
        )
    )
    cases.append(
        case(
            "sw2-neg-003-truncated-one-field",
            "silent_witness/v2",
            "224 bytes: the scoped frame without its committed version field.",
            SILENT_V2_VALID[:-2 * FIELD_LEN],
            "length",
        )
    )
    cases.append(
        case(
            "sw2-neg-004-v1-len-as-v2",
            "silent_witness/v2",
            "A 160-byte v1 silent frame must not be accepted under the v2 schema.",
            SILENT_VALID,
            "length",
        )
    )
    cases.append(
        case(
            "sw2-neg-005-doubled-frame",
            "silent_witness/v2",
            "Two concatenated v2 frames must not be accepted as one.",
            SILENT_V2_VALID + SILENT_V2_VALID,
            "length",
        )
    )

    # ---- padding invariants ----------------------------------------------
    cases.append(
        case(
            "sw2-neg-010-hi-padding-dirty",
            "silent_witness/v2",
            "High half of video_hash_hi must be zero padding.",
            silent_v2("01" + PAD16[2:] + VIDEO_HASH[:32], VIDEO_LO, CREDENTIAL_ROOT, NULLIFIER),
            "padding",
        )
    )
    cases.append(
        case(
            "sw2-neg-011-lo-padding-dirty",
            "silent_witness/v2",
            "High half of video_hash_lo must be zero padding.",
            silent_v2(VIDEO_HI, PAD16[:30] + "01" + VIDEO_HASH[32:], CREDENTIAL_ROOT, NULLIFIER),
            "padding",
        )
    )

    # ---- scope / epoch bindings ------------------------------------------
    cases.append(
        case(
            "sw2-pos-005-zero-epoch",
            "silent_witness/v2",
            "Epoch 0 is a legal epoch; only identity fields must be non-zero.",
            silent_v2(VIDEO_HI, VIDEO_LO, CREDENTIAL_ROOT, NULLIFIER, epoch=EPOCH_ZERO),
            None,
        )
    )
    cases.append(
        case(
            "sw2-pos-006-zero-scope",
            "silent_witness/v2",
            "The default (zero) verifier scope is legal; scope is a binding, not an identity.",
            silent_v2(VIDEO_HI, VIDEO_LO, CREDENTIAL_ROOT, NULLIFIER, scope=EPOCH_ZERO),
            None,
        )
    )
    cases.append(
        case(
            "sw2-neg-012-epoch-non-canonical",
            "silent_witness/v2",
            "An epoch above the BN254 modulus is not a field element.",
            silent_v2(VIDEO_HI, VIDEO_LO, CREDENTIAL_ROOT, NULLIFIER, epoch=ONES),
            "non_canonical_field",
        )
    )
    cases.append(
        case(
            "sw2-neg-013-scope-non-canonical",
            "silent_witness/v2",
            "A verifier scope above the BN254 modulus is not a field element.",
            silent_v2(VIDEO_HI, VIDEO_LO, CREDENTIAL_ROOT, NULLIFIER, scope=ONES),
            "non_canonical_field",
        )
    )

    # ---- circuit version (#368) ------------------------------------------
    cases.append(
        case(
            "sw2-neg-020-version-zero",
            "silent_witness/v2",
            "A zero version field is not the accepted circuit version.",
            silent_v2(VIDEO_HI, VIDEO_LO, CREDENTIAL_ROOT, NULLIFIER, version=ZERO),
            "version_mismatch",
        )
    )
    cases.append(
        case(
            "sw2-neg-021-version-one",
            "silent_witness/v2",
            "Declaring legacy circuit version 1 inside a v2 envelope is a mismatch.",
            silent_v2(VIDEO_HI, VIDEO_LO, CREDENTIAL_ROOT, NULLIFIER, version=VERSION_1),
            "version_mismatch",
        )
    )
    cases.append(
        case(
            "sw2-neg-022-version-three",
            "silent_witness/v2",
            "A future circuit version is rejected until the codec is promoted.",
            silent_v2(VIDEO_HI, VIDEO_LO, CREDENTIAL_ROOT, NULLIFIER, version=VERSION_3),
            "version_mismatch",
        )
    )
    cases.append(
        case(
            "sw2-neg-023-version-all-ones",
            "silent_witness/v2",
            "An all-ones version field is not a valid u32 encoding (upper bytes dirty).",
            silent_v2(VIDEO_HI, VIDEO_LO, CREDENTIAL_ROOT, NULLIFIER, version=ONES),
            "version_mismatch",
        )
    )
    cases.append(
        case(
            "sw2-neg-024-version-dirty-upper",
            "silent_witness/v2",
            "Version 2 with a non-zero upper byte is a malformed u32 encoding.",
            silent_v2(VIDEO_HI, VIDEO_LO, CREDENTIAL_ROOT, NULLIFIER, version=VERSION_DIRTY_UPPER),
            "version_mismatch",
        )
    )

    # ---- field canonicity ------------------------------------------------
    cases.append(
        case(
            "sw2-neg-030-credential-root-equals-modulus",
            "silent_witness/v2",
            "A field element equal to the modulus is a non-canonical encoding.",
            silent_v2(VIDEO_HI, VIDEO_LO, BN254_R_HEX, NULLIFIER),
            "non_canonical_field",
        )
    )
    cases.append(
        case(
            "sw2-neg-031-nullifier-all-ones",
            "silent_witness/v2",
            "0xff..ff is far above the modulus.",
            silent_v2(VIDEO_HI, VIDEO_LO, CREDENTIAL_ROOT, ONES),
            "non_canonical_field",
        )
    )

    # ---- zero identity fields --------------------------------------------
    cases.append(
        case(
            "sw2-neg-040-zero-nullifier",
            "silent_witness/v2",
            "A zero nullifier would disable replay protection.",
            silent_v2(VIDEO_HI, VIDEO_LO, CREDENTIAL_ROOT, ZERO),
            "zero_field",
        )
    )
    cases.append(
        case(
            "sw2-neg-041-zero-credential-root",
            "silent_witness/v2",
            "A zero credential root can never be registered on-chain.",
            silent_v2(VIDEO_HI, VIDEO_LO, ZERO, NULLIFIER),
            "zero_field",
        )
    )

    # ---- domain binding ---------------------------------------------------
    cases.append(
        case(
            "sw2-neg-050-domain-mismatch",
            "silent_witness/v2",
            "Silent-witness domain tag must match the protocol binding.",
            silent_v2(VIDEO_HI, VIDEO_LO, CREDENTIAL_ROOT, NULLIFIER, domain=ONES),
            "domain_mismatch",
        )
    )
    cases.append(
        case(
            "sw2-neg-051-domain-all-ones",
            "silent_witness/v2",
            "An all-ones domain tag is not the protocol binding (the silent domain is compared byte-for-byte, not canonicalised).",
            silent_v2(VIDEO_HI, VIDEO_LO, CREDENTIAL_ROOT, NULLIFIER, domain=DOMAIN_HEX),
            "domain_mismatch",
        )
    )

    # ---- proof blob bounds ------------------------------------------------
    cases.append(
        case(
            "sw2-neg-060-empty-proof",
            "silent_witness/v2",
            "Empty proof blob.",
            SILENT_V2_VALID,
            "proof_undersize",
            "",
        )
    )
    cases.append(
        case(
            "sw2-neg-061-proof-one-byte-long",
            "silent_witness/v2",
            "Proof blob one byte past the accepted ceiling.",
            SILENT_V2_VALID,
            "proof_oversize",
            "ab" * (MAX_PROOF_BYTES + 1),
        )
    )

    # ---- check-order regressions -----------------------------------------
    cases.append(
        case(
            "sw2-neg-070-length-before-version",
            "silent_witness/v2",
            "255 bytes with a wrong version field: length wins (check order).",
            silent_v2(VIDEO_HI, VIDEO_LO, CREDENTIAL_ROOT, NULLIFIER, version=VERSION_1)[:-2],
            "length",
        )
    )
    cases.append(
        case(
            "sw2-neg-071-padding-before-version",
            "silent_witness/v2",
            "Dirty padding with a wrong version field: padding wins.",
            silent_v2("01" + PAD16[2:] + VIDEO_HASH[:32], VIDEO_LO, CREDENTIAL_ROOT, NULLIFIER, version=VERSION_1),
            "padding",
        )
    )
    cases.append(
        case(
            "sw2-neg-072-version-before-canonical",
            "silent_witness/v2",
            "Wrong version with a non-canonical root: version wins.",
            silent_v2(VIDEO_HI, VIDEO_LO, BN254_R_HEX, NULLIFIER, version=VERSION_1),
            "version_mismatch",
        )
    )

    return cases


def _decrement_hex(value: str) -> str:
    return format(int(value, 16) - 1, "064x")


def _increment_hex(value: str) -> str:
    return format(int(value, 16) + 1, "064x")


def build_document() -> dict[str, object]:
    return {
        "format": "harpocrates.verifier-conformance",
        "version": VECTOR_VERSION,
        "codec": CODEC_ID,
        "description": (
            "Cross-layer conformance vectors for the Harpocrates verifier input "
            "boundary. Every layer (Noir-facing backend, browser, Soroban "
            "registry) must classify each case identically."
        ),
        "regenerate_with": "python zk/vectors/generate_vectors.py",
        "constants": {
            "field_len": FIELD_LEN,
            "public_inputs_len": PUBLIC_INPUTS_LEN,
            "min_proof_bytes": MIN_PROOF_BYTES,
            "max_proof_bytes": MAX_PROOF_BYTES,
            "bn254_scalar_field_modulus_hex": BN254_R_HEX,
            "revocation_domain_separator_hex": DOMAIN_HEX,
        },
        "schemas": {
            "silent_witness/v1": [
                "video_hash_hi",
            "video_hash_lo",
            "credential_root",
            "nullifier",
            "domain_tag",
            ],
            "revocation_witness/v1": [
                "revocation_root",
                "nullifier",
                "domain_separator",
                "credential_root",
            ],
        },
        "reject_codes": [
            "length",
            "padding",
            "non_canonical_field",
            "zero_field",
            "domain_mismatch",
            "proof_undersize",
            "proof_oversize",
            "malformed_hex",
        ],
        "cases": build_cases(),
    }


def build_document_v2() -> dict[str, object]:
    """Circuit-versioned silent-witness envelope corpus (#368)."""
    return {
        "format": "harpocrates.verifier-conformance",
        "version": VECTOR_VERSION_V2,
        "codec": CODEC_ID_V2,
        "description": (
            "Cross-layer conformance vectors for the circuit-versioned "
            "silent-witness envelope. `silent_witness/v2` is the scoped frame "
            "with the circuit version committed as its trailing field, so the "
            "wire format names the exact circuit that produced the proof. "
            "Every layer must classify each case identically."
        ),
        "regenerate_with": "python zk/vectors/generate_vectors.py",
        "constants": {
            "field_len": FIELD_LEN,
            "public_inputs_len": PUBLIC_INPUTS_LEN,
            "silent_witness_v2_field_count": SILENT_WITNESS_V2_FIELD_COUNT,
            "silent_witness_v2_public_inputs_len": SILENT_WITNESS_V2_PUBLIC_INPUTS_LEN,
            "min_proof_bytes": MIN_PROOF_BYTES,
            "max_proof_bytes": MAX_PROOF_BYTES,
            "bn254_scalar_field_modulus_hex": BN254_R_HEX,
            "revocation_domain_separator_hex": DOMAIN_HEX,
            "silent_witness_domain_tag_hex": DOMAIN_TAG_HEX,
            "expected_circuit_version": EXPECTED_CIRCUIT_VERSION,
        },
        "schemas": {
            "silent_witness/v2": [
                "video_hash_hi",
                "video_hash_lo",
                "credential_root",
                "nullifier",
                "verifier_scope",
                "epoch",
                "domain_tag",
                "circuit_version",
            ],
        },
        "reject_codes": [
            "length",
            "padding",
            "non_canonical_field",
            "zero_field",
            "domain_mismatch",
            "proof_undersize",
            "proof_oversize",
            "malformed_hex",
            "version_mismatch",
        ],
        "cases": build_cases_v2(),
    }


def scoped_case_definitions() -> dict:
    """Synthetic seeds and scenario descriptions; calculated fields are added below."""
    return {
        "_description": "Generated synthetic scoped-nullifier vectors evaluated with the shared Noir "
        "derivation. The scenario descriptions also document contract policies; they do "
        "not constitute real proofs.",
        "_version": "3.0.0",
        "_domain_separator": "HARPOCRATES_SCOPED_NULLIFIER_V1",
        "_domain_separator_bytes": "00484152504f4352415445535f53434f5045445f4e554c4c49464945525f5631",
        "_public_input_layout_v2": "8 x BN254 field elements (256 bytes): [video_hash_hi, video_hash_lo, "
        "credential_root, nullifier, verifier_scope, epoch, domain_tag, "
        "circuit_version]",
        "_public_input_layout_v1": "5 x BN254 field elements (160 bytes): [video_hash_hi, video_hash_lo, "
        "credential_root, nullifier, domain_tag]",
        "witness": {
            "credential_secret": 12345,
            "nullifier_secret": 67890,
            "video_hash_hi": "22685491128062564230891640495451214097",
            "video_hash_lo": "45370982256125128461783280990902428194",
        },
        "scope_derivation": {
            "description": "Scope field elements are derived from canonical scope "
            "strings using SHA-256 mod BN254 field modulus.",
            "canonical_format": "v:{verifierAddress}:p:{purpose}",
            "global_scope": "0 (field element representing the unscoped/global context)",
            "example_scope_strings": [
                {
                    "scope_string": "v:GCQ234567890ABCDEFGHIJKLMNOPQRSTUVWXYZ12:p:default",
                    "description": "Default purpose for a verifier",
                },
                {
                    "scope_string": "v:GCQ234567890ABCDEFGHIJKLMNOPQRSTUVWXYZ12:p:attestation",
                    "description": "Attestation purpose",
                },
                {
                    "scope_string": "v:GCQ234567890ABCDEFGHIJKLMNOPQRSTUVWXYZ12:p:membership",
                    "description": "Membership verification " "purpose",
                },
            ],
        },
        "positive_cases": [
            {
                "name": "global_scope_epoch_0",
                "description": "Global scope (verifier_scope=0) with epoch=0. The default "
                "configuration.",
                "credential_secret": 12345,
                "nullifier_secret": 67890,
                "verifier_scope": 0,
                "epoch": 0,
                "expected": "pass",
            },
            {
                "name": "explicit_scope_epoch_1",
                "description": "Explicit verifier scope with epoch 1. Demonstrates scoped "
                "nullifier derivation.",
                "credential_secret": 12345,
                "nullifier_secret": 67890,
                "verifier_scope": 1111,
                "epoch": 1,
                "expected": "pass",
            },
            {
                "name": "zero_credential_secret",
                "description": "Zero credential secret is a valid BN254 field element. Edge "
                "case.",
                "credential_secret": 0,
                "nullifier_secret": 67890,
                "verifier_scope": 0,
                "epoch": 0,
                "expected": "pass",
            },
            {
                "name": "max_field_credential_secret",
                "description": "Legacy large-field credential secret, retained from the "
                "original fixture. Despite the historical case name, this seed "
                "is not BN254 prime - 1.",
                "credential_secret": "2188824287183927522224640574525727508854836440034343698204186575808495616",
                "nullifier_secret": 67890,
                "verifier_scope": 0,
                "epoch": 0,
                "expected": "pass",
            },
            {
                "name": "zero_video_hash",
                "description": "All-zero video hash (blank-frame video). Edge case with "
                "correct secrets.",
                "credential_secret": 12345,
                "nullifier_secret": 67890,
                "video_hash_hi": 0,
                "video_hash_lo": 0,
                "verifier_scope": 0,
                "epoch": 0,
                "expected": "pass",
            },
            {
                "name": "cross_scope_different_nullifiers",
                "description": "Same credential and video, different scopes produce different "
                "nullifiers. Demonstrates scope binding.",
                "credential_secret": 12345,
                "nullifier_secret": 67890,
                "verifier_scope_a": 0,
                "verifier_scope_b": 1111,
                "epoch": 0,
                "expected": "pass — both scopes produce distinct nullifiers",
            },
            {
                "name": "epoch_rotation_valid",
                "description": "After epoch rotation, a new proof with the updated epoch is "
                "accepted.",
                "credential_secret": 12345,
                "nullifier_secret": 67890,
                "verifier_scope": 42,
                "epoch_old": 0,
                "epoch_new": 1,
                "expected": "pass — epoch 1 proof accepted after rotation",
            },
        ],
        "negative_cases": [
            {
                "name": "wrong_credential_secret",
                "description": "Wrong credential secret in the witness — credential root "
                "assertion fails.",
                "credential_secret_wrong": 99999,
                "credential_secret_correct": 12345,
                "nullifier_secret": 67890,
                "verifier_scope": 0,
                "epoch": 0,
                "expected": "fail — credential root mismatch",
            },
            {
                "name": "wrong_nullifier_secret",
                "description": "Wrong nullifier secret in the witness — nullifier assertion "
                "fails.",
                "credential_secret": 12345,
                "nullifier_secret_wrong": 11111,
                "nullifier_secret_correct": 67890,
                "verifier_scope": 0,
                "epoch": 0,
                "expected": "fail — nullifier mismatch",
            },
            {
                "name": "wrong_video_hash_hi",
                "description": "Wrong video_hash_hi in public inputs — nullifier assertion "
                "fails.",
                "credential_secret": 12345,
                "nullifier_secret": 67890,
                "video_hash_hi_wrong": "999999999999999999999999999999999999",
                "video_hash_lo_correct": "45370982256125128461783280990902428194",
                "verifier_scope": 0,
                "epoch": 0,
                "expected": "fail — nullifier mismatch",
            },
            {
                "name": "wrong_video_hash_lo",
                "description": "Wrong video_hash_lo in public inputs — nullifier assertion "
                "fails.",
                "credential_secret": 12345,
                "nullifier_secret": 67890,
                "video_hash_hi_correct": "22685491128062564230891640495451214097",
                "video_hash_lo_wrong": "222222222222222222222222222222222222",
                "verifier_scope": 0,
                "epoch": 0,
                "expected": "fail — nullifier mismatch",
            },
            {
                "name": "nullifier_from_different_scope",
                "description": "Nullifier computed for scope=999 must not satisfy scope=0. "
                "Proves scope binding.",
                "credential_secret": 12345,
                "nullifier_secret": 67890,
                "verifier_scope_proof": 0,
                "verifier_scope_nullifier": 999,
                "epoch": 0,
                "expected": "fail — nullifier mismatch",
            },
            {
                "name": "nullifier_from_different_epoch",
                "description": "Nullifier computed for epoch=2 must not satisfy epoch=1. "
                "Proves epoch binding.",
                "credential_secret": 12345,
                "nullifier_secret": 67890,
                "verifier_scope": 42,
                "epoch_proof": 1,
                "epoch_nullifier": 2,
                "expected": "fail — nullifier mismatch",
            },
            {
                "name": "nullifier_from_different_video",
                "description": "Nullifier computed for a different video must not satisfy the "
                "current video hash.",
                "credential_secret": 12345,
                "nullifier_secret": 67890,
                "verifier_scope": 0,
                "epoch": 0,
                "video_hash_hi_different": "111111111111111111111111111111111111",
                "video_hash_lo_different": "222222222222222222222222222222222222",
                "expected": "fail — nullifier mismatch",
            },
            {
                "name": "tampered_scope_public_input",
                "description": "Correct nullifier for scope=0, but scope public input is "
                "tampered to 1.",
                "credential_secret": 12345,
                "nullifier_secret": 67890,
                "verifier_scope_proof": 0,
                "verifier_scope_public_input": 1,
                "epoch": 0,
                "expected": "fail — nullifier mismatch",
            },
            {
                "name": "tampered_epoch_public_input",
                "description": "Correct nullifier for epoch=1, but epoch public input is "
                "tampered to 0.",
                "credential_secret": 12345,
                "nullifier_secret": 67890,
                "verifier_scope": 42,
                "epoch_proof": 1,
                "epoch_public_input": 0,
                "expected": "fail — nullifier mismatch",
            },
            {
                "name": "swapped_credential_root_and_nullifier",
                "description": "Credential root and nullifier positions are swapped in public "
                "inputs.",
                "credential_secret": 12345,
                "nullifier_secret": 67890,
                "verifier_scope": 0,
                "epoch": 0,
                "expected": "fail — credential root mismatch",
            },
            {
                "name": "stale_epoch_rejected",
                "description": "Proof with epoch 0 is rejected when the current scope epoch "
                "is 1.",
                "credential_secret": 12345,
                "nullifier_secret": 67890,
                "verifier_scope": 42,
                "epoch_proof": 0,
                "epoch_current": 1,
                "expected": "fail — StaleEpoch",
            },
            {
                "name": "future_epoch_rejected",
                "description": "Proof with epoch 2 is rejected when the current scope epoch "
                "is 1.",
                "credential_secret": 12345,
                "nullifier_secret": 67890,
                "verifier_scope": 42,
                "epoch_proof": 2,
                "epoch_current": 1,
                "expected": "fail — StaleEpoch",
            },
        ],
        "boundary_cases": [
            {
                "name": "adjacent_nullifier_secrets",
                "description": "Adjacent synthetic secrets must derive distinct nullifiers.",
                "credential_secret": 12345,
                "nullifier_secret_a": 67890,
                "nullifier_secret_b": 67891,
                "verifier_scope": 0,
                "epoch": 0,
                "expected": "distinct",
            },
            {
                "name": "nullifier_secret_field_edges",
                "description": "Legacy large-field secret and zero must remain distinct. The "
                "original nullifier_secret_max seed is retained; it is not "
                "BN254 prime - 1.",
                "credential_secret": 12345,
                "nullifier_secret_max": "2188824287183927522224640574525727508854836440034343698204186575808495616",
                "nullifier_secret_wrapped": 0,
                "verifier_scope": 0,
                "epoch": 0,
                "expected": "distinct",
            },
            {
                "name": "scope_epoch_adjacent_boundaries",
                "description": "Changing only the adjacent scope or epoch must change the "
                "nullifier.",
                "credential_secret": 12345,
                "nullifier_secret": 67890,
                "base_verifier_scope": 0,
                "base_epoch": 0,
                "adjacent_verifier_scope": 1,
                "adjacent_epoch": 1,
                "expected": "distinct",
            },
            {
                "name": "video_hash_high_limb_edges",
                "description": "Zero and one high video-hash limbs must not collide.",
                "credential_secret": 12345,
                "nullifier_secret": 67890,
                "video_hash_hi_a": 0,
                "video_hash_hi_b": 1,
                "verifier_scope": 0,
                "epoch": 0,
                "expected": "distinct",
            },
        ],
        "v1_v2_compatibility": {
            "description": "Historical unscoped/scoped compatibility notes, retained "
            "as scenario documentation. These notes do not assert that "
            "a particular proof envelope is currently accepted.",
            "v1_layout": "5 x BN254 field elements (160 bytes): [video_hash_hi, "
            "video_hash_lo, credential_root, nullifier, domain_tag]",
            "v2_layout": "8 x BN254 field elements (256 bytes): [video_hash_hi, "
            "video_hash_lo, credential_root, nullifier, verifier_scope, "
            "epoch, domain_tag, circuit_version]",
            "nullifier_independence": "v1 and v2 nullifiers for the same "
            "credential/video are different values because "
            "the derivation formulas differ (v1 does not "
            "include scope_hash).",
            "test_case": {
                "name": "v1_v2_nullifiers_are_different",
                "credential_secret": 12345,
                "nullifier_secret": 67890,
                "video_hash": "same for both v1 and v2",
                "v1_nullifier": "different from v2 nullifier",
                "v2_nullifier": "different from v1 nullifier",
                "expected": "both v1 and v2 proofs succeed with distinct " "nullifiers",
            },
        },
        "regenerate_with": "python zk/vectors/generate_vectors.py",
    }


def compute_scoped_nullifiers(inputs: Sequence[dict[str, int]]) -> list[dict[str, str]]:
    """Evaluate the existing Noir derivation; all returned fields are decimal strings.

    A temporary test package imports the shared circuit function rather than
    maintaining a second Pedersen implementation. Nothing in the repository's
    Noir sources, Prover.toml files, or target directories is modified.
    """
    if not inputs:
        return []
    statements = []
    for index, fields in enumerate(inputs):
        values = [int(fields[name]) for name in SCOPED_INPUT_NAMES]
        if any(value < 0 or value >= int(BN254_R_HEX, 16) for value in values):
            raise ValueError(
                "scoped nullifier inputs must be canonical BN254 field elements"
            )
        arguments = ", ".join(str(value) for value in values)
        statements.extend(
            [
                f"let root_{index} = std::hash::pedersen_hash([{values[0]}]);",
                f"let nullifier_{index} = compute_scoped_nullifier({arguments});",
                f'println(f"SCOPED_VECTOR:{index}:{{root_{index}}}:{{nullifier_{index}}}");',
            ]
        )
    with tempfile.TemporaryDirectory(prefix="harpocrates-scoped-vectors-") as scratch:
        package = Path(scratch)
        (package / "src").mkdir()
        common = (REPO_ROOT / "zk/noir/harpocrates_common").as_posix()
        (package / "Nargo.toml").write_text(
            '[package]\nname = "scoped_vectors"\ntype = "bin"\n'
            'compiler_version = ">=1.0.0"\n\n[dependencies]\n'
            f"harpocrates_common = {{ path = {json.dumps(common)} }}\n",
            encoding="utf-8",
        )
        (package / "src/main.nr").write_text(
            "use harpocrates_common::compute_scoped_nullifier;\n"
            "fn main() {}\n#[test]\nfn emit_vectors() {\n"
            + "\n".join(statements)
            + "\n}\n",
            encoding="utf-8",
        )
        try:
            result = subprocess.run(
                [os.environ.get("NARGO", "nargo"), "test", "--show-output"],
                cwd=package,
                capture_output=True,
                text=True,
                check=True,
            )
        except FileNotFoundError as error:
            raise RuntimeError(
                "scoped vectors require nargo; install the version in "
                "zk/toolchain.lock.json or set NARGO to its executable path"
            ) from error
        except subprocess.CalledProcessError as error:
            raise RuntimeError(
                f"Noir vector calculation failed:\n{error.stdout}\n{error.stderr}"
            ) from error
    rows = re.findall(
        r"^SCOPED_VECTOR:(\d+):(0x[0-9a-fA-F]+):(0x[0-9a-fA-F]+)$",
        result.stdout,
        re.MULTILINE,
    )
    if [int(row[0]) for row in rows] != list(range(len(inputs))):
        raise RuntimeError(
            f"Noir did not emit the expected scoped vectors:\n{result.stdout}"
        )
    return [
        {"credential_root": str(int(root, 16)), "nullifier": str(int(nullifier, 16))}
        for _, root, nullifier in rows
    ]


def build_scoped_document() -> dict[str, object]:
    document = scoped_case_definitions()
    base = document["witness"]
    base.update(verifier_scope=0, epoch=0)
    requests = [{name: int(base[name]) for name in SCOPED_INPUT_NAMES}]
    targets = [base]

    def sample(label: str, **overrides: int) -> dict:
        fields = {name: int(base[name]) for name in SCOPED_INPUT_NAMES}
        fields.update(overrides)
        output = {
            "label": label,
            "inputs": {name: str(value) for name, value in fields.items()},
        }
        requests.append(fields)
        targets.append(output)
        return output

    for case in document["positive_cases"]:
        fields = {name: int(case[name]) for name in SCOPED_INPUT_NAMES if name in case}
        if case["name"] == "cross_scope_different_nullifiers":
            case["derived"] = [
                sample(
                    "scope_a", **(fields | {"verifier_scope": case["verifier_scope_a"]})
                ),
                sample(
                    "scope_b", **(fields | {"verifier_scope": case["verifier_scope_b"]})
                ),
            ]
        elif case["name"] == "epoch_rotation_valid":
            case["derived"] = [
                sample("old", **(fields | {"epoch": case["epoch_old"]})),
                sample("new", **(fields | {"epoch": case["epoch_new"]})),
            ]
        else:
            case["derived"] = [sample("value", **fields)]

    mutations = {
        "wrong_credential_secret": (
            "credential_secret",
            "credential_secret_correct",
            "credential_secret_wrong",
        ),
        "wrong_nullifier_secret": (
            "nullifier_secret",
            "nullifier_secret_correct",
            "nullifier_secret_wrong",
        ),
        "wrong_video_hash_hi": ("video_hash_hi", None, "video_hash_hi_wrong"),
        "wrong_video_hash_lo": ("video_hash_lo", None, "video_hash_lo_wrong"),
        "nullifier_from_different_scope": (
            "verifier_scope",
            "verifier_scope_proof",
            "verifier_scope_nullifier",
        ),
        "nullifier_from_different_epoch": ("epoch", "epoch_proof", "epoch_nullifier"),
        "tampered_scope_public_input": (
            "verifier_scope",
            "verifier_scope_proof",
            "verifier_scope_public_input",
        ),
        "tampered_epoch_public_input": ("epoch", "epoch_proof", "epoch_public_input"),
        "stale_epoch_rejected": ("epoch", "epoch_proof", "epoch_current"),
        "future_epoch_rejected": ("epoch", "epoch_proof", "epoch_current"),
    }
    for case in document["negative_cases"]:
        fields = {name: int(case[name]) for name in SCOPED_INPUT_NAMES if name in case}
        name = case["name"]
        if name in mutations:
            field, correct, wrong = mutations[name]
            if correct is not None:
                fields[field] = int(case[correct])
            case["derived"] = [
                sample("reference", **fields),
                sample("changed", **(fields | {field: int(case[wrong])})),
            ]
        elif name == "nullifier_from_different_video":
            case["derived"] = [
                sample("reference", **fields),
                sample(
                    "changed",
                    **(
                        fields
                        | {
                            "video_hash_hi": int(case["video_hash_hi_different"]),
                            "video_hash_lo": int(case["video_hash_lo_different"]),
                        }
                    ),
                ),
            ]
        else:
            case["derived"] = [sample("reference", **fields)]

    for case in document["boundary_cases"]:
        fields = {name: int(case[name]) for name in SCOPED_INPUT_NAMES if name in case}
        name = case["name"]
        if name == "adjacent_nullifier_secrets":
            changes = [
                {"nullifier_secret": case["nullifier_secret_a"]},
                {"nullifier_secret": case["nullifier_secret_b"]},
            ]
        elif name == "nullifier_secret_field_edges":
            changes = [
                {"nullifier_secret": int(case["nullifier_secret_max"])},
                {"nullifier_secret": case["nullifier_secret_wrapped"]},
            ]
        elif name == "scope_epoch_adjacent_boundaries":
            changes = [
                {
                    "verifier_scope": case["base_verifier_scope"],
                    "epoch": case["base_epoch"],
                },
                {
                    "verifier_scope": case["adjacent_verifier_scope"],
                    "epoch": case["base_epoch"],
                },
                {
                    "verifier_scope": case["base_verifier_scope"],
                    "epoch": case["adjacent_epoch"],
                },
            ]
        else:
            changes = [
                {"video_hash_hi": case["video_hash_hi_a"]},
                {"video_hash_hi": case["video_hash_hi_b"]},
            ]
        case["derived"] = [
            sample(str(index), **(fields | change))
            for index, change in enumerate(changes)
        ]

    for target, computed in zip(
        targets, compute_scoped_nullifiers(requests), strict=True
    ):
        target.update(computed)
    return document


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "--check",
        action="store_true",
        help="verify committed vector files match generated output without writing",
    )
    if argv is None:
        argv = sys.argv[1:] if Path(sys.argv[0]).name == Path(__file__).name else []
    args = parser.parse_args(list(argv))

    documents = [build_document(), build_document_v2(), build_scoped_document()]
    outputs = [OUT_PATH, OUT_PATH_V2, SCOPED_OUT_PATH]
    seen: set[str] = set()
    mismatched = False
    for document, output in zip(documents, outputs):
        seen.clear()
        if "cases" in document:
            cases = document["cases"]
        else:
            cases = [
                case
                for group in ("positive_cases", "negative_cases", "boundary_cases")
                for case in document[group]
            ]
        for entry in cases:
            case_id = entry.get("id", entry.get("name"))
            if case_id in seen:
                raise SystemExit(f"duplicate case id: {case_id}")
            seen.add(case_id)

        rendered = json.dumps(document, indent=2, sort_keys=False) + "\n"
        if args.check:
            if not output.is_file():
                print(f"missing vector file: {output}", file=sys.stderr)
                mismatched = True
                continue
            committed_bytes = output.read_bytes()
            committed = committed_bytes.decode("utf-8")
            if committed_bytes != rendered.encode("utf-8"):
                diff = "".join(
                    difflib.unified_diff(
                        committed.splitlines(keepends=True),
                        rendered.splitlines(keepends=True),
                        fromfile=f"{output.name} (committed)",
                        tofile=f"{output.name} (generated)",
                    )
                )
                print(
                    f"{output} is out of date; regenerate with `{document['regenerate_with']}`:",
                    file=sys.stderr,
                )
                print(diff, end="", file=sys.stderr)
                mismatched = True
            else:
                print(f"verified {len(cases)} cases in {output}")
        else:
            output.write_bytes(rendered.encode("utf-8"))
            print(f"wrote {len(cases)} cases to {output}")

    if mismatched:
        raise SystemExit(1)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
