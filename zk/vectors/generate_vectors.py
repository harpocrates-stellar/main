#!/usr/bin/env python3
"""Regenerate the cross-layer verifier conformance vectors.

The emitted file (``verifier_conformance_v1.json``) is the single source of
truth consumed by every verifier boundary in the repository:

    backend   backend/test_conformance_vectors.py   (Python codec)
    frontend  frontend/src/verifierInputs.conformance.test.ts (TypeScript codec)
    contract  contracts/contracts/harpocrates-registry/src/test_conformance.rs

Run this script only when the vector corpus changes; the JSON file is checked
in so the runners never depend on Python being available.

    python zk/vectors/generate_vectors.py

The vector file is versioned. Adding cases is a minor change; changing the
meaning of an existing case id, the codec id, or the reject-code set requires
bumping ``version`` and shipping a migration note in
docs/zk-conformance-vectors.md.
"""

from __future__ import annotations

import json
from pathlib import Path

OUT_PATH = Path(__file__).resolve().parent / "verifier_conformance_v1.json"
OUT_PATH_V2 = Path(__file__).resolve().parent / "verifier_conformance_v2.json"

CODEC_ID = "hpx-vi/1"
CODEC_ID_V2 = "hpx-vi/2"
VECTOR_VERSION = 1
VECTOR_VERSION_V2 = 2

FIELD_LEN = 32
PUBLIC_INPUTS_LEN = 160
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
DOMAIN_TAG_HEX = "4aa038f0a27b6675d7122ae2d4e197c21e83fbe30143a5c83ff35c9514b92c55"

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

PROOF_MIN = "ab" * MIN_PROOF_BYTES
PROOF_TYPICAL = "cd" * 512


def silent(hi: str, lo: str, root: str, nullifier: str, domain: str = DOMAIN_TAG_HEX) -> str:
    return hi + lo + root + nullifier + domain


def silent_v2(
    hi: str,
    lo: str,
    root: str,
    nullifier: str,
    domain: str = DOMAIN_TAG_HEX,
    version: str | None = None,
) -> str:
    """silent_witness/v2 frame: v1 fields followed by the circuit version."""
    if version is None:
        version = VERSION_2
    return hi + lo + root + nullifier + domain + version


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

    # ---- domain binding: domain all-ones --------------------------------
    cases.append(
        case(
            "rv-neg-044-domain-all-ones",
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
            "191 bytes: one byte short of a v2 frame.",
            SILENT_V2_VALID[:-2],
            "length",
        )
    )
    cases.append(
        case(
            "sw2-neg-003-truncated-one-field",
            "silent_witness/v2",
            "160 bytes: the six-field frame missing the version field.",
            SILENT_V2_VALID[: 160 * 2],
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
            silent_v2(VIDEO_HI, VIDEO_LO, CREDENTIAL_ROOT, NULLIFIER, ONES),
            "domain_mismatch",
        )
    )
    cases.append(
        case(
            "sw2-neg-051-domain-all-ones",
            "silent_witness/v2",
            "An all-ones domain tag is not the protocol binding (the silent domain is compared byte-for-byte, not canonicalised).",
            silent_v2(VIDEO_HI, VIDEO_LO, CREDENTIAL_ROOT, NULLIFIER, ONES),
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
            "191 bytes with a wrong version field: length wins (check order).",
            SILENT_V2_VALID[:-10] + VERSION_1[-8:],
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
            "silent-witness envelope. `silent_witness/v2` appends the circuit "
            "version as a trailing field so the wire format commits to the "
            "exact circuit that produced the proof. Every layer must classify "
            "each case identically."
        ),
        "regenerate_with": "python zk/vectors/generate_vectors.py",
        "constants": {
            "field_len": FIELD_LEN,
            "public_inputs_len": PUBLIC_INPUTS_LEN,
            "silent_witness_v2_public_inputs_len": FIELD_LEN * 6,
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


def main() -> None:
    documents = [build_document(), build_document_v2()]
    outputs = [OUT_PATH, OUT_PATH_V2]
    seen: set[str] = set()
    for document, output in zip(documents, outputs):
        seen.clear()
        for entry in document["cases"]:  # type: ignore[index]
            case_id = entry["id"]  # type: ignore[index]
            if case_id in seen:
                raise SystemExit(f"duplicate case id: {case_id}")
            seen.add(case_id)

        output.write_text(
            json.dumps(document, indent=2, sort_keys=False) + "\n",
            encoding="utf-8",
        )
        print(f"wrote {len(document['cases'])} cases to {output}")  # type: ignore[arg-type]


if __name__ == "__main__":
    main()
