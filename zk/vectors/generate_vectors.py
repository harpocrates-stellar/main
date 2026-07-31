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

CODEC_ID = "hpx-vi/1"
VECTOR_VERSION = 1

FIELD_LEN = 32
PUBLIC_INPUTS_LEN = 128
MIN_PROOF_BYTES = 64
MAX_PROOF_BYTES = 65536

# BN254 scalar field modulus, big-endian. A field element encoding is canonical
# only when it is strictly below this value.
BN254_R_HEX = "30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001"

# Must byte-for-byte match REVOCATION_DOMAIN_SEPARATOR in
# contracts/contracts/harpocrates-registry/src/lib.rs:
# 7 zero bytes of BN254 padding followed by the 25 ASCII bytes of
# "HARPOCRATES_REVOCATION_V1".
DOMAIN_HEX = ("00" * 7) + b"HARPOCRATES_REVOCATION_V1".hex()

# Redaction witness domain tag constant:
# 8 zero bytes of BN254 padding followed by the 24 ASCII bytes of
# "HARPOCRATES_REDACTION_V1".
REDACTION_DOMAIN_HEX = ("00" * 8) + b"HARPOCRATES_REDACTION_V1".hex()

ZERO = "00" * FIELD_LEN
ONES = "ff" * FIELD_LEN

VIDEO_HASH = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
PAD16 = "00" * 16
VIDEO_HI = PAD16 + VIDEO_HASH[:32]
VIDEO_LO = PAD16 + VIDEO_HASH[32:]

CREDENTIAL_ROOT = "01" * FIELD_LEN
NULLIFIER = "02" * FIELD_LEN
REVOCATION_ROOT = "03" * FIELD_LEN

PARENT_COMMITMENT = "04" * FIELD_LEN
OUTPUT_COMMITMENT = "05" * FIELD_LEN
OPERATION_CROP = "00" * 31 + "01"
REPLAY_BINDING = "06" * FIELD_LEN

PROOF_MIN = "ab" * MIN_PROOF_BYTES
PROOF_TYPICAL = "cd" * 512


def silent(hi: str, lo: str, root: str, nullifier: str) -> str:
    return hi + lo + root + nullifier


def revocation(root: str, nullifier: str, domain: str, credential: str) -> str:
    return root + nullifier + domain + credential


def redaction(parent: str, output: str, operation: str, replay: str, domain: str) -> str:
    return parent + output + operation + replay + domain


SILENT_VALID = silent(VIDEO_HI, VIDEO_LO, CREDENTIAL_ROOT, NULLIFIER)
REVOCATION_VALID = revocation(REVOCATION_ROOT, NULLIFIER, DOMAIN_HEX, CREDENTIAL_ROOT)
REDACTION_VALID = redaction(
    PARENT_COMMITMENT, OUTPUT_COMMITMENT, OPERATION_CROP, REPLAY_BINDING, REDACTION_DOMAIN_HEX
)


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
    cases.append(
        case(
            "rd-pos-001-canonical",
            "redaction_witness/v1",
            "Canonical redaction lineage inputs with crop operation.",
            REDACTION_VALID,
            None,
        )
    )
    cases.append(
        case(
            "rd-pos-002-typical-proof-size",
            "redaction_witness/v1",
            "Same redaction inputs with a typical proof size.",
            REDACTION_VALID,
            None,
            PROOF_TYPICAL,
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
    cases.append(
        case(
            "rd-neg-001-empty",
            "redaction_witness/v1",
            "Empty redaction public inputs.",
            "",
            "length",
        )
    )
    cases.append(
        case(
            "rd-neg-002-truncated",
            "redaction_witness/v1",
            "159 bytes: one byte short of a full redaction frame.",
            REDACTION_VALID[:-2],
            "length",
        )
    )
    cases.append(
        case(
            "rd-neg-003-oversized",
            "redaction_witness/v1",
            "161 bytes: one trailing byte past the redaction frame.",
            REDACTION_VALID + "00",
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
    cases.append(
        case(
            "rd-neg-020-parent-commitment-non-canonical",
            "redaction_witness/v1",
            "Non-canonical parent commitment element above modulus.",
            redaction(
                ONES, OUTPUT_COMMITMENT, OPERATION_CROP, REPLAY_BINDING, REDACTION_DOMAIN_HEX
            ),
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
    cases.append(
        case(
            "rd-neg-030-zero-parent-commitment",
            "redaction_witness/v1",
            "A zero parent commitment is invalid.",
            redaction(
                ZERO, OUTPUT_COMMITMENT, OPERATION_CROP, REPLAY_BINDING, REDACTION_DOMAIN_HEX
            ),
            "zero_field",
        )
    )
    cases.append(
        case(
            "rd-neg-031-zero-output-commitment",
            "redaction_witness/v1",
            "A zero output commitment is invalid.",
            redaction(
                PARENT_COMMITMENT, ZERO, OPERATION_CROP, REPLAY_BINDING, REDACTION_DOMAIN_HEX
            ),
            "zero_field",
        )
    )
    cases.append(
        case(
            "rd-neg-032-zero-replay-binding",
            "redaction_witness/v1",
            "A zero replay binding disables claim uniqueness.",
            redaction(
                PARENT_COMMITMENT, OUTPUT_COMMITMENT, OPERATION_CROP, ZERO, REDACTION_DOMAIN_HEX
            ),
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
            "rd-neg-040-domain-mismatch",
            "redaction_witness/v1",
            "Domain tag mismatch on redaction witness frame.",
            redaction(
                PARENT_COMMITMENT, OUTPUT_COMMITMENT, OPERATION_CROP, REPLAY_BINDING, ZERO
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

    return cases


def _decrement_hex(value: str) -> str:
    return format(int(value, 16) - 1, "064x")


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
            "redaction_domain_tag_hex": REDACTION_DOMAIN_HEX,
        },
        "schemas": {
            "silent_witness/v1": [
                "video_hash_hi",
                "video_hash_lo",
                "credential_root",
                "nullifier",
            ],
            "revocation_witness/v1": [
                "revocation_root",
                "nullifier",
                "domain_separator",
                "credential_root",
            ],
            "redaction_witness/v1": [
                "parent_commitment",
                "output_commitment",
                "operation_type",
                "replay_binding",
                "domain_tag",
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


def main() -> None:
    document = build_document()
    seen: set[str] = set()
    for entry in document["cases"]:  # type: ignore[index]
        case_id = entry["id"]  # type: ignore[index]
        if case_id in seen:
            raise SystemExit(f"duplicate case id: {case_id}")
        seen.add(case_id)

    OUT_PATH.write_text(
        json.dumps(document, indent=2, sort_keys=False) + "\n",
        encoding="utf-8",
    )
    print(f"wrote {len(document['cases'])} cases to {OUT_PATH}")  # type: ignore[arg-type]


if __name__ == "__main__":
    main()
