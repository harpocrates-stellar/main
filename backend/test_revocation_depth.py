"""Depth-bound checks for revocation_witness/v1 (#357)."""

from __future__ import annotations

import pytest

from verifier_inputs import (
    MAX_REVOCATION_LEAVES,
    MAX_REVOCATION_WITNESS_DEPTH,
    RejectCode,
    VerifierInputError,
    check_revocation_witness_depth,
)


def test_protocol_constants():
    assert MAX_REVOCATION_WITNESS_DEPTH == 3
    assert MAX_REVOCATION_LEAVES == 8
    assert MAX_REVOCATION_LEAVES == 2**MAX_REVOCATION_WITNESS_DEPTH


def test_accepts_bound_depths():
    for depth in range(1, MAX_REVOCATION_WITNESS_DEPTH + 1):
        check_revocation_witness_depth(depth)


def test_rejects_oversized_depth():
    with pytest.raises(VerifierInputError) as exc:
        check_revocation_witness_depth(MAX_REVOCATION_WITNESS_DEPTH + 1)
    assert exc.value.code == RejectCode.PROOF_OVERSIZE
    assert exc.value.field == "depth"
    assert "leaf" not in str(exc.value).lower()


def test_rejects_undersized_and_malformed():
    with pytest.raises(VerifierInputError) as exc:
        check_revocation_witness_depth(0)
    assert exc.value.code == RejectCode.LENGTH
    with pytest.raises(VerifierInputError) as exc:
        check_revocation_witness_depth(True)  # type: ignore[arg-type]
    assert exc.value.code == RejectCode.MALFORMED_HEX
