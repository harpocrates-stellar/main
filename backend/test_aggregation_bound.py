"""Aggregation proof count bound checks for silent witness batch aggregation (#497)."""

import sys
from pathlib import Path

backend_dir = str(Path(__file__).resolve().parent)
if backend_dir not in sys.path:
    sys.path.insert(0, backend_dir)

import pytest

from verifier_inputs import (
    MAX_AGGREGATION_SIZE,
    MIN_AGGREGATION_SIZE,
    RejectCode,
    VerifierInputError,
    check_aggregation_batch_size,
)


def test_protocol_constants():
    assert MAX_AGGREGATION_SIZE == 8
    assert MIN_AGGREGATION_SIZE == 1


def test_accepts_bound_batch_sizes():
    for size in range(MIN_AGGREGATION_SIZE, MAX_AGGREGATION_SIZE + 1):
        assert check_aggregation_batch_size(size) == size


def test_rejects_oversized_batch_size():
    with pytest.raises(VerifierInputError) as exc:
        check_aggregation_batch_size(MAX_AGGREGATION_SIZE + 1)
    assert exc.value.code == RejectCode.PROOF_OVERSIZE
    assert exc.value.field == "batch_size"
    assert "video" not in str(exc.value).lower()
    assert "secret" not in str(exc.value).lower()


def test_rejects_undersized_and_malformed():
    with pytest.raises(VerifierInputError) as exc:
        check_aggregation_batch_size(0)
    assert exc.value.code == RejectCode.LENGTH
    assert exc.value.field == "batch_size"

    with pytest.raises(VerifierInputError) as exc:
        check_aggregation_batch_size(-1)
    assert exc.value.code == RejectCode.LENGTH

    with pytest.raises(VerifierInputError) as exc:
        check_aggregation_batch_size(True)  # type: ignore[arg-type]
    assert exc.value.code == RejectCode.MALFORMED_HEX
    assert exc.value.field == "batch_size"

    with pytest.raises(VerifierInputError) as exc:
        check_aggregation_batch_size(False)  # type: ignore[arg-type]
    assert exc.value.code == RejectCode.MALFORMED_HEX

    with pytest.raises(VerifierInputError) as exc:
        check_aggregation_batch_size("8")  # type: ignore[arg-type]
    assert exc.value.code == RejectCode.MALFORMED_HEX

    with pytest.raises(VerifierInputError) as exc:
        check_aggregation_batch_size(None)  # type: ignore[arg-type]
    assert exc.value.code == RejectCode.MALFORMED_HEX
