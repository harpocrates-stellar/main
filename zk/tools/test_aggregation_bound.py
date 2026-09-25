"""Unit tests for bounded aggregation proof count (#497).

Run from the repository root:

    python -m pytest zk/tools -q
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))

import aggregation_bound as ab  # noqa: E402

FIXTURES = (
    Path(__file__).resolve().parents[1]
    / "noir"
    / "fixtures"
    / "aggregation_vectors.json"
)


def test_protocol_constants():
    assert ab.MAX_AGGREGATION_SIZE == 8
    assert ab.MIN_AGGREGATION_SIZE == 1


def test_accepts_bound_batch_sizes():
    for size in range(ab.MIN_AGGREGATION_SIZE, ab.MAX_AGGREGATION_SIZE + 1):
        assert ab.check_aggregation_batch_size(size) == size


def test_rejects_oversized_batch_size():
    with pytest.raises(ab.AggregationBoundError) as exc:
        ab.check_aggregation_batch_size(ab.MAX_AGGREGATION_SIZE + 1)
    assert exc.value.code == "batch_size_oversize"
    assert exc.value.signal() == {"rejectCode": "batch_size_oversize", "field": "batch_size"}

    with pytest.raises(ab.AggregationBoundError) as exc:
        ab.check_aggregation_batch_size(100)
    assert exc.value.code == "batch_size_oversize"


def test_rejects_undersized_and_malformed():
    with pytest.raises(ab.AggregationBoundError) as exc:
        ab.check_aggregation_batch_size(0)
    assert exc.value.code == "batch_size_undersize"
    assert exc.value.signal() == {"rejectCode": "batch_size_undersize", "field": "batch_size"}

    with pytest.raises(ab.AggregationBoundError) as exc:
        ab.check_aggregation_batch_size(-1)
    assert exc.value.code == "batch_size_undersize"

    with pytest.raises(ab.AggregationBoundError) as exc:
        ab.check_aggregation_batch_size(True)  # type: ignore[arg-type]
    assert exc.value.code == "malformed_batch_size"

    with pytest.raises(ab.AggregationBoundError) as exc:
        ab.check_aggregation_batch_size(False)  # type: ignore[arg-type]
    assert exc.value.code == "malformed_batch_size"

    with pytest.raises(ab.AggregationBoundError) as exc:
        ab.check_aggregation_batch_size("8")  # type: ignore[arg-type]
    assert exc.value.code == "malformed_batch_size"

    with pytest.raises(ab.AggregationBoundError) as exc:
        ab.check_aggregation_batch_size(None)  # type: ignore[arg-type]
    assert exc.value.code == "malformed_batch_size"

    with pytest.raises(ab.AggregationBoundError) as exc:
        ab.check_aggregation_batch_size(4.5)  # type: ignore[arg-type]
    assert exc.value.code == "malformed_batch_size"


def test_fixtures_declare_bound():
    data = json.loads(FIXTURES.read_text())
    assert data["maxBatchSize"] == ab.MAX_AGGREGATION_SIZE
    if "_max_aggregation_size" in data:
        assert data["_max_aggregation_size"] == ab.MAX_AGGREGATION_SIZE
    if "_min_aggregation_size" in data:
        assert data["_min_aggregation_size"] == ab.MIN_AGGREGATION_SIZE
