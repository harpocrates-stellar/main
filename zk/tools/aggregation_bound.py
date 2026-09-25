"""Bounded Silent Witness aggregation proof count (#497).

Host-side guard that mirrors the Noir globals and registry constants:

    MAX_AGGREGATION_SIZE = 8
    MIN_AGGREGATION_SIZE = 1

Oversized, undersized, or malformed batch counts are rejected with a stable
machine code and never echo video hashes, secrets, or witness material.
"""

from __future__ import annotations

from typing import Final

MAX_AGGREGATION_SIZE: Final[int] = 8
MIN_AGGREGATION_SIZE: Final[int] = 1


class AggregationBoundError(ValueError):
    """Privacy-safe aggregation size rejection."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)

    def signal(self) -> dict[str, str]:
        return {"rejectCode": self.code, "field": "batch_size"}


def check_aggregation_batch_size(batch_size: object) -> int:
    """Return ``batch_size`` when it is within ``[MIN_AGGREGATION_SIZE, MAX_AGGREGATION_SIZE]``."""
    if isinstance(batch_size, bool) or not isinstance(batch_size, int):
        raise AggregationBoundError("malformed_batch_size")
    if batch_size < MIN_AGGREGATION_SIZE:
        raise AggregationBoundError("batch_size_undersize")
    if batch_size > MAX_AGGREGATION_SIZE:
        raise AggregationBoundError("batch_size_oversize")
    return batch_size
